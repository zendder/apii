from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import time
import re
import requests
import asyncio
from threading import Thread, Lock
from functools import wraps
from collections import defaultdict
import secrets
import hashlib
import html

app = Flask(__name__)
# Use a secure random secret key - CHANGE THIS IN PRODUCTION
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

rooms = {}
rooms_lock = Lock()

# Rate limiting for socket events (per user)
socket_rate_limits = defaultdict(lambda: {'messages': [], 'actions': []})
RATE_LIMIT_MESSAGES = 30  # messages per minute
RATE_LIMIT_ACTIONS = 30  # actions per minute
rate_limit_lock = Lock()

# E2B Desktop imports
import os
from e2b_desktop import Sandbox

# Set E2B API key
os.environ['E2B_API_KEY'] = 'e2b_3fb5bcdeab1a2585f58b645bbe59adee7c3f73db'

# ========================= SECURITY FUNCTIONS =========================

def check_socket_rate_limit(socket_id, limit_type='actions'):
    """
    Check if a socket has exceeded rate limits
    Returns True if within limit, False if rate limit exceeded
    """
    with rate_limit_lock:
        now = time.time()
        limits = socket_rate_limits[socket_id]
        
        # Clean old entries (older than 60 seconds)
        limits[limit_type] = [t for t in limits[limit_type] if now - t < 60]
        
        # Check limit
        max_limit = RATE_LIMIT_MESSAGES if limit_type == 'messages' else RATE_LIMIT_ACTIONS
        if len(limits[limit_type]) >= max_limit:
            return False
        
        # Add new timestamp
        limits[limit_type].append(now)
        return True

def sanitize_message(message):
    """Sanitize user input to prevent XSS attacks"""
    if not isinstance(message, str):
        return ""
    
    # HTML escape
    message = html.escape(message)
    
    # Limit length
    max_length = 500
    if len(message) > max_length:
        message = message[:max_length]
    
    return message.strip()

def sanitize_nickname(nickname):
    """Sanitize nickname to prevent spoofing and XSS"""
    if not isinstance(nickname, str):
        return ""
    
    # HTML escape
    nickname = html.escape(nickname)
    
    # Remove special characters that could be used for spoofing
    nickname = re.sub(r'[^\w\s\-\_]', '', nickname)
    
    # Limit length
    max_length = 30
    if len(nickname) > max_length:
        nickname = nickname[:max_length]
    
    return nickname.strip()

def validate_session_for_room(room_id):
    """
    Validate that the current session is authorized for the room
    Returns tuple: (is_valid, user_info)
    """
    session_id = session.get('session_id')
    stored_room_id = session.get('room_id')
    
    if not session_id or stored_room_id != room_id:
        return False, None
    
    if room_id not in rooms:
        return False, None
    
    room = rooms[room_id]
    is_host = session.get('is_host', False)
    
    # Verify the session matches the stored session
    if is_host:
        if room.get('host_session_id') != session_id:
            return False, None
        nickname = session.get('host_nickname') or room.get('host_nickname')
    else:
        nickname = session.get('user_nickname')
    
    if not nickname:
        return False, None
    
    return True, {
        'is_host': is_host,
        'nickname': nickname,
        'session_id': session_id
    }

def validate_socket_session(room_id):
    """
    Decorator to validate socket session before allowing action
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            is_valid, user_info = validate_session_for_room(room_id)
            if not is_valid:
                emit('error', {'message': 'Invalid session'})
                return
            return f(*args, **kwargs)
        return wrapped
    return decorator

def require_host_permission(f):
    """Decorator to require host permissions"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('is_host', False):
            emit('error', {'message': 'Only the host can perform this action'})
            return
        return f(*args, **kwargs)
    return wrapped

def generate_csrf_token():
    """Generate a CSRF token for the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token == session.get('csrf_token')

# ========================= END SECURITY FUNCTIONS =========================

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Movie Night - Create Room</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #e4e4e7;
            min-height: 100vh;
            min-height: -webkit-fill-available;
            display: flex;
            align-items: flex-start;
            justify-content: center;
            position: relative;
            overflow-x: hidden;
            overflow-y: auto;
            padding: 20px;
            padding-top: max(20px, env(safe-area-inset-top));
            padding-bottom: max(20px, env(safe-area-inset-bottom));
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 50%, rgba(24, 24, 27, 0.5) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(39, 39, 42, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(24, 24, 27, 0.4) 0%, transparent 50%);
            z-index: -1;
        }
        
        .grid-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255,255,255,0.01) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.01) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            opacity: 0.5;
        }
        
        .logo-area {
            text-align: center;
            margin-bottom: clamp(32px, 6vh, 48px);
        }
        
        .logo {
            width: clamp(56px, 10vw, 72px);
            height: clamp(56px, 10vw, 72px);
            margin: 0 auto clamp(16px, 3vh, 20px);
            background: linear-gradient(135deg, #18181b 0%, #27272a 100%);
            border-radius: clamp(16px, 3vw, 20px);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: clamp(24px, 5vw, 32px);
            box-shadow: 
                0 10px 40px rgba(0, 0, 0, 0.5),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            position: relative;
            animation: float 6s ease-in-out infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
        
        .logo::after {
            content: '';
            position: absolute;
            inset: -1px;
            border-radius: clamp(16px, 3vw, 20px);
            padding: 1px;
            background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.02));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            z-index: -1;
        }
        
        .form-container {
            background: #111111;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: clamp(12px, 2vw, 16px);
            padding: clamp(24px, 5vw, 48px);
            max-width: 480px;
            width: 100%;
            max-height: calc(100vh - 40px);
            overflow-y: auto;
            box-shadow: 
                0 20px 60px rgba(0, 0, 0, 0.8),
                0 0 0 1px rgba(255, 255, 255, 0.02),
                inset 0 0 0 1px rgba(255, 255, 255, 0.02);
            animation: slideUp 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
            position: relative;
            margin: auto 0;
        }
        
        .form-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, 
                transparent, 
                rgba(255, 255, 255, 0.1) 20%, 
                rgba(255, 255, 255, 0.1) 80%, 
                transparent);
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }
        
        h2 {
            font-size: clamp(20px, 5vw, 28px);
            font-weight: 600;
            color: #fafafa;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            color: #71717a;
            font-size: clamp(12px, 2.5vw, 14px);
            margin-bottom: clamp(24px, 5vh, 40px);
            font-weight: 400;
            line-height: 1.4;
        }
        
        .room-type-selector {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: clamp(24px, 5vh, 32px);
        }
        
        .room-type-btn {
            padding: clamp(12px, 2.5vw, 16px);
            background: #18181b;
            border: 2px solid #27272a;
            border-radius: 8px;
            color: #71717a;
            font-size: clamp(12px, 2.5vw, 14px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 8px;
            -webkit-tap-highlight-color: transparent;
        }
        
        .room-type-btn.active {
            background: #27272a;
            border-color: #3f3f46;
            color: #fafafa;
        }
        
        .room-type-btn:hover {
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .room-type-icon {
            font-size: clamp(20px, 4vw, 24px);
        }
        
        .room-type-label {
            font-size: clamp(11px, 2vw, 13px);
        }
        
        .room-forms {
            position: relative;
        }
        
        .room-form {
            display: none;
        }
        
        .room-form.active {
            display: block;
            animation: fadeIn 0.3s ease-out;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .input-group {
            margin-bottom: clamp(16px, 3vh, 24px);
            position: relative;
        }
        
        label {
            display: block;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 500;
            color: #a1a1aa;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        .optional-tag {
            font-size: clamp(9px, 1.8vw, 10px);
            color: #52525b;
            font-weight: 400;
            text-transform: none;
            margin-left: 8px;
        }
        
        input, select {
            width: 100%;
            padding: clamp(12px, 2.5vw, 14px) clamp(14px, 3vw, 16px);
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 8px;
            color: #e4e4e7;
            font-size: clamp(14px, 3vw, 15px);
            transition: all 0.2s ease;
            font-family: inherit;
            -webkit-appearance: none;
            appearance: none;
        }
        
        select {
            cursor: pointer;
            background-image: url('data:image/svg+xml;charset=US-ASCII,%3Csvg%20width%3D%2714%27%20height%3D%278%27%20viewBox%3D%270%200%2014%208%27%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%3E%3Cpath%20d%3D%27M1%201l6%206%206-6%27%20stroke%3D%27%23999%27%20stroke-width%3D%272%27%20fill%3D%27none%27%20fill-rule%3D%27evenodd%27/%3E%3C/svg%3E');
            background-repeat: no-repeat;
            background-position: right 16px center;
            padding-right: 40px;
        }
        
        input::placeholder {
            color: #52525b;
        }
        
        input:focus, select:focus {
            outline: none;
            background: #0f0f0f;
            border-color: #3f3f46;
            box-shadow: 
                0 0 0 3px rgba(63, 63, 70, 0.1),
                0 0 0 1px rgba(63, 63, 70, 0.2);
        }
        
        button {
            width: 100%;
            padding: clamp(12px, 2.5vw, 14px);
            background: #fafafa;
            border: none;
            border-radius: 8px;
            color: #0a0a0a;
            font-size: clamp(13px, 2.5vw, 14px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-top: 12px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(250, 250, 250, 0.1);
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }
        
        button::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.1);
            transform: translate(-50%, -50%) scale(0);
            border-radius: 50%;
            transition: transform 0.5s ease;
        }
        
        button:hover::before {
            transform: translate(-50%, -50%) scale(2);
        }
        
        button:hover {
            background: #e4e4e7;
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(250, 250, 250, 0.15);
        }
        
        button:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(250, 250, 250, 0.1);
        }
        
        .error {
            background: rgba(127, 29, 29, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #ef4444;
            padding: clamp(10px, 2vw, 12px) clamp(14px, 3vw, 16px);
            border-radius: 8px;
            margin-bottom: clamp(16px, 3vh, 24px);
            font-size: clamp(12px, 2.5vw, 13px);
            animation: shake 0.5s;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .features {
            margin-top: clamp(32px, 6vh, 48px);
            padding-top: clamp(24px, 5vh, 36px);
            border-top: 1px solid #1a1a1a;
            display: flex;
            justify-content: space-around;
            text-align: center;
        }
        
        .feature {
            opacity: 0.5;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .feature:hover {
            opacity: 1;
            transform: translateY(-2px);
        }
        
        .feature-icon {
            width: clamp(32px, 7vw, 40px);
            height: clamp(32px, 7vw, 40px);
            margin: 0 auto clamp(8px, 2vw, 12px);
            background: #18181b;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: clamp(14px, 3vw, 18px);
            border: 1px solid #27272a;
        }
        
        .feature-text {
            font-size: clamp(9px, 2vw, 10px);
            color: #71717a;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 500;
        }
        
        @media (max-width: 480px) {
            body {
                padding: 10px;
                align-items: flex-start;
                padding-top: max(10px, env(safe-area-inset-top));
                padding-bottom: max(10px, env(safe-area-inset-bottom));
            }
            
            .form-container {
                padding: 20px 16px;
                max-height: calc(100vh - 20px);
                margin: 0;
                border-radius: 12px;
            }
            
            .logo-area {
                margin-bottom: 24px;
            }
            
            .logo {
                width: 48px;
                height: 48px;
                margin-bottom: 12px;
            }
            
            h2 {
                font-size: 20px;
                margin-bottom: 6px;
            }
            
            .subtitle {
                font-size: 12px;
                margin-bottom: 24px;
            }
            
            .room-type-selector {
                margin-bottom: 20px;
            }
            
            .input-group {
                margin-bottom: 16px;
            }
            
            .features {
                margin-top: 20px;
                padding-top: 16px;
            }
        }
        
        @media (max-height: 600px) {
            body {
                align-items: flex-start;
                padding-top: 10px;
                padding-bottom: 10px;
            }
            
            .form-container {
                max-height: calc(100vh - 20px);
                margin: 0;
            }
            
            .logo-area {
                margin-bottom: 20px;
            }
            
            .features {
                margin-top: 16px;
                padding-top: 12px;
            }
        }
        
        @media (min-width: 1920px) {
            .form-container {
                max-width: 540px;
            }
        }
    </style>
</head>
<body>
    <div class="grid-overlay"></div>
    <div class="form-container">
        <div class="logo-area">
            <div class="logo">🎬</div>
            <h2>Create Room</h2>
            <div class="subtitle">Choose your room type</div>
        </div>
        
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        
        <div class="room-type-selector">
            <div class="room-type-btn active" onclick="selectRoomType('cinema')">
                <div class="room-type-icon">🎬</div>
                <div class="room-type-label">Cinema Room</div>
            </div>
            <div class="room-type-btn" onclick="selectRoomType('movie_room')">
                <div class="room-type-icon">🍿</div>
                <div class="room-type-label">Movie Room</div>
            </div>
            <div class="room-type-btn" onclick="selectRoomType('sports')">
                <div class="room-type-icon">⚽</div>
                <div class="room-type-label">Sports Room</div>
            </div>
            <div class="room-type-btn" onclick="selectRoomType('vm')">
                <div class="room-type-icon">💻</div>
                <div class="room-type-label">VM Room</div>
            </div>
        </div>
        
        <div class="room-forms">
            <form method="POST" class="room-form active" id="cinema-form">
                <input type="hidden" name="room_type" value="cinema">
                <div class="input-group">
                    <label>Your Nickname</label>
                    <input type="text" name="nickname" placeholder="Enter your nickname" required maxlength="20">
                </div>
                
                <div class="input-group">
                    <label>Room Password <span class="optional-tag">(Optional)</span></label>
                    <input type="text" name="password" placeholder="Leave blank for no password">
                </div>
                
                <div class="input-group">
                    <label>Video URLs <span class="optional-tag">(Add as many as you want - they'll play in order!)</span></label>
                    <div id="video-urls-container">
                        <div class="video-url-entry" style="display: flex; gap: 8px; margin-bottom: 8px;">
                            <input type="url" name="video_url" placeholder="https://example.com/video1.mp4 (direct video link)" required style="flex: 1;">
                            <button type="button" class="remove-video-btn" onclick="removeVideoUrl(this)" style="display: none; padding: 8px 12px; background: #ef4444; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px;">✕</button>
                        </div>
                    </div>
                    <button type="button" onclick="addVideoUrl()" style="width: 100%; padding: 10px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; margin-top: 8px; font-weight: 500;">+ Add Another Video</button>
                </div>
                
                <button type="submit">Create Cinema Room</button>
                
                <div class="video-url-help" style="margin-top: 16px; padding: 12px; background: #18181b; border: 1px solid #27272a; border-radius: 8px; font-size: 11px; color: #71717a;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #a1a1aa;">📹 Supported Video URLs:</div>
                    <div style="margin-bottom: 4px;">✅ Direct video files (.mp4, .webm, .ogg)</div>
                    <div style="margin-bottom: 4px;">✅ Example: https://jerrrycans-file.hf.space/rbxg/NV81Bgxdj67DifSxGR0g26uHf0Mzz1AvKLhW0ZVFJe6DXJPf/War%20of%20the%20Worlds_1754678270.mp4</div>
                    <div style="margin-bottom: 4px;">❌ YouTube, Vimeo, or streaming platform URLs</div>
                    <div style="margin-bottom: 4px;">❌ Embedded player URLs (iframe links)</div>
                    <div style="margin-top: 8px; color: #a1a1aa;">💡 Videos will play sequentially - when one ends, the next one automatically starts!</div>
                </div>
            </form>
            
            <form method="POST" class="room-form" id="movie_room-form">
                <input type="hidden" name="room_type" value="movie_room">
                <div class="input-group">
                    <label>Your Nickname</label>
                    <input type="text" name="nickname" placeholder="Enter your nickname" required maxlength="20">
                </div>
                
                <div class="input-group">
                    <label>Room Password <span class="optional-tag">(Optional)</span></label>
                    <input type="text" name="password" placeholder="Leave blank for no password">
                </div>
                
                <button type="submit">Create Movie Room</button>
                
                <div class="video-url-help" style="margin-top: 16px; padding: 12px; background: #18181b; border: 1px solid #27272a; border-radius: 8px; font-size: 11px; color: #71717a;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #a1a1aa;">🍿 Movie Room Features:</div>
                    <div style="margin-bottom: 4px;">✅ Search movies and TV shows from TMDB database</div>
                    <div style="margin-bottom: 4px;">✅ Synchronized playback with all room members</div>
                    <div style="margin-bottom: 4px;">✅ Multiple streaming servers available</div>
                    <div>✅ Watch trending movies or continue watching</div>
                </div>
            </form>
            
            <form method="POST" class="room-form" id="sports-form">
                <input type="hidden" name="room_type" value="sports">
                <div class="input-group">
                    <label>Your Nickname</label>
                    <input type="text" name="nickname" placeholder="Enter your nickname" required maxlength="20">
                </div>
                
                <div class="input-group">
                    <label>Room Password <span class="optional-tag">(Optional)</span></label>
                    <input type="text" name="password" placeholder="Leave blank for no password">
                </div>
                
                <button type="submit">Create Sports Room</button>
                
                <div class="video-url-help" style="margin-top: 16px; padding: 12px; background: #18181b; border: 1px solid #27272a; border-radius: 8px; font-size: 11px; color: #71717a;">
                    <div style="font-weight: 600; margin-bottom: 8px; color: #a1a1aa;">⚽ Sports Streaming:</div>
                    <div style="margin-bottom: 4px;">✅ Watch live sports matches together</div>
                    <div style="margin-bottom: 4px;">✅ Browse by sport type (NFL/American Football, Hockey, etc.)</div>
                    <div style="margin-bottom: 4px;">✅ Multiple streaming sources available</div>
                    <div>✅ Search for specific teams or matches</div>
                </div>
            </form>
            
            <form method="POST" class="room-form" id="vm-form">
                <input type="hidden" name="room_type" value="vm">
                <div class="input-group">
                    <label>Your Nickname</label>
                    <input type="text" name="nickname" placeholder="Enter your nickname" required maxlength="20">
                </div>
                
                <div class="input-group">
                    <label>Room Password <span class="optional-tag">(Optional)</span></label>
                    <input type="text" name="password" placeholder="Leave blank for no password">
                </div>
                
                <div class="input-group">
                    <label>Application to Launch</label>
                    <select name="application">
                        <option value="">None</option>
                        <option value="google-chrome">Google Chrome</option>
                        <option value="firefox">Firefox</option>
                        <option value="code">VS Code</option>
                        <option value="terminal">Terminal</option>
                        <option value="nautilus">File Manager</option>
                        <option value="libreoffice">LibreOffice</option>
                        <option value="gimp">GIMP</option>
                        <option value="vlc">VLC</option>
                    </select>
                </div>
                
                <div class="input-group">
                    <label>Session Timeout (seconds)</label>
                    <input type="number" name="timeout" value="3600" min="60" max="7200" placeholder="3600">
                </div>

                <!-- Hidden fields for screen size detection -->
                <input type="hidden" name="screen_width" id="screen_width" value="1920">
                <input type="hidden" name="screen_height" id="screen_height" value="1080">
                <input type="hidden" name="dpi" id="dpi" value="120">

                <button type="submit">Create VM Room</button>
            </form>
        </div>
        
        <div class="features">
            <div class="feature">
                <div class="feature-icon">🔒</div>
                <div class="feature-text">Encrypted</div>
            </div>
            <div class="feature">
                <div class="feature-icon">⚡</div>
                <div class="feature-text">Real-time</div>
            </div>
            <div class="feature">
                <div class="feature-icon">🌐</div>
                <div class="feature-text">Global</div>
            </div>
        </div>
    </div>
    
    <script>
        function selectRoomType(type) {
            // Update button states
            document.querySelectorAll('.room-type-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.closest('.room-type-btn').classList.add('active');
            
            // Update form visibility
            document.querySelectorAll('.room-form').forEach(form => {
                form.classList.remove('active');
            });
            document.getElementById(type + '-form').classList.add('active');
        }
        
        function addVideoUrl() {
            const container = document.getElementById('video-urls-container');
            const videoCount = container.querySelectorAll('.video-url-entry').length;
            
            const entry = document.createElement('div');
            entry.className = 'video-url-entry';
            entry.style.cssText = 'display: flex; gap: 8px; margin-bottom: 8px;';
            
            entry.innerHTML = `
                <input type="url" name="video_url" placeholder="https://example.com/video${videoCount + 1}.mp4 (direct video link)" required style="flex: 1;">
                <button type="button" class="remove-video-btn" onclick="removeVideoUrl(this)" style="padding: 8px 12px; background: #ef4444; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px;">✕</button>
            `;
            
            container.appendChild(entry);
            updateRemoveButtons();
        }
        
        function removeVideoUrl(btn) {
            const entry = btn.closest('.video-url-entry');
            entry.remove();
            updateRemoveButtons();
        }
        
        function updateRemoveButtons() {
            const container = document.getElementById('video-urls-container');
            const entries = container.querySelectorAll('.video-url-entry');
            
            // Show remove buttons only if there's more than one entry
            entries.forEach((entry, index) => {
                const removeBtn = entry.querySelector('.remove-video-btn');
                if (removeBtn) {
                    removeBtn.style.display = entries.length > 1 ? 'block' : 'none';
                }
            });
        }
    </script>
</body>
</html>
"""

SHARE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Room Created - Movie Night</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #e4e4e7;
            min-height: 100vh;
            min-height: -webkit-fill-available;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
            padding: 20px;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 50%, rgba(24, 24, 27, 0.5) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(39, 39, 42, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(24, 24, 27, 0.4) 0%, transparent 50%);
            z-index: -1;
        }
        
        .grid-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255,255,255,0.01) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.01) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            opacity: 0.5;
        }
        
        .share-container {
            background: #111111;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: clamp(12px, 2vw, 16px);
            padding: clamp(24px, 5vw, 48px);
            max-width: 600px;
            width: 100%;
            box-shadow: 
                0 20px 60px rgba(0, 0, 0, 0.8),
                0 0 0 1px rgba(255, 255, 255, 0.02),
                inset 0 0 0 1px rgba(255, 255, 255, 0.02);
            animation: slideUp 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
            text-align: center;
            position: relative;
        }
        
        .share-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, 
                transparent, 
                rgba(255, 255, 255, 0.1) 20%, 
                rgba(255, 255, 255, 0.1) 80%, 
                transparent);
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }
        
        .success-icon {
            width: clamp(56px, 10vw, 72px);
            height: clamp(56px, 10vw, 72px);
            margin: 0 auto clamp(16px, 3vh, 24px);
            background: linear-gradient(135deg, #18181b 0%, #27272a 100%);
            border-radius: clamp(16px, 3vw, 20px);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: clamp(24px, 5vw, 32px);
            box-shadow: 
                0 10px 40px rgba(0, 0, 0, 0.5),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            animation: celebrate 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        
        @keyframes celebrate {
            0% { transform: scale(0) rotate(0); }
            50% { transform: scale(1.1) rotate(180deg); }
            100% { transform: scale(1) rotate(360deg); }
        }
        
        h2 {
            font-size: clamp(20px, 5vw, 28px);
            font-weight: 600;
            color: #fafafa;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            color: #71717a;
            font-size: clamp(12px, 2.5vw, 14px);
            margin-bottom: clamp(24px, 5vh, 40px);
        }
        
        .link-box {
            background: #0a0a0a;
            border: 1px solid #27272a;
            padding: clamp(16px, 3vw, 20px);
            border-radius: 8px;
            margin: clamp(24px, 4vh, 32px) 0;
            word-break: break-all;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: clamp(11px, 2.5vw, 13px);
            color: #a1a1aa;
            position: relative;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
        }
        
        .link-box:hover {
            background: #0f0f0f;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .link-label {
            position: absolute;
            top: -10px;
            left: 16px;
            background: #111111;
            padding: 0 8px;
            font-size: clamp(9px, 2vw, 10px);
            color: #71717a;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 500;
        }
        
        .protection-status {
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: clamp(10px, 2vw, 12px);
            margin-bottom: clamp(16px, 3vh, 24px);
            font-size: clamp(12px, 2.5vw, 13px);
            color: #71717a;
        }
        
        .protection-status.protected {
            border-color: #22c55e20;
            color: #22c55e;
        }
        
        .button-group {
            display: flex;
            gap: clamp(12px, 2vw, 16px);
            margin-top: clamp(24px, 4vh, 32px);
            flex-wrap: wrap;
        }
        
        button {
            flex: 1;
            min-width: 120px;
            padding: clamp(12px, 2.5vw, 14px);
            border: none;
            border-radius: 8px;
            font-size: clamp(12px, 2.5vw, 14px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            position: relative;
            overflow: hidden;
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }
        
        .copy-btn {
            background: transparent;
            color: #a1a1aa;
            border: 1px solid #27272a;
        }
        
        .copy-btn:hover {
            background: #18181b;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .start-btn {
            background: #fafafa;
            color: #0a0a0a;
            box-shadow: 0 4px 12px rgba(250, 250, 250, 0.1);
        }
        
        .start-btn:hover {
            background: #e4e4e7;
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(250, 250, 250, 0.15);
        }
        
        .start-btn:active {
            transform: translateY(0);
        }
        
        a {
            text-decoration: none;
        }
        
        .room-info {
            display: flex;
            justify-content: center;
            gap: clamp(24px, 5vw, 48px);
            margin-top: clamp(32px, 6vh, 48px);
            padding-top: clamp(24px, 5vh, 36px);
            border-top: 1px solid #1a1a1a;
            flex-wrap: wrap;
        }
        
        .info-item {
            text-align: center;
            min-width: 80px;
        }
        
        .info-label {
            font-size: clamp(9px, 2vw, 10px);
            color: #71717a;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        .info-value {
            font-size: clamp(14px, 3vw, 16px);
            font-weight: 600;
            color: #e4e4e7;
        }
        
        .info-value.active {
            color: #22c55e;
        }
        
        .copied-toast {
            position: fixed;
            top: 50px;
            left: 50%;
            transform: translateX(-50%) translateY(-100px);
            background: #18181b;
            color: #fafafa;
            padding: clamp(12px, 2.5vw, 14px) clamp(20px, 5vw, 28px);
            border-radius: 8px;
            font-size: clamp(12px, 2.5vw, 13px);
            font-weight: 500;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8);
            border: 1px solid #27272a;
            opacity: 0;
            transition: all 0.3s ease;
            z-index: 1000;
        }
        
        .copied-toast.show {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
        
        .vm-info {
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: clamp(12px, 3vw, 16px);
            margin-bottom: clamp(16px, 3vh, 24px);
            font-size: clamp(11px, 2.5vw, 12px);
            color: #71717a;
        }
        
        @media (max-width: 480px) {
            body {
                padding: 16px;
            }
            
            .share-container {
                padding: 24px 20px;
            }
            
            .button-group {
                flex-direction: column;
            }
            
            button {
                width: 100%;
            }
        }
        
        @media (min-width: 1920px) {
            .share-container {
                max-width: 720px;
            }
        }
    </style>
</head>
<body>
    <div class="grid-overlay"></div>
    <div class="share-container">
        <div class="success-icon">✓</div>
        <h2>{{ room_type }} Room Created Successfully</h2>
        <div class="subtitle">Share this link with your friends to join</div>
        
        {% if has_password %}
        <div class="protection-status protected">
            🔒 This room is password protected
        </div>
        {% else %}
        <div class="protection-status">
            🔓 This room has no password
        </div>
        {% endif %}
        
        {% if room_type == 'VM' %}
        <div class="vm-info">
            💻 Virtual Machine ready with {{ vm_app or 'Desktop' }} • Resolution: 1280x720 • DPI: 120
        </div>
        {% elif room_type == 'SPORTS' %}
        <div class="vm-info">
            ⚽ Sports Streaming Room ready • Watch live matches together
        </div>
        {% endif %}
        
        <div class="link-box" id="link" onclick="copyLink()">
            <span class="link-label">Room Link</span>
            {{ share_url }}
        </div>
        
        <div class="button-group">
            <button class="copy-btn" onclick="copyLink()">Copy Link</button>
            <a href="{{ watch_url }}"><button class="start-btn">Enter Room</button></a>
        </div>
        
        <div class="room-info">
            <div class="info-item">
                <div class="info-label">Room ID</div>
                <div class="info-value">{{ room_id }}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Status</div>
                <div class="info-value active">● Active</div>
            </div>
            <div class="info-item">
                <div class="info-label">Your Role</div>
                <div class="info-value">Host</div>
            </div>
            <div class="info-item">
                <div class="info-label">Type</div>
                <div class="info-value">{{ room_type }}</div>
            </div>
        </div>
    </div>
    
    <div class="copied-toast" id="toast">✓ Link copied to clipboard</div>
    
    <script>
        function copyLink() {
            const linkElement = document.getElementById('link');
            // Get only the URL, not the "Room Link" label
            const linkText = linkElement.textContent.trim();
            const url = linkText.replace('Room Link', '').trim();
            navigator.clipboard.writeText(url).then(() => {
                const toast = document.getElementById('toast');
                toast.classList.add('show');
                setTimeout(() => {
                    toast.classList.remove('show');
                }, 2000);
            });
        }

        // Screen size detection for responsive VM resolution
        function detectScreenSize() {
            const screenWidth = window.screen.width;
            const screenHeight = window.screen.height;
            const devicePixelRatio = window.devicePixelRatio || 1;
            const dpi = Math.round(devicePixelRatio * 96); // Standard DPI calculation

            // Update hidden form fields
            document.getElementById('screen_width').value = screenWidth;
            document.getElementById('screen_height').value = screenHeight;
            document.getElementById('dpi').value = dpi;

            console.log(`Detected screen: ${screenWidth}x${screenHeight}, DPI: ${dpi}`);
        }

        // Detect screen size on page load and before form submission
        window.addEventListener('load', detectScreenSize);
        window.addEventListener('resize', detectScreenSize);
    </script>
</body>
</html>
"""

JOIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Join Room - Movie Night</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0a;
            color: #e4e4e7;
            min-height: 100vh;
            min-height: -webkit-fill-available;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
            padding: 20px;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 50%, rgba(24, 24, 27, 0.5) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(39, 39, 42, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(24, 24, 27, 0.4) 0%, transparent 50%);
            z-index: -1;
        }
        
        .grid-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255,255,255,0.01) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.01) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            opacity: 0.5;
        }
        
        .join-container {
            background: #111111;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: clamp(12px, 2vw, 16px);
            padding: clamp(24px, 5vw, 48px);
            max-width: 480px;
            width: 100%;
            box-shadow: 
                0 20px 60px rgba(0, 0, 0, 0.8),
                0 0 0 1px rgba(255, 255, 255, 0.02),
                inset 0 0 0 1px rgba(255, 255, 255, 0.02);
            animation: slideUp 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
            text-align: center;
            position: relative;
        }
        
        .join-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, 
                transparent, 
                rgba(255, 255, 255, 0.1) 20%, 
                rgba(255, 255, 255, 0.1) 80%, 
                transparent);
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }
        
        .logo {
            width: clamp(56px, 10vw, 72px);
            height: clamp(56px, 10vw, 72px);
            margin: 0 auto clamp(16px, 3vh, 24px);
            background: linear-gradient(135deg, #18181b 0%, #27272a 100%);
            border-radius: clamp(16px, 3vw, 20px);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: clamp(24px, 5vw, 32px);
            box-shadow: 
                0 10px 40px rgba(0, 0, 0, 0.5),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }
        
        h2 {
            font-size: clamp(20px, 5vw, 28px);
            font-weight: 600;
            color: #fafafa;
            margin-bottom: clamp(12px, 2vh, 16px);
            letter-spacing: -0.5px;
        }
        
        .room-badge {
            display: inline-block;
            background: #18181b;
            border: 1px solid #27272a;
            padding: clamp(6px, 1.5vw, 8px) clamp(16px, 4vw, 20px);
            border-radius: 100px;
            font-size: clamp(11px, 2.5vw, 12px);
            color: #71717a;
            font-weight: 600;
            margin-bottom: clamp(24px, 5vh, 40px);
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        
        .input-group {
            margin-bottom: clamp(16px, 3vh, 24px);
            position: relative;
            text-align: left;
        }
        
        label {
            display: block;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 500;
            color: #a1a1aa;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        input {
            width: 100%;
            padding: clamp(12px, 2.5vw, 14px) clamp(14px, 3vw, 16px);
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 8px;
            color: #e4e4e7;
            font-size: clamp(14px, 3vw, 15px);
            transition: all 0.2s ease;
            font-family: inherit;
            -webkit-appearance: none;
            appearance: none;
        }
        
        input::placeholder {
            color: #52525b;
        }
        
        input:focus {
            outline: none;
            background: #0f0f0f;
            border-color: #3f3f46;
            box-shadow: 
                0 0 0 3px rgba(63, 63, 70, 0.1),
                0 0 0 1px rgba(63, 63, 70, 0.2);
        }
        
        button {
            width: 100%;
            padding: clamp(12px, 2.5vw, 14px);
            background: #fafafa;
            border: none;
            border-radius: 8px;
            color: #0a0a0a;
            font-size: clamp(13px, 2.5vw, 14px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-top: 12px;
            box-shadow: 0 4px 12px rgba(250, 250, 250, 0.1);
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }
        
        button:hover {
            background: #e4e4e7;
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(250, 250, 250, 0.15);
        }
        
        .error {
            background: rgba(127, 29, 29, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #ef4444;
            padding: clamp(10px, 2vw, 12px) clamp(14px, 3vw, 16px);
            border-radius: 8px;
            margin-bottom: clamp(16px, 3vh, 24px);
            font-size: clamp(12px, 2.5vw, 13px);
            animation: shake 0.5s;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .info-text {
            color: #71717a;
            font-size: clamp(11px, 2.5vw, 12px);
            margin-top: clamp(24px, 4vh, 32px);
            padding-top: clamp(24px, 4vh, 32px);
            border-top: 1px solid #1a1a1a;
        }
        
        .no-password-msg {
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 8px;
            padding: clamp(14px, 3vw, 16px);
            margin-bottom: clamp(16px, 3vh, 24px);
            color: #71717a;
            font-size: clamp(12px, 2.5vw, 13px);
        }
        
        .room-type-indicator {
            display: inline-block;
            background: #18181b;
            border: 1px solid #27272a;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: clamp(10px, 2vw, 11px);
            color: #71717a;
            margin-bottom: 16px;
        }
        
        @media (max-width: 480px) {
            body {
                padding: 16px;
            }
            
            .join-container {
                padding: 24px 20px;
            }
        }
        
        @media (min-width: 1920px) {
            .join-container {
                max-width: 540px;
            }
        }
    </style>
</head>
<body>
    <div class="grid-overlay"></div>
    <div class="join-container">
        <div class="logo">{{ '🎬' if room_type == 'cinema' else '⚽' if room_type == 'sports' else '💻' }}</div>
        <h2>Join {{ room_type }} Room</h2>
        <div class="room-badge">Room {{ room_id }}</div>
        <div class="room-type-indicator">{{ room_type }} Room</div>
        
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        
        <form method="POST">
            <div class="input-group">
                <label>Your Nickname</label>
                <input type="text" name="nickname" placeholder="Enter your nickname" required maxlength="20" autofocus>
            </div>
            
            {% if needs_password %}
            <div class="input-group">
                <label>Room Password</label>
                <input type="password" name="password" placeholder="Enter room password" required>
            </div>
            {% endif %}
            
            <button type="submit">Join Room</button>
        </form>
        
        <div class="info-text">
            {% if needs_password %}
            Enter your nickname and password to join the {{ 'synchronized viewing' if room_type == 'Cinema' else 'movie watching' if room_type == 'Movie_room' else 'sports streaming' if room_type == 'Sports' else 'virtual machine' if room_type == 'Vm' else 'viewing' }} session
        {% else %}
            Enter your nickname to join the {{ 'synchronized viewing' if room_type == 'Cinema' else 'movie watching' if room_type == 'Movie_room' else 'sports streaming' if room_type == 'Sports' else 'virtual machine' if room_type == 'Vm' else 'viewing' }} session
        {% endif %}
        </div>
    </div>
</body>
</html>
"""

WATCH_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Movie Night - {{ room_type }} Room</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --header-height: 60px;
            --safe-area-top: env(safe-area-inset-top);
            --safe-area-bottom: env(safe-area-inset-bottom);
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #000000;
            color: #e4e4e7;
            min-height: 100vh;
            min-height: -webkit-fill-available;
            overflow-x: hidden;
            position: relative;
            padding-top: var(--safe-area-top);
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(ellipse at center top, rgba(24, 24, 27, 0.4) 0%, transparent 40%),
                radial-gradient(ellipse at center bottom, rgba(24, 24, 27, 0.3) 0%, transparent 40%);
            pointer-events: none;
            z-index: 0;
        }
        
        .cinema-container {
            position: relative;
            z-index: 1;
            padding: 0;
            margin: 0 auto;
            max-width: 100%;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px clamp(16px, 3vw, 24px);
            background: rgba(15, 15, 15, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            position: sticky;
            top: 0;
            z-index: 100;
            min-height: var(--header-height);
        }
        
        .title-section {
            display: flex;
            align-items: center;
            gap: clamp(8px, 2vw, 16px);
            flex-wrap: wrap;
        }
        
        .logo-icon {
            width: clamp(32px, 6vw, 40px);
            height: clamp(32px, 6vw, 40px);
            background: #111111;
            border: 1px solid #1a1a1a;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: clamp(16px, 3vw, 20px);
            flex-shrink: 0;
        }
        
        h1 {
            font-size: clamp(16px, 3.5vw, 20px);
            font-weight: 600;
            color: #fafafa;
            letter-spacing: -0.3px;
        }
        
        .room-id {
            background: #111111;
            padding: clamp(4px, 1vw, 6px) clamp(10px, 2vw, 14px);
            border-radius: 6px;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            letter-spacing: 1.2px;
            border: 1px solid #1a1a1a;
            color: #71717a;
            text-transform: uppercase;
        }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: clamp(8px, 2vw, 12px);
        }
        
        .copy-link-btn {
            padding: clamp(6px, 1.5vw, 8px) clamp(12px, 3vw, 16px);
            background: #111111;
            border: 1px solid #1a1a1a;
            border-radius: 6px;
            color: #a1a1aa;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
            white-space: nowrap;
        }
        
        .copy-link-btn:hover {
            background: #18181b;
            border-color: #27272a;
            color: #e4e4e7;
        }
        
        .delete-room-btn {
            padding: clamp(6px, 1.5vw, 8px) clamp(12px, 3vw, 16px);
            background: #dc2626;
            border: 1px solid #dc2626;
            border-radius: 6px;
            color: #fafafa;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
            white-space: nowrap;
        }
        
        .delete-room-btn:hover {
            background: #b91c1c;
            border-color: #b91c1c;
            color: #fafafa;
        }
        
        .role-badge {
            padding: clamp(6px, 1.5vw, 8px) clamp(16px, 3vw, 20px);
            border-radius: 6px;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .role-badge.host {
            background: #18181b;
            color: #22c55e;
            border: 1px solid #22c55e20;
        }
        
        .role-badge.viewer {
            background: #18181b;
            color: #3b82f6;
            border: 1px solid #3b82f620;
        }
        
        .role-badge.has-control {
            background: #18181b;
            color: #f59e0b;
            border: 1px solid #f59e0b20;
        }
        
        .role-badge::before {
            content: '●';
            font-size: 8px;
        }
        
        .main-content {
            flex: 1;
            display: flex;
            padding: clamp(16px, 3vw, 24px);
            gap: clamp(16px, 3vw, 24px);
            overflow: hidden;
        }
        
        .video-section {
            flex: 1;
            display: flex;
            flex-direction: column;
            min-width: 0;
        }
        
        .video-wrapper {
            position: relative;
            width: 100%;
            background: #000;
            border-radius: clamp(8px, 1.5vw, 12px);
            overflow: hidden;
            box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.03);
            margin-bottom: clamp(16px, 3vw, 24px);
            aspect-ratio: 16 / 9;
        }
        
        video {
            width: 100%;
            height: 100%;
            display: block;
            background: #000;
            object-fit: contain;
        }
        
        video:fullscreen {
            object-fit: contain;
        }
        
        .vm-iframe {
            width: 100%;
            height: 100%;
            border: none;
            background: #000;
            object-fit: contain;
            min-height: 400px;
        }
        
        /* Ensure VM iframe scales properly on all devices */
        @media (max-width: 768px) {
            .vm-iframe {
                min-height: 300px;
            }
        }
        
        @media (max-width: 480px) {
            .vm-iframe {
                min-height: 250px;
            }
        }
        
        .vm-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none;
            z-index: 10;
        }
        
        .vm-overlay.no-control {
            pointer-events: all;
            cursor: not-allowed;
        }
        

        
        .controls-panel {
            background: #0f0f0f;
            border: 1px solid #1a1a1a;
            border-radius: clamp(8px, 1.5vw, 12px);
            padding: clamp(16px, 3vw, 32px);
        }
        
        .control-buttons {
            display: flex;
            gap: clamp(8px, 2vw, 12px);
            justify-content: center;
            margin-bottom: clamp(16px, 3vw, 32px);
            flex-wrap: wrap;
        }
        
        .control-btn {
            padding: clamp(10px, 2vw, 12px) clamp(16px, 4vw, 24px);
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            font-size: clamp(11px, 2.5vw, 13px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            background: #111111;
            color: #a1a1aa;
            -webkit-tap-highlight-color: transparent;
            touch-action: manipulation;
        }
        
        .control-btn:hover {
            background: #18181b;
            border-color: #27272a;
            color: #e4e4e7;
            transform: translateY(-1px);
        }
        
        .control-btn:active {
            transform: translateY(0);
        }
        
        .control-btn.play {
            background: #fafafa;
            color: #0a0a0a;
            border: none;
        }
        
        .control-btn.play:hover {
            background: #e4e4e7;
        }
        
        .control-btn.pause {
            background: #FF463F;
            color: #ffffff;
            border: none;
        }
        
        .control-btn.pause:hover {
            background: #FF352E;
        }
        
        .control-btn.primary {
            background: #fafafa;
            color: #0a0a0a;
            border: none;
        }
        
        .control-btn.primary:hover {
            background: #e4e4e7;
        }
        
        .control-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        
        .control-btn.small {
            padding: 8px 12px;
            font-size: 11px;
        }
        
        .queue-controls {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
        }
        
        .queue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        
        .queue-title {
            font-size: 14px;
            font-weight: 600;
            color: #fafafa;
        }
        
        .queue-panel {
            margin-top: 16px;
        }
        
        .queue-add {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
        }
        
        .queue-add input {
            flex: 1;
            padding: 10px 12px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #fafafa;
            font-size: 13px;
        }
        
        .queue-add input:focus {
            outline: none;
            border-color: #3f3f46;
        }
        
        .queue-list {
            max-height: 300px;
            overflow-y: auto;
            margin-bottom: 16px;
        }
        
        .queue-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            margin-bottom: 8px;
            transition: all 0.2s ease;
        }
        
        .queue-item:hover {
            background: #1f1f23;
            border-color: #3f3f46;
        }
        
        .queue-item.current {
            background: #1e293b;
            border-color: #334155;
        }
        
        .queue-item-info {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
            overflow: hidden;
        }
        
        .queue-item-number {
            font-weight: 600;
            color: #71717a;
            min-width: 24px;
        }
        
        .queue-item-url {
            color: #a1a1aa;
            font-size: 12px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .queue-item-badge {
            background: #3b82f6;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            white-space: nowrap;
        }
        
        .queue-item-remove {
            background: #dc2626;
            color: white;
            border: none;
            border-radius: 4px;
            width: 24px;
            height: 24px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: background 0.2s ease;
        }
        
        .queue-item-remove:hover {
            background: #b91c1c;
        }
        
        .queue-navigation {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }
        
        .queue-position {
            font-size: 14px;
            font-weight: 600;
            color: #a1a1aa;
        }
        
        .vm-controls {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: clamp(16px, 3vw, 20px);
            margin-bottom: clamp(16px, 3vw, 24px);
        }
        
        .vm-control-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        
        .vm-control-title {
            font-size: clamp(12px, 2.5vw, 14px);
            font-weight: 600;
            color: #fafafa;
        }
        
        .current-controller {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: clamp(11px, 2.5vw, 12px);
            color: #71717a;
        }
        
        .controller-name {
            color: #f59e0b;
            font-weight: 600;
        }
        
        .control-selector {
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .control-selector select {
            flex: 1;
            min-width: 150px;
            padding: 8px 12px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #e4e4e7;
            font-size: clamp(11px, 2.5vw, 12px);
            cursor: pointer;
        }
        
        .control-selector button {
            padding: 8px 16px;
            background: #f59e0b;
            border: none;
            border-radius: 6px;
            color: #ffffff;
            font-size: clamp(11px, 2.5vw, 12px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
        }
        
        .control-selector button:hover {
            background: #d97706;
        }
        
        .remove-control-btn {
            background: #ef4444 !important;
            color: #ffffff !important;
        }
        
        .remove-control-btn:hover {
            background: #dc2626 !important;
        }
        
        .vm-control-status {
            padding: clamp(10px, 2vw, 12px) clamp(16px, 4vw, 24px);
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            font-size: clamp(11px, 2.5vw, 13px);
            font-weight: 600;
            cursor: default;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            background: #111111;
            color: #a1a1aa;
            -webkit-tap-highlight-color: transparent;
        }
        
        .vm-control-status.no-control {
            background: #18181b;
            color: #f59e0b;
            border-color: #f59e0b20;
        }
        
        .vm-control-status.has-control {
            background: #18181b;
            color: #22c55e;
            border-color: #22c55e20;
        }
        
        .volume-control {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: clamp(12px, 3vw, 20px);
            display: flex;
            align-items: center;
            gap: clamp(12px, 3vw, 20px);
            margin-bottom: clamp(16px, 3vw, 24px);
        }
        
        .volume-label {
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #71717a;
            min-width: 50px;
        }
        
        .volume-slider {
            flex: 1;
            -webkit-appearance: none;
            appearance: none;
            height: 4px;
            border-radius: 2px;
            background: linear-gradient(to right, 
                #fafafa 0%, 
                #fafafa var(--volume-percent), 
                #27272a var(--volume-percent), 
                #27272a 100%);
            outline: none;
            transition: all 0.2s ease;
        }
        
        .volume-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: #fafafa;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        }
        
        .volume-slider::-webkit-slider-thumb:hover {
            transform: scale(1.2);
        }
        
        .volume-value {
            min-width: 40px;
            text-align: right;
            font-weight: 600;
            font-size: clamp(11px, 2.5vw, 13px);
            color: #a1a1aa;
        }
        
        .status-bar {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: clamp(12px, 2.5vw, 16px) clamp(16px, 3vw, 20px);
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: clamp(10px, 2vw, 12px);
            color: #71717a;
            flex-wrap: wrap;
            gap: 12px;
        }
        
        .viewer-count {
            display: flex;
            align-items: center;
            gap: 8px;
            background: #18181b;
            padding: 6px 12px;
            border-radius: 6px;
            border: 1px solid #27272a;
        }
        
        .viewer-count-icon {
            font-size: 14px;
        }
        
        .viewer-count-number {
            font-weight: 600;
            color: #e4e4e7;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-indicator {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #22c55e;
            animation: pulse 2s ease-in-out infinite;
        }
        
        .status-indicator.disconnected {
            background: #ef4444;
            animation: none;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .host-info {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: clamp(16px, 3vw, 20px);
            text-align: center;
            margin-bottom: clamp(16px, 3vw, 24px);
        }
        
        .host-notice {
            color: #a1a1aa;
            font-size: clamp(12px, 2.5vw, 14px);
            line-height: 1.5;
        }
        
        .host-notice strong {
            color: #fafafa;
        }
        
        .viewer-info {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: clamp(16px, 3vw, 24px);
            text-align: center;
            margin-bottom: clamp(16px, 3vw, 32px);
        }
        
        .viewer-info p {
            color: #71717a;
            font-size: clamp(11px, 2.5vw, 13px);
            line-height: 1.6;
        }
        
        .viewer-info .icon {
            font-size: clamp(24px, 5vw, 28px);
            margin-bottom: 12px;
            opacity: 0.5;
        }
        
        /* Sports Streaming Styles */
        .sports-controls {
            background: #0a0a0a;
            border: 1px solid #1a1a1a;
            border-radius: 8px;
            padding: clamp(16px, 3vw, 20px);
            margin-bottom: clamp(16px, 3vw, 24px);
        }
        
        .sports-filter {
            margin-bottom: 16px;
        }
        
        #match-search {
            width: 100%;
            padding: 10px 12px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #e4e4e7;
            font-size: 13px;
            margin-bottom: 12px;
            outline: none;
        }
        
        #match-search:focus {
            border-color: #3f3f46;
        }
        
        .category-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        
        .category-tab {
            padding: 8px 14px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #a1a1aa;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .category-tab:hover {
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .category-tab.active {
            background: #22c55e;
            border-color: #22c55e;
            color: #fff;
        }
        
        .refresh-btn {
            width: 100%;
            padding: 8px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #a1a1aa;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .refresh-btn:hover {
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .matches-list {
            max-height: 400px;
            overflow-y: auto;
            margin-bottom: 16px;
        }
        
        .match-card {
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .match-card:hover {
            border-color: #22c55e;
            transform: translateX(2px);
        }
        
        .match-card.popular {
            border-left: 3px solid #f59e0b;
        }
        
        .match-title {
            font-size: 14px;
            font-weight: 600;
            color: #fafafa;
            margin-bottom: 6px;
        }
        
        .match-teams {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
            font-size: 13px;
            color: #a1a1aa;
        }
        
        .match-vs {
            color: #22c55e;
            font-weight: 600;
        }
        
        .match-meta {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            font-size: 11px;
        }
        
        .match-category {
            background: #22c55e20;
            color: #22c55e;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .match-time {
            color: #71717a;
        }
        
        .match-popular-badge {
            background: #f59e0b;
            color: #fff;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        
        .source-selector {
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid #27272a;
        }
        
        .source-title {
            font-size: 12px;
            font-weight: 600;
            color: #a1a1aa;
            margin-bottom: 8px;
        }
        
        .source-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .source-btn {
            padding: 8px 14px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #a1a1aa;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-transform: uppercase;
        }
        
        .source-btn:hover {
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .source-btn.active {
            background: #22c55e;
            border-color: #22c55e;
            color: #fff;
        }
        
        .selected-match-info {
            margin-top: 16px;
            padding: 12px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
        }
        
        .match-info-title {
            font-size: 13px;
            color: #a1a1aa;
            margin-bottom: 8px;
        }
        
        #current-match-name {
            color: #fafafa;
            font-weight: 600;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #71717a;
            font-size: 13px;
        }
        
        /* Ad Blocker Styles */
        #sports-iframe {
            position: relative;
        }
        
        /* Block common ad elements */
        iframe[id*="google_ads"],
        iframe[id*="aswift"],
        iframe[src*="doubleclick"],
        iframe[src*="googlesyndication"],
        iframe[src*="adservice"],
        iframe[src*="advertising"],
        iframe[src*="popads"],
        iframe[src*="popcash"],
        iframe[src*="propeller"],
        iframe[src*="adnxs"],
        div[class*="ad-container"],
        div[id*="ad-"],
        div[id*="ads-"],
        div[class*="advertisement"],
        div[class*="ad_"],
        div[class*="_ad"],
        .ad-overlay,
        .ads,
        .ad-banner,
        .ad-popup,
        .popup-ad,
        .overlay-ad,
        [class*="AdBlock"],
        [id*="AdBlock"],
        [class*="popup"],
        [id*="popup"],
        [class*="modal"][id*="ad"],
        [style*="z-index: 2147483647"],
        [style*="z-index: 999999"] {
            display: none !important;
            visibility: hidden !important;
            opacity: 0 !important;
            width: 0 !important;
            height: 0 !important;
            position: absolute !important;
            left: -9999px !important;
            pointer-events: none !important;
        }
        
        /* Prevent overlay ads from appearing on top */
        body > div[style*="position: fixed"][style*="z-index"],
        body > div[style*="position: absolute"][style*="z-index: 999"] {
            display: none !important;
        }
        
        .chat-section {
            width: 360px;
            background: #0f0f0f;
            border: 1px solid #1a1a1a;
            border-radius: clamp(8px, 1.5vw, 12px);
            display: flex;
            flex-direction: column;
            height: 100%;
            min-height: 400px;
            max-height: calc(100vh - var(--header-height) - 48px - var(--safe-area-top) - var(--safe-area-bottom));
        }
        
        .chat-toggle {
            display: none;
            position: fixed;
            bottom: calc(20px + var(--safe-area-bottom));
            right: 20px;
            width: 56px;
            height: 56px;
            background: #fafafa;
            border-radius: 50%;
            display: none;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            cursor: pointer;
            z-index: 99;
            -webkit-tap-highlight-color: transparent;
            color: #0a0a0a;
        }
        
        .chat-toggle:hover {
            transform: scale(1.1);
        }
        
        .chat-header {
            padding: clamp(16px, 3vw, 20px);
            border-bottom: 1px solid #1a1a1a;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-shrink: 0;
        }
        
        .chat-title {
            font-size: clamp(12px, 2.5vw, 14px);
            font-weight: 600;
            color: #fafafa;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .chat-close {
            display: none;
            width: 32px;
            height: 32px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 8px;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            font-size: 18px;
            color: #71717a;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
        }
        
        .chat-close:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: clamp(12px, 3vw, 20px);
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        
        .chat-messages::-webkit-scrollbar {
            width: 6px;
        }
        
        .chat-messages::-webkit-scrollbar-track {
            background: transparent;
        }
        
        .chat-messages::-webkit-scrollbar-thumb {
            background: #27272a;
            border-radius: 3px;
        }
        
        .chat-messages::-webkit-scrollbar-thumb:hover {
            background: #3f3f46;
        }
        
        .message {
            animation: messageSlide 0.3s ease-out;
        }
        
        @keyframes messageSlide {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .message-header {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 4px;
            flex-wrap: wrap;
        }
        
        .message-nickname {
            font-size: clamp(11px, 2.5vw, 12px);
            font-weight: 600;
            color: #a1a1aa;
        }
        
        .message-role {
            font-size: clamp(9px, 2vw, 10px);
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .message-role.host {
            background: #22c55e20;
            color: #22c55e;
        }
        
        .message-role.control {
            background: #f59e0b20;
            color: #f59e0b;
        }
        
        .message-time {
            font-size: clamp(9px, 2vw, 10px);
            color: #52525b;
            margin-left: auto;
        }
        
        .message-content {
            font-size: clamp(12px, 2.5vw, 13px);
            color: #e4e4e7;
            line-height: 1.5;
            word-wrap: break-word;
        }
        
        .message-content img {
            max-width: 100%;
            border-radius: 8px;
            margin-top: 8px;
            cursor: pointer;
            transition: transform 0.2s ease;
        }
        
        .message-content img:hover {
            transform: scale(1.02);
        }
        
        .message-content video {
            max-width: 100%;
            border-radius: 8px;
            margin-top: 8px;
        }
        
        .system-message {
            text-align: center;
            font-size: clamp(10px, 2vw, 11px);
            color: #71717a;
            font-style: italic;
            padding: 8px;
            background: #18181b;
            border-radius: 6px;
        }
        
        .chat-input-wrapper {
            padding: clamp(12px, 3vw, 20px);
            border-top: 1px solid #1a1a1a;
            flex-shrink: 0;
        }
        
        .nickname-setter {
            display: flex;
            gap: 8px;
            margin-bottom: 12px;
        }
        
        .nickname-input {
            flex: 1;
            padding: clamp(8px, 2vw, 10px) clamp(12px, 3vw, 14px);
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #e4e4e7;
            font-size: clamp(12px, 2.5vw, 13px);
            transition: all 0.2s ease;
            -webkit-appearance: none;
        }
        
        .nickname-input:focus {
            outline: none;
            background: #0f0f0f;
            border-color: #3f3f46;
        }
        
        .set-nickname-btn {
            padding: clamp(8px, 2vw, 10px) clamp(14px, 3vw, 16px);
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #a1a1aa;
            font-size: clamp(11px, 2.5vw, 12px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
        }
        
        .set-nickname-btn:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .chat-input-container {
            display: flex;
            gap: 8px;
        }
        
        .chat-input {
            flex: 1;
            padding: clamp(10px, 2vw, 12px) clamp(14px, 3vw, 16px);
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 8px;
            color: #e4e4e7;
            font-size: clamp(12px, 2.5vw, 13px);
            transition: all 0.2s ease;
            resize: none;
            max-height: 100px;
            font-family: inherit;
            -webkit-appearance: none;
        }
        
        .chat-input:focus {
            outline: none;
            background: #0f0f0f;
            border-color: #3f3f46;
        }
        
        .chat-buttons {
            display: flex;
            gap: 8px;
        }
        
        .upload-btn {
            padding: clamp(10px, 2vw, 12px) clamp(14px, 3vw, 16px);
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 8px;
            color: #a1a1aa;
            font-size: clamp(14px, 3vw, 16px);
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            -webkit-tap-highlight-color: transparent;
        }
        
        .upload-btn:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .upload-input {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .send-btn {
            padding: clamp(10px, 2vw, 12px) clamp(16px, 4vw, 20px);
            background: #fafafa;
            border: none;
            border-radius: 8px;
            color: #0a0a0a;
            font-size: clamp(11px, 2.5vw, 13px);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            -webkit-tap-highlight-color: transparent;
        }
        
        .send-btn:hover {
            background: #e4e4e7;
            transform: translateY(-1px);
        }
        
        .send-btn:active {
            transform: translateY(0);
        }
        
        .send-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        
        .upload-status {
            position: absolute;
            top: -30px;
            left: 0;
            right: 0;
            text-align: center;
            font-size: 11px;
            color: #71717a;
            background: #0f0f0f;
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid #1a1a1a;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .upload-status.show {
            opacity: 1;
        }
        
        .image-preview {
            position: fixed;
            bottom: calc(80px + var(--safe-area-bottom));
            right: 20px;
            width: min(320px, calc(100vw - 40px));
            background: #0f0f0f;
            border: 1px solid #1a1a1a;
            border-radius: 12px;
            padding: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8);
            z-index: 100;
            animation: slideUp 0.3s ease-out;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .preview-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        
        .preview-title {
            font-size: 12px;
            font-weight: 600;
            color: #a1a1aa;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        .preview-close {
            width: 24px;
            height: 24px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            font-size: 14px;
            color: #71717a;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
        }
        
        .preview-close:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .preview-image {
            width: 100%;
            border-radius: 8px;
            margin-bottom: 12px;
        }
        
        .preview-buttons {
            display: flex;
            gap: 8px;
        }
        
        .preview-btn {
            flex: 1;
            padding: 10px;
            border: none;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            -webkit-tap-highlight-color: transparent;
        }
        
        .preview-cancel {
            background: #18181b;
            color: #a1a1aa;
            border: 1px solid #27272a;
        }
        
        .preview-cancel:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #e4e4e7;
        }
        
        .preview-send {
            background: #fafafa;
            color: #0a0a0a;
        }
        
        .preview-send:hover {
            background: #e4e4e7;
        }
        
        .image-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.95);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
            padding: 20px;
        }
        
        .image-modal.show {
            opacity: 1;
            visibility: visible;
        }
        
        .modal-content {
            position: relative;
            max-width: min(90vw, 1200px);
            max-height: 90vh;
            animation: modalZoom 0.3s ease-out;
        }
        
        @keyframes modalZoom {
            from {
                transform: scale(0.8);
            }
            to {
                transform: scale(1);
            }
        }
        
        .modal-image {
            max-width: 100%;
            max-height: calc(90vh - 40px);
            border-radius: 8px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8);
            object-fit: contain;
        }
        
        .modal-close {
            position: absolute;
            top: -40px;
            right: 0;
            width: 36px;
            height: 36px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            font-size: 18px;
            color: #a1a1aa;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
        }
        
        .modal-close:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #fafafa;
            transform: scale(1.1);
        }
        
        .copied-toast {
            position: fixed;
            top: calc(var(--header-height) + 20px);
            left: 50%;
            transform: translateX(-50%) translateY(-100px);
            background: #18181b;
            color: #fafafa;
            padding: 14px 28px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.8);
            border: 1px solid #27272a;
            opacity: 0;
            transition: all 0.3s ease;
            z-index: 1000;
        }
        
        .copied-toast.show {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
        
        .loading-history {
            text-align: center;
            font-size: 11px;
            color: #52525b;
            padding: 8px;
            font-style: italic;
        }
        
        @media (max-width: 1024px) {
            .main-content {
                flex-direction: column;
                padding: 16px;
            }
            
            .chat-section {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                width: 100%;
                max-height: 100vh;
                border-radius: 0;
                z-index: 200;
            }
            
            .chat-section.show {
                display: flex;
            }
            
            .chat-toggle {
                display: flex;
            }
            
            .chat-close {
                display: flex;
            }
            
            .video-wrapper {
                aspect-ratio: 16 / 9;
            }
        }
        
        @media (max-width: 640px) {
            .header {
                padding: 12px 16px;
            }
            
            .title-section h1 {
                display: none;
            }
            
            .control-buttons {
                flex-direction: column;
                width: 100%;
            }
            
            .control-btn {
                width: 100%;
            }
            
            .image-preview {
                bottom: calc(20px + var(--safe-area-bottom));
                right: 10px;
                left: 10px;
                width: auto;
            }
        }
        
        @media (min-width: 1920px) {
            .cinema-container {
                max-width: 1800px;
            }
            
            .chat-section {
                width: 420px;
            }
        }
        
        @media (min-width: 2560px) {
            .cinema-container {
                max-width: 2400px;
            }
            
            .chat-section {
                width: 480px;
            }
        }
        
        @media (orientation: landscape) and (max-height: 500px) {
            .header {
                position: relative;
                padding: 8px 16px;
                min-height: 48px;
            }
            
            .main-content {
                padding: 8px;
            }
            
            .controls-panel {
                padding: 12px;
            }
            
            .control-buttons {
                margin-bottom: 12px;
            }
        }
    </style>
</head>
<body>
    <div class="cinema-container">
        <div class="header">
            <div class="title-section">
                <div class="logo-icon">{{ '🎬' if room_type == 'cinema' else '⚽' if room_type == 'sports' else '💻' }}</div>
                <h1>{{ room_type }} Room</h1>
                <div class="room-id">{{ room_id }}</div>
            </div>
            <div class="header-right">
                <button class="copy-link-btn" onclick="copyRoomLink()">Copy Link</button>
                {% if is_host %}
                <button class="delete-room-btn" onclick="deleteRoom()">Delete Room</button>
                {% endif %}
                <div class="role-badge {% if is_host %}host{% elif has_control %}has-control{% else %}viewer{% endif %}" id="role-badge">
                    {% if is_host %}Host{% elif has_control %}Controller{% else %}Viewer{% endif %}
                </div>
            </div>
        </div>

        <div class="main-content">
            <div class="video-section">
                <div class="video-wrapper">
                    {% if room_type == 'cinema' %}
                        <video id="video" src="{{ video_url }}" preload="metadata" {% if is_host %}controls{% endif %} playsinline></video>
                    {% elif room_type == 'sports' %}
                        <iframe id="sports-iframe" class="vm-iframe" {% if current_stream_url %}src="{{ current_stream_url }}"{% endif %} allowfullscreen referrerpolicy="no-referrer"></iframe>
                        <div class="vm-overlay" id="sports-overlay"></div>
                        <div id="ad-block-overlay" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 999;"></div>
                    {% else %}
                        <iframe id="vm-iframe" class="vm-iframe" data-vm-id="{{ room_id }}" allowfullscreen></iframe>
                        <div class="vm-overlay" id="vm-overlay"></div>
                    {% endif %}
                </div>

                <div class="controls-panel">
                    {% if room_type == 'cinema' %}
                        {% if is_host %}
                            <div class="host-info">
                                <div class="host-notice">
                                    🎬 <strong>Host Controls:</strong> Use the Play/Pause buttons below to control playback for all viewers
                                </div>
                            </div>
                            
                            <div class="control-buttons">
                                <button class="control-btn play" onclick="playVideo()">
                                    ▶ Play for Everyone
                                </button>
                                <button class="control-btn pause" onclick="pauseVideo()">
                                    ⏸ Pause for Everyone
                                </button>
                                <button class="control-btn" onclick="toggleFullscreen()">
                                    Fullscreen
                                </button>
                            </div>
                            
                            <div class="queue-controls">
                                <div class="queue-header">
                                    <span class="queue-title">🎬 Video Queue (<span id="queue-count">{{ video_queue|length }}</span>)</span>
                                    <button class="control-btn small" onclick="toggleQueuePanel()">
                                        <span id="queue-toggle-icon">▼</span>
                                    </button>
                                </div>
                                
                                <div class="queue-panel" id="queue-panel" style="display: none;">
                                    <div class="queue-add">
                                        <input type="text" id="queue-url-input" placeholder="Enter video URL to add to queue" />
                                        <button class="control-btn primary small" onclick="addToQueue()">Add</button>
                                    </div>
                                    
                                    <div class="queue-list" id="queue-list">
                                        {% for url in video_queue %}
                                        <div class="queue-item {% if loop.index0 == current_video_index %}current{% endif %}" data-index="{{ loop.index0 }}">
                                            <div class="queue-item-info">
                                                <span class="queue-item-number">{{ loop.index }}</span>
                                                <span class="queue-item-url">{{ url[:50] }}{% if url|length > 50 %}...{% endif %}</span>
                                                {% if loop.index0 == current_video_index %}
                                                <span class="queue-item-badge">▶ Now Playing</span>
                                                {% endif %}
                                            </div>
                                            {% if loop.index0 != current_video_index %}
                                            <button class="queue-item-remove" onclick="removeFromQueue({{ loop.index0 }})">×</button>
                                            {% endif %}
                                        </div>
                                        {% endfor %}
                                    </div>
                                    
                                    <div class="queue-navigation">
                                        <button class="control-btn" onclick="previousVideo()" id="prev-btn">
                                            ⏮ Previous
                                        </button>
                                        <span class="queue-position">
                                            <span id="current-position">{{ current_video_index + 1 }}</span> / <span id="total-videos">{{ video_queue|length }}</span>
                                        </span>
                                        <button class="control-btn" onclick="nextVideo()" id="next-btn">
                                            Next ⏭
                                        </button>
                                    </div>
                                </div>
                            </div>
                        {% else %}
                            <div class="viewer-info">
                                <div class="icon">👥</div>
                                <p>You're watching as a viewer. The host controls playback.</p>
                            </div>
                            <div class="control-buttons">
                                <button class="control-btn primary" onclick="requestSync()">
                                    Sync Now
                                </button>
                                <button class="control-btn" onclick="toggleFullscreen()">
                                    Fullscreen
                                </button>
                            </div>
                            
                            <div class="queue-controls">
                                <div class="queue-header">
                                    <span class="queue-title">🎬 Video Queue (<span id="queue-count">{{ video_queue|length }}</span>)</span>
                                    <button class="control-btn small" onclick="toggleQueuePanel()">
                                        <span id="queue-toggle-icon">▼</span>
                                    </button>
                                </div>
                                
                                <div class="queue-panel" id="queue-panel" style="display: none;">
                                    <div class="queue-list" id="queue-list">
                                        {% for url in video_queue %}
                                        <div class="queue-item {% if loop.index0 == current_video_index %}current{% endif %}" data-index="{{ loop.index0 }}">
                                            <div class="queue-item-info">
                                                <span class="queue-item-number">{{ loop.index }}</span>
                                                <span class="queue-item-url">{{ url[:50] }}{% if url|length > 50 %}...{% endif %}</span>
                                                {% if loop.index0 == current_video_index %}
                                                <span class="queue-item-badge">▶ Now Playing</span>
                                                {% endif %}
                                            </div>
                                        </div>
                                        {% endfor %}
                                    </div>
                                    
                                    <div class="queue-navigation">
                                        <span class="queue-position">
                                            <span id="current-position">{{ current_video_index + 1 }}</span> / <span id="total-videos">{{ video_queue|length }}</span>
                                        </span>
                                    </div>
                                </div>
                            </div>
                        {% endif %}
                        
                        <div class="volume-control">
                            <div class="volume-label">Volume</div>
                            <input type="range" class="volume-slider" id="volume" min="0" max="100" value="50" 
                                   style="--volume-percent: 50%" oninput="setVolume(this.value)">
                            <div class="volume-value" id="vol-text">50%</div>
                        </div>
                    {% elif room_type == 'sports' %}
                        {% if is_host %}
                            <div class="sports-controls" id="sports-controls">
                                <div class="host-info">
                                    <div class="host-notice">
                                        ⚽ <strong>Host Controls:</strong> Select a match and source for all viewers
                                    </div>
                                    <div style="margin-top: 8px; padding: 8px; background: #c52238; border: 1px solid #a01d2d; border-radius: 6px; font-size: 11px; color: white;">
                                        ⚠️ <strong>Ads:</strong> A pop up will appear when you click play close it or turn on a adblocker
                                    </div>
                                </div>
                                
                                <div class="sports-filter">
                                    <input type="text" id="match-search" placeholder="🔍 Search matches..." oninput="filterMatches()">
                                    <div class="category-tabs">
                                        <button class="category-tab active" onclick="filterByCategory('all')">All</button>
                                        <button class="category-tab" onclick="filterByCategory('american-football')">🏈 AMERICAN-FOOTBALL</button>
                                        <button class="category-tab" onclick="filterByCategory('hockey')">🏒 Hockey</button>
                                        <button class="category-tab" onclick="filterByCategory('football')">⚽ Soccer</button>
                                        <button class="category-tab" onclick="filterByCategory('other')">🏆 Other</button>
                                    </div>
                                    <button class="refresh-btn" onclick="loadMatches()">🔄 Refresh Matches</button>
                                </div>
                                
                                <div class="matches-list" id="matches-list">
                                    <div class="loading">Loading matches...</div>
                                </div>
                                
                                <div class="source-selector" id="source-selector" style="display: none;">
                                    <div class="source-title">Select Stream Source:</div>
                                    <div class="source-buttons" id="source-buttons"></div>
                                </div>
                                
                                <div class="selected-match-info" id="selected-match-info" style="display: none;">
                                    <div class="match-info-title">Current: <span id="current-match-name">None</span></div>
                                    <button class="control-btn" onclick="closeStream()">Close Stream</button>
                                </div>
                            </div>
                        {% else %}
                            <div class="viewer-info">
                                <div class="icon">👥</div>
                                <p>You're watching as a viewer. The host controls the stream.</p>
                                <div style="margin-top: 12px; padding: 8px; background: #c52238; border: 1px solid #a01d2d; border-radius: 6px; font-size: 11px; color: white; text-align: left;">
                                    ⚠️ <strong>Ads:</strong> A pop up will appear when you click play close it or turn on a adblocker
                                </div>
                            </div>
                            <div id="viewer-match-info" style="padding: 16px; background: #18181b; border-radius: 8px; margin-top: 12px; display: none;">
                                <div style="font-size: 14px; color: #a1a1aa; margin-bottom: 4px;">Now Watching:</div>
                                <div id="viewer-match-name" style="font-size: 16px; font-weight: 600; color: #fafafa;"></div>
                            </div>
                        {% endif %}
                        
                        <div class="control-buttons">
                            <button class="control-btn" onclick="toggleSportsFullscreen()">
                                Fullscreen
                            </button>
                        </div>
                    {% else %}
                        {% if is_host %}
                            <div class="vm-controls">
                                <div class="vm-control-header">
                                    <div class="vm-control-title">VM Control Management</div>
                                    <div class="current-controller">
                                        Current Controller: <span class="controller-name" id="current-controller">You</span>
                                    </div>
                                </div>
                                <div class="control-selector">
                                    <select id="user-selector">
                                        <option value="">Select User</option>
                                    </select>
                                    <button onclick="grantControl()">Grant Control</button>
                                    <button onclick="removeAllControl()" class="remove-control-btn" id="remove-control-btn">Remove All Control</button>
                                </div>
                            </div>
                        {% endif %}
                        
                        <div class="control-buttons">
                            <div class="vm-control-status" id="vm-control-status">
                                <span id="control-status-text">🔒 View Only</span>
                            </div>
                            <button class="control-btn" onclick="toggleVMFullscreen()">
                                Fullscreen
                            </button>
                        </div>
                    {% endif %}
                    
                    <div class="status-bar">
                        <div class="status-item">
                            <div class="status-indicator" id="status-dot"></div>
                            <span id="connection-status">Connected</span>
                        </div>
                        <div class="viewer-count">
                            <span class="viewer-count-icon">👥</span>
                            <span class="viewer-count-number" id="viewer-count">0</span>
                            <span>viewers</span>
                        </div>
                        <div class="status-item" id="debug">
                            Ready
                        </div>
                    </div>
                </div>
            </div>

            <div class="chat-section" id="chat-section">
                <div class="chat-header">
                    <div class="chat-title">
                        💬 Room Chat
                    </div>
                    <div class="chat-close" onclick="toggleChat()">×</div>
                </div>
                
                <div class="chat-messages" id="chat-messages">
                    <div class="loading-history" id="loading-history">Loading chat history...</div>
                </div>
                
                <div class="chat-input-wrapper">
                    <div class="nickname-setter" id="nickname-setter" style="display: none;">
                        <input type="text" class="nickname-input" id="nickname-input" 
                               placeholder="Enter your nickname" maxlength="20">
                        <button class="set-nickname-btn" onclick="setNickname()">Set</button>
                    </div>
                    
                    <div class="chat-input-container" id="chat-input-container" style="display: flex; position: relative;">
                        <div class="upload-status" id="upload-status">Uploading...</div>
                        <textarea class="chat-input" id="chat-input" 
                                  placeholder="Type a message..." rows="1"
                                  onkeypress="handleChatKeypress(event)"
                                  onpaste="handlePaste(event)"></textarea>
                        <div class="chat-buttons">
                            <button class="upload-btn">
                                📎
                                <input type="file" class="upload-input" 
                                       accept="image/*,video/*" 
                                       onchange="handleFileSelect(this)">
                            </button>
                            <button class="send-btn" onclick="sendMessage()" id="send-btn">
                                Send
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="chat-toggle" id="chat-toggle" onclick="toggleChat()">💬</div>
    </div>
    
    <div id="image-preview" class="image-preview" style="display: none;">
        <div class="preview-header">
            <span class="preview-title">Preview</span>
            <div class="preview-close" onclick="cancelPreview()">×</div>
        </div>
        <img id="preview-img" class="preview-image" src="" alt="Preview">
        <div class="preview-buttons">
            <button class="preview-btn preview-cancel" onclick="cancelPreview()">Cancel</button>
            <button class="preview-btn preview-send" onclick="sendPreview()">Send</button>
        </div>
    </div>
    
    <div id="image-modal" class="image-modal" onclick="closeModal(event)">
        <div class="modal-content">
            <div class="modal-close" onclick="closeModal()">×</div>
            <img id="modal-img" class="modal-image" src="" alt="Image">
        </div>
    </div>
    
    <div class="copied-toast" id="toast">✓ Room link copied to clipboard</div>

    <script>
        const socket = io();
        const video = {% if room_type == 'cinema' %}document.getElementById('video'){% else %}null{% endif %};
        const debug = document.getElementById('debug');
        const statusDot = document.getElementById('status-dot');
        const connectionStatus = document.getElementById('connection-status');
        const isHost = {{ is_host|tojson }};
        const roomId = "{{ room_id }}";
        const roomType = "{{ room_type }}";
        let hasControl = {{ has_control|tojson }};
        
        // Chat variables
        let userNickname = null;
        const chatMessages = document.getElementById('chat-messages');
        const chatInput = document.getElementById('chat-input');
        const sendBtn = document.getElementById('send-btn');
        const nicknameInput = document.getElementById('nickname-input');
        const uploadStatus = document.getElementById('upload-status');
        let historyLoaded = false;
        let pendingFileUrl = null;
        
        if (video) {
            video.volume = 0.5;
        }
        let lastEventTime = 0;
        let syncTimeout = null;
        
        // VM specific
        const vmIframe = document.getElementById('vm-iframe');
        const vmOverlay = document.getElementById('vm-overlay');
        
        // Sports specific
        let allMatches = [];
        let filteredMatches = [];
        let currentCategory = 'all';
        let selectedMatch = null;
        const sportsIframe = document.getElementById('sports-iframe');
        const sportsOverlay = document.getElementById('sports-overlay');
        
        // Ad Blocker - Block known ad domains and scripts
        const adBlockList = [
            'doubleclick.net',
            'googlesyndication.com',
            'googleadservices.com',
            'google-analytics.com',
            'googletagmanager.com',
            'facebook.com/tr',
            'facebook.net',
            'adnxs.com',
            'advertising.com',
            'adsystem.com',
            'adtechus.com',
            'serving-sys.com',
            'criteo.com',
            'outbrain.com',
            'taboola.com',
            'scorecardresearch.com',
            'quantserve.com',
            'popads.net',
            'popcash.net',
            'propellerads.com',
            'exoclick.com',
            'adcash.com',
            'juicyads.com',
            'trafficjunky.com',
            'trafficstars.com',
            'adsterra.com',
            'hilltopads.com',
            'clickadu.com',
            'mgid.com',
            'revcontent.com',
            'bidvertiser.com',
            'adf.ly',
            'linkbucks.com',
            'bc.vc',
            'clk.sh',
            'ity.im'
        ];
        
        // Aggressive popup and ad blocker
        // Block all popup windows
        const originalWindowOpen = window.open;
        window.open = function() {
            log('Blocked popup attempt');
            return null;
        };
        
        // Block all alerts, confirms, and prompts from ads
        const originalAlert = window.alert;
        const originalConfirm = window.confirm;
        const originalPrompt = window.prompt;
        
        window.alert = function(msg) {
            // Block ALL alerts (they're almost always from ads/popups)
            log('🚫 BLOCKED alert popup');
            console.error('Alert blocked:', msg);
            return;
        };
        
        window.confirm = function(msg) {
            // Allow confirms from legitimate app functions (check stack trace)
            const stack = new Error().stack;
            if (stack && stack.includes('deleteRoom')) {
                // Allow deleteRoom confirm
                return originalConfirm.call(window, msg);
            }
            log('🚫 BLOCKED confirm dialog');
            console.error('Confirm blocked:', msg);
            return false;
        };
        
        window.prompt = function(msg) {
            log('🚫 BLOCKED prompt dialog');
            console.error('Prompt blocked:', msg);
            return null;
        };
        
        // Prevent clicks from opening new tabs/windows
        document.addEventListener('click', function(e) {
            const target = e.target.closest('a');
            if (target && target.target === '_blank') {
                const href = target.href || '';
                if (adBlockList.some(domain => href.includes(domain))) {
                    e.preventDefault();
                    e.stopPropagation();
                    log(`Blocked ad link: ${href}`);
                }
            }
        }, true);
        
        // Prevent context menu on ads
        document.addEventListener('contextmenu', function(e) {
            const target = e.target;
            if (target.tagName === 'IFRAME' && target.id === 'sports-iframe') {
                // Allow context menu on main iframe
                return;
            }
        }, true);
        
        // Block ad requests
        if (sportsIframe) {
            // Prevent right-click menu spam
            sportsIframe.addEventListener('contextmenu', function(e) {
                // Allow normal context menu
            });
            
            // Monitor iframe loads to apply ad blocking
            sportsIframe.addEventListener('load', function() {
                try {
                    // Try to access iframe content (will fail for cross-origin, but worth trying)
                    const iframeDoc = sportsIframe.contentDocument || sportsIframe.contentWindow.document;
                    if (iframeDoc) {
                        // Remove ad elements
                        const adSelectors = [
                            'iframe[src*="doubleclick"]',
                            'iframe[src*="googlesyndication"]',
                            'div[class*="ad-"]',
                            'div[id*="ad-"]',
                            '[class*="advertisement"]',
                            '.ad-overlay',
                            '.ads'
                        ];
                        
                        adSelectors.forEach(selector => {
                            const elements = iframeDoc.querySelectorAll(selector);
                            elements.forEach(el => el.remove());
                        });
                        
                        // Set up mutation observer to catch dynamically added ads
                        const observer = new MutationObserver(mutations => {
                            adSelectors.forEach(selector => {
                                const elements = iframeDoc.querySelectorAll(selector);
                                elements.forEach(el => el.remove());
                            });
                        });
                        
                        observer.observe(iframeDoc.body, {
                            childList: true,
                            subtree: true
                        });
                    }
                } catch (e) {
                    // Cross-origin restriction - expected for most streams
                    log('Ad blocker: Cross-origin restrictions apply');
                }
            });
        }
        
        // Block ad scripts at document level
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const url = args[0];
            if (typeof url === 'string' && adBlockList.some(domain => url.includes(domain))) {
                log(`Blocked ad request: ${url}`);
                return Promise.reject(new Error('Blocked by ad blocker'));
            }
            return originalFetch.apply(this, args);
        };
        
        // Also block XMLHttpRequest to ad domains
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            if (typeof url === 'string' && adBlockList.some(domain => url.includes(domain))) {
                log(`Blocked XHR ad request: ${url}`);
                return;
            }
            return originalXHROpen.apply(this, arguments);
        };
        
        // Block script tags from ad domains
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeName === 'SCRIPT' && node.src) {
                        if (adBlockList.some(domain => node.src.includes(domain))) {
                            log(`Blocked ad script: ${node.src}`);
                            node.remove();
                        }
                    }
                    if (node.nodeName === 'IFRAME' && node.src) {
                        if (adBlockList.some(domain => node.src.includes(domain))) {
                            log(`Blocked ad iframe: ${node.src}`);
                            node.remove();
                        }
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
        
        // Additional popup blocking - prevent focus change tricks
        let popupAttempts = 0;
        const maxPopupAttempts = 5;
        
        // Override document.write and writeln (used by some aggressive ads)
        document.write = function() {
            log('Blocked document.write attempt');
        };
        document.writeln = function() {
            log('Blocked document.writeln attempt');
        };
        
        // Prevent forced navigation
        let lastUrl = location.href;
        const checkUrlChange = setInterval(() => {
            if (location.href !== lastUrl) {
                // Check if it's an ad redirect
                const currentUrl = location.href;
                if (adBlockList.some(domain => currentUrl.includes(domain))) {
                    log('Blocked ad redirect');
                    history.back();
                }
                lastUrl = location.href;
            }
        }, 100);
        
        // Block beforeunload for ad popups
        window.addEventListener('beforeunload', function(e) {
            popupAttempts++;
            if (popupAttempts > maxPopupAttempts) {
                e.preventDefault();
                e.returnValue = '';
                log('Blocked repeated popup attempt');
                return '';
            }
        });
        
        // Prevent iframe from navigating parent
        if (sportsIframe) {
            try {
                Object.defineProperty(sportsIframe.contentWindow, 'opener', {
                    get: function() { return null; },
                    set: function() { return null; }
                });
            } catch(e) {
                // Expected for cross-origin
            }
        }
        
        // Block focus stealing (common ad trick)
        window.addEventListener('blur', function(e) {
            // Don't block if user actually clicked away
            if (!document.hasFocus()) {
                setTimeout(() => {
                    if (!document.hasFocus()) {
                        window.focus();
                        log('Blocked focus stealing attempt');
                    }
                }, 100);
            }
        });
        
        // Prevent page from being framed by ads
        if (window.top !== window.self) {
            try {
                window.top.location = window.self.location;
            } catch(e) {
                // Framed by different origin
            }
        }
        
        // Continuous ad removal - check every 500ms for new ads
        setInterval(() => {
            // Remove high z-index overlays (common ad technique)
            document.querySelectorAll('div, iframe').forEach(el => {
                const style = window.getComputedStyle(el);
                const zIndex = parseInt(style.zIndex);
                
                if (zIndex > 10000 && el.id !== 'sports-iframe') {
                    // Check if it's not a legitimate element
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 100 && rect.height > 100) {
                        // Likely a popup ad
                        el.remove();
                        log('Removed high z-index popup element');
                    }
                }
            });
            
            // Remove elements with ad-related attributes
            const adSelectors = [
                '[id*="popunder"]',
                '[class*="popunder"]',
                '[id*="popad"]',
                '[class*="popad"]',
                'div[style*="position: fixed"][style*="top: 0"][style*="left: 0"]',
                'iframe[src*="ad"]',
                'iframe[src*="pop"]'
            ];
            
            adSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(el => {
                    if (el.id !== 'sports-iframe' && el.id !== 'vm-iframe') {
                        el.remove();
                        log(`Removed ad element: ${selector}`);
                    }
                });
            });
        }, 500);
        const vmControlStatus = document.getElementById('vm-control-status');
        const controlStatusText = document.getElementById('control-status-text');
        const userSelector = document.getElementById('user-selector');
        const viewerCountElement = document.getElementById('viewer-count');
        const connectedUsers = {};
        
        // VM URL obfuscation
        let vmUrlLoaded = false;
        
        async function loadVMUrl() {
            if (roomType !== 'vm' || !vmIframe || vmUrlLoaded) return;
            
            try {
                const response = await fetch(`/vm-url/${roomId}`, {
                    method: 'GET',
                    credentials: 'same-origin'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    // Create a temporary URL with additional obfuscation
                    const obfuscatedUrl = data.url + (data.url.includes('?') ? '&' : '?') + 
                                        `t=${data.timestamp}&r=${roomId}&v=${Math.random().toString(36).substr(2, 9)}`;
                    
                    // Set the iframe source
                    vmIframe.src = obfuscatedUrl;
                    vmUrlLoaded = true;
                    
                    // Add security measures to make URL harder to discover
                    vmIframe.addEventListener('contextmenu', (e) => e.preventDefault());
                    vmIframe.style.pointerEvents = 'auto'; // Ensure it works normally
                    
                    // Clear the URL from memory after a short delay
                    setTimeout(() => {
                        // Remove the data-vm-id attribute to make it harder to trace
                        vmIframe.removeAttribute('data-vm-id');
                        
                        // URL loaded and secured - no need for periodic refresh
                    }, 2000);
                    
                    log('VM loaded');
                } else {
                    log('Failed to load VM');
                }
            } catch (error) {
                log('VM load error');
                console.error('VM URL load error:', error);
            }
        }
        
        function log(msg) {
            debug.textContent = msg;
            console.log(msg);
        }
        
        function debounce(func, delay) {
            clearTimeout(syncTimeout);
            syncTimeout = setTimeout(func, delay);
        }
        
        function copyRoomLink() {
            const roomLink = window.location.origin + '/join/' + roomId;
            navigator.clipboard.writeText(roomLink).then(() => {
                const toast = document.getElementById('toast');
                toast.classList.add('show');
                setTimeout(() => {
                    toast.classList.remove('show');
                }, 2000);
            });
        }
        
        function deleteRoom() {
            // Use confirm - popup blocker allows it from deleteRoom function
            if (confirm('Are you sure you want to delete this room? This will remove all users and data permanently.')) {
                // Send delete request to server
                fetch('/delete_room', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        room_id: roomId
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Redirect to home page
                        window.location.href = '/';
                    } else {
                        console.error('Failed to delete room:', data.error);
                        log('Failed to delete room: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    log('Failed to delete room. Please try again.');
                });
            }
        }
        
        function toggleChat() {
            const chatSection = document.getElementById('chat-section');
            const chatToggle = document.getElementById('chat-toggle');
            
            if (window.innerWidth <= 1024) {
                chatSection.classList.toggle('show');
                if (chatSection.classList.contains('show')) {
                    chatToggle.style.display = 'none';
                } else {
                    chatToggle.style.display = 'flex';
                }
            }
        }
        
        // Chat functions
        function setNickname() {
            const nickname = nicknameInput.value.trim();
            if (nickname && nickname.length > 0) {
                userNickname = nickname;
                document.getElementById('nickname-setter').style.display = 'none';
                document.getElementById('chat-input-container').style.display = 'flex';
                
                socket.emit('user_joined_chat', {
                    room: roomId,
                    nickname: userNickname,
                    isHost: isHost
                });
                
                chatInput.focus();
            }
        }
        
        function detectMediaUrl(text) {
            // Check if the text is a URL to the file upload service
            const fileServicePattern = /https:\/\/jerrrycans-file\.hf\.space\/[^\s]+/gi;
            const imageExtensions = /\.(jpg|jpeg|png|gif|webp)$/i;
            const videoExtensions = /\.(mp4|webm|ogg|mov)$/i;
            
            return text.replace(fileServicePattern, (url) => {
                if (imageExtensions.test(url)) {
                    return `<img src="${url}" alt="Image" onload="scrollChatToBottom()" onclick="openImageModal('${url}')">`;
                } else if (videoExtensions.test(url)) {
                    return `<video src="${url}" controls onloadeddata="scrollChatToBottom()"></video>`;
                }
                return url;
            });
        }
        
        function formatMessage(text) {
            // Convert file service URLs to embedded media
            let formatted = detectMediaUrl(text);
            return formatted;
        }
        
        function addMessage(data, skipAnimation = false) {
            const messageDiv = document.createElement('div');
            messageDiv.className = skipAnimation ? 'message' : 'message';
            
            const time = data.timestamp ? new Date(data.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) 
                                        : new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            
            let roles = '';
            if (data.isHost) {
                roles += '<span class="message-role host">HOST</span>';
            }
            if (data.hasControl && roomType === 'vm') {
                roles += '<span class="message-role control">CONTROL</span>';
            }
            
            messageDiv.innerHTML = `
                <div class="message-header">
                    <span class="message-nickname">${data.nickname}</span>
                    ${roles}
                    <span class="message-time">${time}</span>
                </div>
                <div class="message-content">${formatMessage(data.message)}</div>
            `;
            
            chatMessages.appendChild(messageDiv);
            if (!skipAnimation) {
                scrollChatToBottom();
            }
        }
        
        function addSystemMessage(message, skipAnimation = false) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'system-message';
            messageDiv.textContent = message;
            chatMessages.appendChild(messageDiv);
            if (!skipAnimation) {
                scrollChatToBottom();
            }
        }
        
        function scrollChatToBottom() {
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        function sendMessage() {
            const message = chatInput.value.trim();
            if (message && userNickname) {
                socket.emit('chat_message', {
                    room: roomId,
                    nickname: userNickname,
                    message: message,
                    isHost: isHost,
                    hasControl: hasControl
                });
                
                chatInput.value = '';
                chatInput.style.height = 'auto';
            }
        }
        
        function handleChatKeypress(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
            }
        }
        
        // Handle paste events for images
        function handlePaste(event) {
            const items = event.clipboardData.items;
            for (let i = 0; i < items.length; i++) {
                const item = items[i];
                if (item.type.indexOf('image') !== -1) {
                    event.preventDefault();
                    const file = item.getAsFile();
                    if (file && userNickname) {
                        showPasteConfirmation(file);
                    }
                    break;
                }
            }
        }
        
        // Show confirmation dialog for pasted images
        function showPasteConfirmation(file) {
            // Create a temporary preview to show the pasted image
            const reader = new FileReader();
            reader.onload = function(e) {
                document.getElementById('preview-img').src = e.target.result;
                document.getElementById('image-preview').style.display = 'block';
                
                // Update the preview title to indicate it's a pasted image
                document.querySelector('.preview-title').textContent = 'Pasted Image - Upload?';
                
                // Show confirmation buttons
                const previewContent = document.querySelector('.preview-content');
                if (previewContent) {
                    previewContent.innerHTML = `
                        <div style="text-align: center; padding: 20px;">
                            <p style="margin-bottom: 20px; color: #e4e4e7;">You pasted an image. Do you want to upload it to the chat?</p>
                            <div style="display: flex; gap: 10px; justify-content: center;">
                                <button onclick="uploadPastedImage()" style="
                                    background: #18181b;
                                    border: 1px solid #27272a;
                                    color: #fafafa;
                                    padding: 10px 20px;
                                    border-radius: 6px;
                                    cursor: pointer;
                                    font-size: 14px;
                                ">Yes, Upload</button>
                                <button onclick="cancelPastedImage()" style="
                                    background: #dc2626;
                                    border: 1px solid #dc2626;
                                    color: #fafafa;
                                    padding: 10px 20px;
                                    border-radius: 6px;
                                    cursor: pointer;
                                    font-size: 14px;
                                ">Cancel</button>
                            </div>
                        </div>
                    `;
                }
            };
            reader.readAsDataURL(file);
            
            // Store file for upload
            pendingFile = file;
        }
        
        // Upload pasted image
        function uploadPastedImage() {
            if (pendingFile && userNickname) {
                uploadFile(pendingFile);
                document.getElementById('image-preview').style.display = 'none';
                pendingFile = null;
            }
        }
        
        // Cancel pasted image upload
        function cancelPastedImage() {
            document.getElementById('image-preview').style.display = 'none';
            pendingFile = null;
        }
        
        function handleFileSelect(input) {
            const file = input.files[0];
            if (!file || !userNickname) return;
            
            // Check if it's an image
            if (file.type.startsWith('image/')) {
                // Create preview
                const reader = new FileReader();
                reader.onload = function(e) {
                    document.getElementById('preview-img').src = e.target.result;
                    document.getElementById('image-preview').style.display = 'block';
                };
                reader.readAsDataURL(file);
                
                // Store file for upload
                pendingFile = file;
            } else {
                // For videos, upload directly
                uploadFile(file);
            }
            
            // Clear the input
            input.value = '';
        }
        
        async function uploadFile(file) {
            // Show upload status
            uploadStatus.classList.add('show');
            uploadStatus.textContent = 'Uploading...';
            
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const response = await fetch('https://jerrrycans-file.hf.space/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const fileUrl = 'https://jerrrycans-file.hf.space' + data.url;
                    
                    // Send the file URL as a message
                    socket.emit('chat_message', {
                        room: roomId,
                        nickname: userNickname,
                        message: fileUrl,
                        isHost: isHost,
                        hasControl: hasControl
                    });
                    
                    uploadStatus.textContent = 'Upload complete!';
                    setTimeout(() => {
                        uploadStatus.classList.remove('show');
                    }, 2000);
                } else {
                    uploadStatus.textContent = 'Upload failed';
                    setTimeout(() => {
                        uploadStatus.classList.remove('show');
                    }, 3000);
                }
            } catch (error) {
                console.error('Upload error:', error);
                uploadStatus.textContent = 'Upload failed';
                setTimeout(() => {
                    uploadStatus.classList.remove('show');
                }, 3000);
            }
        }
        
        function cancelPreview() {
            document.getElementById('image-preview').style.display = 'none';
            pendingFile = null;
        }
        
        function sendPreview() {
            if (pendingFile) {
                uploadFile(pendingFile);
                cancelPreview();
            }
        }
        
        function openImageModal(src) {
            document.getElementById('modal-img').src = src;
            document.getElementById('image-modal').classList.add('show');
        }
        
        function closeModal(event) {
            if (!event || event.target.id === 'image-modal' || event.target.classList.contains('modal-close')) {
                document.getElementById('image-modal').classList.remove('show');
            }
        }
        
        // VM Control functions
        function updateVMAccess() {
            if (roomType === 'vm') {
                if (hasControl || isHost) {
                    // User has control - remove overlay blocking and update status
                    if (vmOverlay) {
                        vmOverlay.classList.remove('no-control');
                    }
                    if (vmControlStatus) {
                        vmControlStatus.classList.add('has-control');
                        vmControlStatus.classList.remove('no-control');
                    }
                    if (controlStatusText) {
                        controlStatusText.textContent = '✓ You Have Control';
                    }
                } else {
                    // User doesn't have control - show overlay to block clicks but allow viewing
                    if (vmOverlay) {
                        vmOverlay.classList.add('no-control');
                    }
                    if (vmControlStatus) {
                        vmControlStatus.classList.add('no-control');
                        vmControlStatus.classList.remove('has-control');
                    }
                    if (controlStatusText) {
                        controlStatusText.textContent = '🔒 View Only';
                    }
                }
            }
        }
        
        function updateViewerCount() {
            const count = Object.keys(connectedUsers).length;
            if (viewerCountElement) {
                viewerCountElement.textContent = count;
            }
        }
        
        function updateRoleBadge() {
            const badge = document.getElementById('role-badge');
            if (badge) {
                badge.className = `role-badge ${isHost ? 'host' : hasControl ? 'has-control' : 'viewer'}`;
                badge.textContent = isHost ? 'Host' : hasControl ? 'Controller' : 'Viewer';
            }
        }
        
        function grantControl() {
            if (isHost && userSelector) {
                const selectedUser = userSelector.value;
                if (selectedUser) {
                    socket.emit('grant_control', {
                        room: roomId,
                        userId: selectedUser
                    });
                }
            }
        }
        
        function removeAllControl() {
            if (isHost) {
                socket.emit('remove_all_control', {
                    room: roomId
                });
            }
        }
        
        function toggleVMFullscreen() {
            if (vmIframe) {
                if (!document.fullscreenElement) {
                    vmIframe.requestFullscreen().catch(err => {
                        log(`Error: ${err.message}`);
                    });
                } else {
                    document.exitFullscreen();
                }
            }
        }
        
        // Sports streaming functions
        function toggleSportsFullscreen() {
            if (sportsIframe) {
                if (!document.fullscreenElement) {
                    sportsIframe.requestFullscreen().catch(err => {
                        log(`Error: ${err.message}`);
                    });
                } else {
                    document.exitFullscreen();
                }
            }
        }
        
        async function loadMatches() {
            if (!isHost) return;
            
            const matchesList = document.getElementById('matches-list');
            matchesList.innerHTML = '<div class="loading">Loading matches...</div>';
            
            try {
                const response = await fetch('https://streamed.pk/api/matches/live');
                if (!response.ok) throw new Error('Failed to fetch matches');
                
                allMatches = await response.json();
                
                // Sort matches: American Football first, then Hockey, then Soccer, then Others
                allMatches.sort((a, b) => {
                    const catOrder = {'american-football': 1, 'nfl': 1, 'hockey': 2, 'football': 3};
                    const catA = catOrder[a.category.toLowerCase()] || 4;
                    const catB = catOrder[b.category.toLowerCase()] || 4;
                    
                    if (catA !== catB) return catA - catB;
                    
                    // Within same category, popular first
                    if (a.popular !== b.popular) return b.popular - a.popular;
                    
                    return 0;
                });
                
                filteredMatches = allMatches;
                displayMatches();
                log(`Loaded ${allMatches.length} matches`);
            } catch (error) {
                matchesList.innerHTML = `<div class="loading" style="color: #ef4444;">Error: ${error.message}</div>`;
                log(`Error loading matches: ${error.message}`);
            }
        }
        
        function displayMatches() {
            const matchesList = document.getElementById('matches-list');
            
            if (filteredMatches.length === 0) {
                matchesList.innerHTML = '<div class="loading">No matches found</div>';
                return;
            }
            
            const html = filteredMatches.map(match => {
                const date = new Date(match.date);
                const timeStr = date.toLocaleString();
                
                let teamsHtml = '';
                if (match.teams && match.teams.home && match.teams.away) {
                    teamsHtml = `
                        <div class="match-teams">
                            <span>${match.teams.home.name}</span>
                            <span class="match-vs">VS</span>
                            <span>${match.teams.away.name}</span>
                        </div>
                    `;
                }
                
                const cat = match.category.toLowerCase();
                let displayCategory = match.category.toUpperCase();
                if (cat === 'american-football' || cat === 'nfl') {
                    displayCategory = 'AMERICAN-FOOTBALL';
                } else if (cat === 'football') {
                    displayCategory = 'SOCCER';
                }
                
                return `
                    <div class="match-card ${match.popular ? 'popular' : ''}" onclick="selectMatch('${match.id}')">
                        <div class="match-title">${match.title}</div>
                        ${teamsHtml}
                        <div class="match-meta">
                            <span class="match-category">${displayCategory}</span>
                            ${match.popular ? '<span class="match-popular-badge">POPULAR</span>' : ''}
                            <span class="match-time">${timeStr}</span>
                        </div>
                    </div>
                `;
            }).join('');
            
            matchesList.innerHTML = html;
        }
        
        function filterByCategory(category) {
            if (!isHost) return;
            
            currentCategory = category;
            
            // Update active tab
            document.querySelectorAll('.category-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Filter matches
            if (category === 'all') {
                filteredMatches = allMatches;
            } else if (category === 'american-football') {
                filteredMatches = allMatches.filter(m => {
                    const cat = m.category.toLowerCase();
                    return cat === 'american-football' || cat === 'nfl';
                });
            } else if (category === 'other') {
                filteredMatches = allMatches.filter(m => {
                    const cat = m.category.toLowerCase();
                    return cat !== 'american-football' && cat !== 'nfl' && cat !== 'hockey' && cat !== 'football' && cat !== 'soccer';
                });
            } else {
                filteredMatches = allMatches.filter(m => 
                    m.category.toLowerCase() === category
                );
            }
            
            displayMatches();
        }
        
        function filterMatches() {
            if (!isHost) return;
            
            const searchTerm = document.getElementById('match-search').value.toLowerCase();
            
            if (!searchTerm) {
                filterByCategory(currentCategory);
                return;
            }
            
            let baseMatches;
            if (currentCategory === 'all') {
                baseMatches = allMatches;
            } else if (currentCategory === 'american-football') {
                baseMatches = allMatches.filter(m => {
                    const cat = m.category.toLowerCase();
                    return cat === 'american-football' || cat === 'nfl';
                });
            } else if (currentCategory === 'other') {
                baseMatches = allMatches.filter(m => {
                    const cat = m.category.toLowerCase();
                    return cat !== 'american-football' && cat !== 'nfl' && cat !== 'hockey' && cat !== 'football' && cat !== 'soccer';
                });
            } else {
                baseMatches = allMatches.filter(m => m.category.toLowerCase() === currentCategory);
            }
            
            filteredMatches = baseMatches.filter(match => {
                const title = match.title.toLowerCase();
                const category = match.category.toLowerCase();
                const homeTeam = match.teams?.home?.name?.toLowerCase() || '';
                const awayTeam = match.teams?.away?.name?.toLowerCase() || '';
                
                return title.includes(searchTerm) ||
                       category.includes(searchTerm) ||
                       homeTeam.includes(searchTerm) ||
                       awayTeam.includes(searchTerm);
            });
            
            displayMatches();
        }
        
        function selectMatch(matchId) {
            if (!isHost) return;
            
            selectedMatch = allMatches.find(m => m.id === matchId);
            if (!selectedMatch) return;
            
            // Show source selector
            const sourceSelector = document.getElementById('source-selector');
            const sourceButtons = document.getElementById('source-buttons');
            
            if (selectedMatch.sources && selectedMatch.sources.length > 0) {
                const sourcesHtml = selectedMatch.sources.map((source, index) => 
                    `<button class="source-btn ${index === 0 ? 'active' : ''}" 
                            onclick="selectSource('${source.source}', '${source.id}', this)">
                        ${source.source.toUpperCase()}
                    </button>`
                ).join('');
                
                sourceButtons.innerHTML = sourcesHtml;
                sourceSelector.style.display = 'block';
                
                // Auto-select first source
                selectSource(selectedMatch.sources[0].source, selectedMatch.sources[0].id);
            }
            
            log(`Selected match: ${selectedMatch.title}`);
        }
        
        async function selectSource(source, id, button) {
            if (!isHost) return;
            
            // Update active button
            if (button) {
                document.querySelectorAll('.source-btn').forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
            }
            
            log(`Loading stream from ${source}...`);
            
            try {
                const response = await fetch(`https://streamed.pk/api/stream/${source}/${id}`);
                if (!response.ok) throw new Error('Failed to fetch stream');
                
                const streams = await response.json();
                
                if (streams.length === 0) {
                    throw new Error('No streams available');
                }
                
                // Use the first stream
                const stream = streams[0];
                
                // Update local iframe
                sportsIframe.src = stream.embedUrl;
                
                // Show selected match info
                document.getElementById('current-match-name').textContent = selectedMatch.title;
                document.getElementById('selected-match-info').style.display = 'block';
                
                // Emit to all viewers
                socket.emit('match_selected', {
                    room: roomId,
                    match: selectedMatch,
                    source: source,
                    streamUrl: stream.embedUrl
                });
                
                log(`Stream loaded: ${stream.language} ${stream.hd ? '(HD)' : '(SD)'}`);
            } catch (error) {
                log(`Error loading stream: ${error.message}`);
            }
        }
        
        function closeStream() {
            if (!isHost) return;
            
            sportsIframe.src = '';
            document.getElementById('selected-match-info').style.display = 'none';
            document.getElementById('source-selector').style.display = 'none';
            selectedMatch = null;
            
            socket.emit('stream_closed', { room: roomId });
            log('Stream closed');
        }
        
        // Update user selector
        function updateUserSelector() {
            if (isHost && userSelector) {
                userSelector.innerHTML = '<option value="">Select User</option>';
                let hasControlUser = false;
                
                Object.entries(connectedUsers).forEach(([userId, userData]) => {
                    if (userData.nickname && !userData.isHost) {
                        const option = document.createElement('option');
                        option.value = userId;
                        option.textContent = userData.nickname + (userData.hasControl ? ' (Current)' : '');
                        userSelector.appendChild(option);
                        
                        if (userData.hasControl) {
                            hasControlUser = true;
                        }
                    }
                });
                
                // Remove All Control button is always visible for hosts
            }
        }
        
        // Auto-resize chat input
        chatInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 100) + 'px';
        });
        
        // Socket event handlers
        socket.on('connect', () => {
            log('Connected');
            connectionStatus.textContent = 'Connected';
            statusDot.classList.remove('disconnected');
            socket.emit('join', {room: roomId});
        });
        
        socket.on('disconnect', () => {
            connectionStatus.textContent = 'Disconnected';
            statusDot.classList.add('disconnected');
            log('Connection lost');
        });
        
        socket.on('joined', () => {
            log('Room joined');
            updateVMAccess();
        });
        
        socket.on('user_list', (users) => {
            Object.assign(connectedUsers, users);
            updateUserSelector();
            updateViewerCount();
        });
        
        socket.on('control_changed', (data) => {
            hasControl = data.userId === socket.id;
            updateVMAccess();
            updateRoleBadge();
            
            const controllerSpan = document.getElementById('current-controller');
            if (controllerSpan) {
                controllerSpan.textContent = data.nickname || 'None';
            }
            
            if (data.userId === null) {
                addSystemMessage(`All VM control has been removed`);
            } else {
            addSystemMessage(`Control granted to ${data.nickname}`);
            }
        });
        
        socket.on('chat_history', (history) => {
            // Clear loading message
            const loadingMsg = document.getElementById('loading-history');
            if (loadingMsg) {
                loadingMsg.remove();
            }
            
            // Only load history once
            if (!historyLoaded) {
                historyLoaded = true;
                
                // Add welcome message if no history
                if (history.length === 0) {
                    addSystemMessage('Welcome to the chat! Set your nickname below to start chatting.', true);
                }
                
                // Add all historical messages
                history.forEach(msg => {
                    if (msg.type === 'message') {
                        addMessage(msg.data, true);
                    } else if (msg.type === 'system') {
                        addSystemMessage(msg.message, true);
                    }
                });
                
                // Scroll to bottom after loading history
                setTimeout(scrollChatToBottom, 100);
            }
        });
        
        socket.on('chat_message', (data) => {
            addMessage(data);
        });
        
        socket.on('room_deleted', (data) => {
            alert('Room has been deleted by the host. You will be redirected to the home page.');
            window.location.href = '/';
        });
        
        socket.on('user_joined_chat', (data) => {
            addSystemMessage(`${data.nickname} joined the chat`);
            updateViewerCount();
        });

        // Cinema room specific events
        if (roomType === 'cinema' && video) {
            socket.on('sync_state', (data) => {
                log(`Synced: ${Math.round(data.time)}s`);
                
                debounce(() => {
                    video.currentTime = data.time;
                    
                    if (data.playing) {
                        video.muted = true;
                        video.play().then(() => {
                            video.muted = false;
                        }).catch(() => {
                            log('Click sync to start');
                        });
                    } else {
                        video.pause();
                    }
                }, 100);
            });

            socket.on('play_signal', (data) => {
                const now = Date.now();
                if (now - lastEventTime < 200) return;
                lastEventTime = now;
                
                log(`Playing: ${Math.round(data.time)}s`);
                
                debounce(() => {
                    video.currentTime = data.time;
                    video.play().catch(e => {
                        log('Playback blocked');
                    });
                }, 50);
            });

            socket.on('pause_signal', (data) => {
                const now = Date.now();
                if (now - lastEventTime < 200) return;
                lastEventTime = now;
                
                log(`Paused: ${Math.round(data.time)}s`);
                
                debounce(() => {
                    video.currentTime = data.time;
                    video.pause();
                }, 50);
            });

            socket.on('seek_signal', (data) => {
                log(`Seeked: ${Math.round(data.time)}s`);
                video.currentTime = data.time;
            });
            
            // Auto-advance to next video when current video ends
            video.addEventListener('ended', () => {
                if (isHost) {
                    log('Video ended, moving to next...');
                    socket.emit('next_video', { room: roomId });
                }
            });
        }
        
        // Queue management socket events
        socket.on('queue_updated', (data) => {
            log('Queue updated');
            updateQueueUI(data);
        });
        
        socket.on('load_next_video', (data) => {
            if (video) {
                log(`Loading video ${data.index + 1} of ${data.queue.length}`);
                video.src = data.url;
                video.currentTime = 0;
                video.load();
                updateQueueUI(data);
            }
        });
        
        socket.on('success', (data) => {
            log(data.message);
        });
        
        socket.on('info', (data) => {
            log(data.message);
        });
        
        // Sports room specific events
        if (roomType === 'sports') {
            socket.on('match_selected', (data) => {
                if (!isHost && sportsIframe) {
                    sportsIframe.src = data.streamUrl;
                    
                    const viewerMatchInfo = document.getElementById('viewer-match-info');
                    const viewerMatchName = document.getElementById('viewer-match-name');
                    if (viewerMatchInfo && viewerMatchName) {
                        viewerMatchName.textContent = data.match.title;
                        viewerMatchInfo.style.display = 'block';
                    }
                    
                    log(`Now watching: ${data.match.title}`);
                }
            });
            
            socket.on('source_changed', (data) => {
                if (!isHost && sportsIframe) {
                    sportsIframe.src = data.streamUrl;
                    log(`Stream source changed`);
                }
            });
            
            socket.on('stream_closed', () => {
                if (!isHost && sportsIframe) {
                    sportsIframe.src = '';
                    const viewerMatchInfo = document.getElementById('viewer-match-info');
                    if (viewerMatchInfo) {
                        viewerMatchInfo.style.display = 'none';
                    }
                    log('Stream closed by host');
                }
            });
            
            // Load matches on page load (host only)
            if (isHost) {
                setTimeout(() => loadMatches(), 1000);
            }
        }

        function playVideo() {
            if (isHost && video) {
                video.play();
                socket.emit('play_command', {room: roomId, time: video.currentTime});
                log(`Playing: ${Math.round(video.currentTime)}s`);
            }
        }

        function pauseVideo() {
            if (isHost && video) {
                video.pause();
                socket.emit('pause_command', {room: roomId, time: video.currentTime});
                log(`Paused: ${Math.round(video.currentTime)}s`);
            }
        }

        function requestSync() {
            log('Syncing...');
            socket.emit('request_sync', {room: roomId});
        }

        function setVolume(value) {
            if (video) {
                video.volume = value / 100;
                document.getElementById('vol-text').textContent = value + '%';
                document.getElementById('volume').style.setProperty('--volume-percent', value + '%');
            }
        }

        function toggleFullscreen() {
            if (video) {
                if (!document.fullscreenElement) {
                    video.requestFullscreen().catch(err => {
                        log(`Error: ${err.message}`);
                    });
                } else {
                    document.exitFullscreen();
                }
            }
        }

        // Queue management functions
        function toggleQueuePanel() {
            const panel = document.getElementById('queue-panel');
            const icon = document.getElementById('queue-toggle-icon');
            if (panel.style.display === 'none') {
                panel.style.display = 'block';
                icon.textContent = '▲';
            } else {
                panel.style.display = 'none';
                icon.textContent = '▼';
            }
        }

        function addToQueue() {
            if (!isHost) return;
            
            const input = document.getElementById('queue-url-input');
            const url = input.value.trim();
            
            if (!url) {
                log('Please enter a video URL');
                return;
            }
            
            socket.emit('add_to_queue', {
                room: roomId,
                url: url
            });
            
            input.value = '';
        }

        function nextVideo() {
            if (!isHost) return;
            socket.emit('next_video', { room: roomId });
        }

        function previousVideo() {
            if (!isHost) return;
            socket.emit('previous_video', { room: roomId });
        }

        function removeFromQueue(index) {
            if (!isHost) return;
            socket.emit('remove_from_queue', {
                room: roomId,
                index: index
            });
        }

        function updateQueueUI(data) {
            const queueList = document.getElementById('queue-list');
            const queueCount = document.getElementById('queue-count');
            const currentPosition = document.getElementById('current-position');
            const totalVideos = document.getElementById('total-videos');
            
            if (queueCount) queueCount.textContent = data.queue.length;
            if (currentPosition) currentPosition.textContent = data.current_index + 1;
            if (totalVideos) totalVideos.textContent = data.queue.length;
            
            if (queueList) {
                queueList.innerHTML = data.queue.map((url, index) => {
                    const isCurrent = index === data.current_index;
                    const truncatedUrl = url.length > 50 ? url.substring(0, 50) + '...' : url;
                    
                    return `
                        <div class="queue-item ${isCurrent ? 'current' : ''}" data-index="${index}">
                            <div class="queue-item-info">
                                <span class="queue-item-number">${index + 1}</span>
                                <span class="queue-item-url">${truncatedUrl}</span>
                                ${isCurrent ? '<span class="queue-item-badge">▶ Now Playing</span>' : ''}
                            </div>
                            ${!isCurrent && isHost ? `<button class="queue-item-remove" onclick="removeFromQueue(${index})">×</button>` : ''}
                        </div>
                    `;
                }).join('');
            }
        }

        if (isHost && video) {
            setInterval(() => {
                if (!video.paused) {
                    socket.emit('time_update', {
                        room: roomId, 
                        time: video.currentTime,
                        playing: !video.paused
                    });
                }
            }, 2000);
            
            let seekDebounceTimer;
            video.addEventListener('seeked', () => {
                clearTimeout(seekDebounceTimer);
                seekDebounceTimer = setTimeout(() => {
                    socket.emit('seek_command', {room: roomId, time: video.currentTime});
                    log(`Seeked: ${Math.round(video.currentTime)}s`);
                }, 300);
            });
        }
        
        if (video) {
            video.addEventListener('loadeddata', () => {
                log('Ready');
            });
        }
        
        if (!isHost && video) {
            setTimeout(() => {
                requestSync();
            }, 1000);
        }
        
                // Auto-join chat for all users since they all have nicknames now
        // Get the actual nickname from the session data
        userNickname = isHost ? '{{ session.host_nickname or "Host" }}' : '{{ session.user_nickname or "User" }}';
        socket.emit('user_joined_chat', {
            room: roomId,
            nickname: userNickname,
            isHost: isHost
        });
        

        
        // Variable to store pending file
        let pendingFile = null;
        
        // Handle window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth > 1024) {
                document.getElementById('chat-section').classList.remove('show');
                document.getElementById('chat-toggle').style.display = 'none';
            } else {
                document.getElementById('chat-toggle').style.display = 'flex';
            }
        });
        
        // Initialize VM access and viewer count on load
        if (roomType === 'vm') {
            updateVMAccess();
            // Load VM URL securely after a short delay
            setTimeout(loadVMUrl, 500);
        }
        updateViewerCount();
    </script>
</body>
</html>
"""

MOVIE_ROOM_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Movie Room - {{ room_id }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --header-height: 60px;
            --safe-area-top: env(safe-area-inset-top);
            --safe-area-bottom: env(safe-area-inset-bottom);
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #000000;
            color: #e4e4e7;
            min-height: 100vh;
            min-height: -webkit-fill-available;
            overflow-x: hidden;
            position: relative;
            padding-top: var(--safe-area-top);
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(ellipse at center top, rgba(24, 24, 27, 0.4) 0%, transparent 40%),
                radial-gradient(ellipse at center bottom, rgba(24, 24, 27, 0.3) 0%, transparent 40%);
            pointer-events: none;
            z-index: 0;
        }
        
        .cinema-container {
            position: relative;
            z-index: 1;
            padding: 0;
            margin: 0 auto;
            max-width: 100%;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px clamp(16px, 3vw, 24px);
            background: rgba(15, 15, 15, 0.95);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            position: sticky;
            top: 0;
            z-index: 100;
            min-height: var(--header-height);
        }
        
        .title-section {
            display: flex;
            align-items: center;
            gap: clamp(8px, 2vw, 16px);
            flex-wrap: wrap;
        }
        
        .logo-icon {
            width: clamp(32px, 6vw, 40px);
            height: clamp(32px, 6vw, 40px);
            background: #111111;
            border: 1px solid #1a1a1a;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: clamp(16px, 3vw, 20px);
            flex-shrink: 0;
        }
        
        h1 {
            font-size: clamp(16px, 3.5vw, 20px);
            font-weight: 600;
            color: #fafafa;
            letter-spacing: -0.3px;
        }
        
        .room-id {
            background: #111111;
            padding: clamp(4px, 1vw, 6px) clamp(10px, 2vw, 14px);
            border-radius: 6px;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            letter-spacing: 1.2px;
            border: 1px solid #1a1a1a;
            color: #71717a;
            text-transform: uppercase;
        }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: clamp(8px, 2vw, 12px);
        }
        
        .copy-link-btn, .chat-toggle-btn {
            padding: clamp(6px, 1.5vw, 8px) clamp(12px, 3vw, 16px);
            background: #111111;
            border: 1px solid #1a1a1a;
            border-radius: 6px;
            color: #a1a1aa;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
            white-space: nowrap;
        }
        
        .copy-link-btn:hover, .chat-toggle-btn:hover {
            background: #18181b;
            border-color: #27272a;
            color: #e4e4e7;
        }
        
        .delete-room-btn {
            padding: clamp(6px, 1.5vw, 8px) clamp(12px, 3vw, 16px);
            background: #dc2626;
            border: 1px solid #dc2626;
            border-radius: 6px;
            color: #fafafa;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
            white-space: nowrap;
        }
        
        .delete-room-btn:hover {
            background: #b91c1c;
            border-color: #b91c1c;
        }
        
        .role-badge {
            padding: clamp(6px, 1.5vw, 8px) clamp(16px, 3vw, 20px);
            border-radius: 6px;
            font-size: clamp(10px, 2vw, 11px);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        
        .role-badge.host {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            color: #fafafa;
            border: 1px solid #b91c1c;
        }
        
        .role-badge.viewer {
            background: #111111;
            color: #71717a;
            border: 1px solid #1a1a1a;
        }
        
        .main-content {
            flex: 1;
            display: flex;
            position: relative;
        }
        
        .content-area {
            flex: 1;
            overflow-y: auto;
            padding: clamp(20px, 4vw, 40px) clamp(16px, 3vw, 24px);
        }
        
        .search-container {
            background: rgba(17, 17, 17, 0.6);
            border: 1px solid rgba(39, 39, 42, 0.5);
            border-radius: 12px;
            padding: clamp(20px, 4vw, 30px);
            margin-bottom: clamp(20px, 3vw, 30px);
            max-width: 100%;
        }
        
        .search-box {
            position: relative;
            margin-bottom: 20px;
        }
        
        .search-box input {
            width: 100%;
            padding: 15px 50px 15px 20px;
            background: #0a0a0a;
            border: 1px solid #27272a;
            border-radius: 8px;
            color: #e4e4e7;
            font-size: 16px;
            transition: all 0.2s;
        }
        
        .search-box input:focus {
            outline: none;
            border-color: #3f3f46;
        }
        
        .search-box .search-icon {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            color: #71717a;
        }
        
        #searchLoader {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 3px solid #27272a;
            border-top: 3px solid #fafafa;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        #searchResults {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: #111111;
            border: 1px solid #27272a;
            border-radius: 8px;
            margin-top: 8px;
            max-height: 400px;
            overflow-y: auto;
            z-index: 1000;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
        }
        
        .search-result-item {
            display: flex;
            gap: 15px;
            padding: 15px;
            border-bottom: 1px solid #18181b;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .search-result-item:hover {
            background: #18181b;
        }
        
        .result-poster {
            width: 50px;
            height: 75px;
            background-size: cover;
            background-position: center;
            border-radius: 4px;
            flex-shrink: 0;
        }
        
        .result-info {
            flex: 1;
            min-width: 0;
        }
        
        .result-title {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .result-type {
            background: #27272a;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin-right: 8px;
        }
        
        .result-year {
            color: #71717a;
            font-size: 13px;
        }
        
        .result-overview {
            color: #71717a;
            font-size: 12px;
            margin-top: 5px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        
        #player-container {
            display: none;
            background: rgba(17, 17, 17, 0.6);
            border: 1px solid rgba(39, 39, 42, 0.5);
            border-radius: 12px;
            padding: clamp(15px, 3vw, 20px);
            margin-bottom: clamp(20px, 3vw, 30px);
        }
        
        .player-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        #nowPlaying {
            font-weight: 600;
            font-size: 18px;
        }
        
        .player-actions {
            display: flex;
            gap: 10px;
        }
        
        .server-btn {
            padding: 8px 16px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #71717a;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
            font-weight: 500;
        }
        
        .server-btn:hover {
            background: #27272a;
            border-color: #3f3f46;
        }
        
        .server-btn.active {
            background: #27272a;
            border-color: #3f3f46;
            color: #fafafa;
        }
        
        .close-player-btn {
            padding: 8px 16px;
            background: #7f1d1d;
            border: 1px solid #991b1b;
            border-radius: 6px;
            color: #fca5a5;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
            font-weight: 500;
            margin-left: 12px;
        }
        
        .close-player-btn:hover {
            background: #991b1b;
            border-color: #b91c1c;
            color: #fef2f2;
            transform: translateY(-1px);
        }
        
        .close-player-btn:active {
            transform: translateY(0);
        }
        
        .player-wrapper {
            position: relative;
            padding-bottom: 56.25%;
            background: #000;
            border-radius: 8px;
            overflow: hidden;
        }
        
        #moviePlayer {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
        }
        
        #tvShowInfo {
            display: none;
            margin-top: 20px;
        }
        
        .tv-controls {
            display: flex;
            gap: 20px;
            margin-top: 20px;
        }
        
        .tv-section {
            flex: 1;
        }
        
        .tv-section h3 {
            font-size: 16px;
            margin-bottom: 10px;
        }
        
        #seasonSelector {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 15px;
        }
        
        .season-btn {
            padding: 8px 16px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #71717a;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .season-btn.active,
        .season-btn:hover {
            background: #27272a;
            border-color: #3f3f46;
            color: #fafafa;
        }
        
        #episodeList {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .episode-item {
            padding: 12px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .episode-item:hover {
            background: #27272a;
            border-color: #3f3f46;
        }
        
        .episode-title {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .episode-number {
            color: #71717a;
            font-size: 12px;
            margin-bottom: 5px;
        }
        
        .episode-overview {
            color: #71717a;
            font-size: 13px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            font-size: 20px;
            margin-bottom: 20px;
        }
        
        .movie-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 20px;
        }
        
        .movie-card {
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .movie-card:hover {
            transform: scale(1.05);
        }
        
        .card-poster {
            width: 100%;
            padding-bottom: 150%;
            background-size: cover;
            background-position: center;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        
        .card-info {
            padding: 0 5px;
        }
        
        .card-title {
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 5px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        
        .card-year-rating {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            color: #71717a;
        }
        
        .card-rating {
            color: #fbbf24;
        }
        
        .card-progress {
            font-size: 12px;
            color: #71717a;
        }
        
        .card-date {
            margin-right: 8px;
        }
        
        .tv-label {
            background: #3f3f46;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
        }
        
        #chat-section {
            width: clamp(280px, 25vw, 360px);
            height: 100%;
            background: rgba(10, 10, 10, 0.98);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-left: 1px solid rgba(255, 255, 255, 0.05);
            display: flex;
            flex-direction: column;
            position: relative;
            z-index: 10;
        }
        
        .chat-header {
            padding: clamp(16px, 3vw, 20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(15, 15, 15, 0.5);
            position: relative;
        }
        
        .chat-header-title {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }
        
        .chat-close-mobile {
            display: none;
            position: absolute;
            top: 16px;
            right: 16px;
            width: 36px;
            height: 36px;
            border: none;
            background: rgba(39, 39, 42, 0.8);
            color: #a1a1aa;
            font-size: 24px;
            line-height: 1;
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.2s ease;
            z-index: 10;
        }
        
        .chat-close-mobile:hover {
            background: rgba(63, 63, 70, 0.9);
            color: #fafafa;
            transform: scale(1.05);
        }
        
        .chat-close-mobile:active {
            transform: scale(0.95);
        }
        
        .chat-header h3 {
            font-size: clamp(14px, 2.5vw, 16px);
            font-weight: 600;
            color: #fafafa;
        }
        
        .viewer-count {
            background: #18181b;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: clamp(9px, 1.8vw, 10px);
            font-weight: 600;
            color: #71717a;
            border: 1px solid #27272a;
            letter-spacing: 0.5px;
        }
        
        .viewer-count-number {
            color: #a1a1aa;
            margin-left: 4px;
        }
        
        .user-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }
        
        .user-chip {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 10px;
            background: #111111;
            border: 1px solid #1a1a1a;
            border-radius: 6px;
            font-size: 11px;
            color: #a1a1aa;
        }
        
        .user-chip.host {
            background: linear-gradient(135deg, rgba(220, 38, 38, 0.15) 0%, rgba(153, 27, 27, 0.15) 100%);
            border-color: rgba(220, 38, 38, 0.3);
            color: #fca5a5;
        }
        
        .user-chip .user-icon {
            font-size: 10px;
        }
        
        #chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: clamp(12px, 2.5vw, 16px);
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-height: 400px;
            min-height: 200px;
        }
        
        #chat-messages::-webkit-scrollbar {
            width: 6px;
        }
        
        #chat-messages::-webkit-scrollbar-track {
            background: transparent;
        }
        
        #chat-messages::-webkit-scrollbar-thumb {
            background: #27272a;
            border-radius: 3px;
        }
        
        #chat-messages::-webkit-scrollbar-thumb:hover {
            background: #3f3f46;
        }
        
        .message {
            animation: messageSlideIn 0.3s ease-out;
            padding: 8px 10px;
            background: rgba(24, 24, 27, 0.4);
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }
        
        @keyframes messageSlideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .message-header {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-bottom: 4px;
        }
        
        .message-nickname {
            font-weight: 600;
            font-size: clamp(11px, 2vw, 12px);
            color: #a1a1aa;
        }
        
        .message-nickname.host {
            color: #fca5a5;
        }
        
        .message-badge {
            padding: 2px 6px;
            background: linear-gradient(135deg, rgba(220, 38, 38, 0.2) 0%, rgba(153, 27, 27, 0.2) 100%);
            border: 1px solid rgba(220, 38, 38, 0.3);
            border-radius: 3px;
            font-size: 9px;
            font-weight: 600;
            color: #fca5a5;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .message-text {
            color: #e4e4e7;
            font-size: clamp(12px, 2.2vw, 13px);
            line-height: 1.5;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .message-text img {
            display: block;
            max-width: 100%;
            height: auto;
            margin-top: 8px;
        }
        
        .message-text video {
            display: block;
            max-width: 100%;
            height: auto;
            margin-top: 8px;
        }
        
        .chat-input {
            padding: clamp(12px, 2.5vw, 16px);
            border-top: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(15, 15, 15, 0.5);
        }
        
        .chat-input-box {
            display: flex;
            gap: 8px;
        }
        
        .chat-input-box input {
            flex: 1;
            padding: clamp(10px, 2vw, 12px);
            background: #111111;
            border: 1px solid #1a1a1a;
            border-radius: 6px;
            color: #e4e4e7;
            font-size: clamp(12px, 2.2vw, 13px);
            transition: all 0.2s ease;
        }
        
        .chat-input-box input:focus {
            outline: none;
            border-color: #27272a;
            background: #0a0a0a;
        }
        
        .chat-input-box input::placeholder {
            color: #52525b;
        }
        
        .chat-input-box button {
            padding: clamp(10px, 2vw, 12px) clamp(16px, 3vw, 20px);
            background: #fafafa;
            color: #0a0a0a;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: clamp(11px, 2vw, 12px);
            cursor: pointer;
            transition: all 0.2s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .chat-input-box button:hover {
            background: #e4e4e7;
        }
        
        .chat-input-box button:active {
            transform: scale(0.98);
        }
        
        .upload-file-btn {
            padding: clamp(10px, 2vw, 12px) !important;
            background: #18181b !important;
            border: 1px solid #27272a !important;
            color: #a1a1aa !important;
            min-width: auto !important;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .upload-file-btn:hover {
            background: #27272a !important;
            color: #e4e4e7 !important;
        }
        
        .host-controls {
            background: rgba(15, 15, 15, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }
        
        .control-section {
            display: flex;
            flex-direction: column;
        }
        
        .control-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        
        .control-btn {
            padding: 10px 16px;
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            color: #e4e4e7;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .control-btn:hover {
            background: #27272a;
            border-color: #3f3f46;
            transform: translateY(-1px);
        }
        
        .control-btn:active {
            transform: translateY(0);
        }
        
        /* Play button - darker green */
        .control-btn[onclick*="playEveryone"] {
            background: #15803d !important;
            border-color: #166534 !important;
        }
        
        .control-btn[onclick*="playEveryone"]:hover {
            background: #16a34a !important;
            border-color: #15803d !important;
        }
        
        /* Pause button - darker red */
        .control-btn[onclick*="pauseEveryone"] {
            background: #991b1b !important;
            border-color: #7f1d1d !important;
        }
        
        .control-btn[onclick*="pauseEveryone"]:hover {
            background: #b91c1c !important;
            border-color: #991b1b !important;
        }
        
        #chat-toggle {
            display: none;
        }
        
        @media (max-width: 1024px) {
            .main-content {
                margin-right: 0;
            }
            
            #chat-section {
                position: fixed;
                right: 0;
                top: 0;
                height: 100vh;
                z-index: 1000;
                transform: translateX(100%);
                transition: transform 0.3s ease;
            }
            
            #chat-section.show {
                transform: translateX(0);
            }
            
            .chat-toggle-btn {
                display: block !important;
            }
            
            .chat-close-mobile {
                display: block;
            }
        }
        
        @media (max-width: 768px) {
            .content-area {
                padding: 15px 12px;
            }
            
            .title-section {
                gap: 8px;
            }
            
            .movie-grid {
                grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
                gap: 15px;
            }
            
            .tv-controls {
                flex-direction: column;
            }
            
            #chat-section {
                width: 100%;
            }
            
            .player-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
                margin-bottom: 12px;
            }
            
            #nowPlaying {
                font-size: 16px;
            }
            
            .player-actions {
                width: 100%;
                flex-wrap: wrap;
            }
            
            .server-btn {
                flex: 1;
                min-width: 80px;
                font-size: 13px;
                padding: 10px 12px;
            }
            
            .close-player-btn {
                flex: 1;
                min-width: 100px;
                margin-left: 0;
                font-size: 13px;
                padding: 10px 12px;
            }
            
            .search-container {
                margin-bottom: 20px;
            }
            
            .search-box input {
                font-size: 14px;
                padding: 12px 40px 12px 16px;
            }
            
            #player-container {
                margin-bottom: 20px;
            }
            
            .player-wrapper {
                border-radius: 6px;
            }
        }
        
        @media (max-width: 480px) {
            .content-area {
                padding: 12px 10px;
            }
            
            .header {
                padding: 12px 15px;
            }
            
            .title-section h1 {
                font-size: 16px;
            }
            
            .logo-icon {
                font-size: 20px;
            }
            
            .room-id {
                font-size: 10px;
                padding: 4px 8px;
            }
            
            .role-badge {
                font-size: 9px;
                padding: 4px 8px;
            }
            
            .player-header {
                gap: 10px;
            }
            
            #nowPlaying {
                font-size: 14px;
            }
            
            .player-actions {
                gap: 8px;
            }
            
            .server-btn,
            .close-player-btn {
                font-size: 12px;
                padding: 8px 10px;
            }
            
            .search-box input {
                font-size: 13px;
                padding: 10px 36px 10px 14px;
            }
            
            .section h2 {
                font-size: 16px;
                margin-bottom: 12px;
            }
            
            .movie-grid {
                grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
                gap: 12px;
            }
            
            .copy-link-btn,
            .chat-toggle-btn,
            .delete-room-btn {
                font-size: 12px;
                padding: 8px 12px;
            }
            
            .chat-close-mobile {
                width: 32px;
                height: 32px;
                font-size: 20px;
                top: 14px;
                right: 14px;
            }
        }
    </style>
</head>
<body>
    <div class="cinema-container">
        <div class="header">
            <div class="title-section">
                <div class="logo-icon">🍿</div>
                <h1>Movie Room</h1>
                <div class="room-id">{{ room_id }}</div>
                <div class="role-badge {{ 'host' if is_host else 'viewer' }}">
                    {{ 'Host' if is_host else 'Viewer' }}
                </div>
            </div>
            <div class="header-right">
                <button class="copy-link-btn" onclick="copyRoomLink()">📋 Copy Link</button>
                <button class="chat-toggle-btn" onclick="toggleChat()" style="display: none;">💬 Chat</button>
                {% if is_host %}
                <button class="delete-room-btn" onclick="deleteRoom()">🗑 Delete</button>
                {% endif %}
            </div>
        </div>
        
        <div class="main-content">
            <div class="content-area">
        
        {% if is_host %}
        <div id="player-container">
            <div class="player-header">
                <div id="nowPlaying">Now Playing</div>
                {% if is_host %}
                <div class="player-actions">
                    <button class="server-btn active" id="server1Btn">Server 1</button>
                    <button class="server-btn" id="server2Btn">Server 2</button>
                    <button class="close-player-btn" id="closePlayer">✕ Close</button>
                </div>
                {% endif %}
            </div>
            <div class="player-wrapper">
                <iframe id="moviePlayer" allowfullscreen allow="autoplay; fullscreen; picture-in-picture; encrypted-media"></iframe>
            </div>
        {% if is_host %}
        <div class="host-controls" id="hostControls" style="display: none;">
            <div class="control-section">
                <h4 style="margin: 0 0 8px 0; font-size: 14px; color: #a1a1aa;">Viewer Controls</h4>
                <div class="control-buttons" style="display: flex; gap: 8px; margin-bottom: 15px;">
                    <button class="control-btn" onclick="playEveryone()" style="flex: 1;">
                        ▶ Play
                    </button>
                    <button class="control-btn" onclick="pauseEveryone()" style="flex: 1;">
                        ⏸ Pause
                    </button>
                </div>
                <div style="padding-top: 15px; border-top: 1px solid #27272a;">
                    <p style="margin: 0; font-size: 12px; color: #71717a; line-height: 1.5;">
                        <strong style="color: #a1a1aa;">ℹ️ How to Watch Together:</strong><br>
                        Timestamp sync is not possible. To watch at the same time, pick a movie or show and it will start at the same time for everyone. Use Play/Pause buttons to control playback together.
                    </p>
                </div>
            </div>
        </div>
        {% endif %}
            {% if is_host %}
            <div id="tvShowInfo">
                <div class="tv-controls">
                    <div class="tv-section">
                        <h3>Seasons</h3>
                        <div id="seasonSelector"></div>
                    </div>
                </div>
                <div class="tv-section">
                    <h3>Episodes</h3>
                    <div id="episodeList"></div>
                </div>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if is_host %}
        <div class="section" id="continueWatchingSection" style="display: none;">
            <h2>Continue Watching</h2>
            <div class="movie-grid" id="continueWatchingGrid"></div>
        </div>
        
        <div class="section">
            <h2>Trending Movies</h2>
            <div class="movie-grid" id="trendingGrid"></div>
        </div>
        
        <div class="search-container">
            <div class="search-box">
                <input type="text" id="movieSearch" placeholder="Search for movies and TV shows...">
                <i class="fas fa-search search-icon"></i>
                <div id="searchLoader">
                    <div class="spinner"></div>
                </div>
                <div id="searchResults"></div>
            </div>
        </div>
        {% else %}
        <div id="waiting-for-host" style="text-align: center; padding: 60px 20px; color: #71717a;">
            <div style="font-size: 48px; margin-bottom: 20px;">🍿</div>
            <h2 style="font-size: 24px; color: #e4e4e7; margin-bottom: 10px;">Waiting for Host</h2>
            <p style="font-size: 16px;">The host will select a movie or TV show to watch together.</p>
        </div>
        {% endif %}
        
            </div><!-- End content-area -->
            
            <div id="chat-section">
                <div class="chat-header">
                    <div class="chat-header-title">
                        <h3>Chat</h3>
                        <div class="viewer-count">
                            <span>👥</span>
                            <span class="viewer-count-number" id="viewer-count">0</span>
                        </div>
                    </div>
                    <button class="chat-close-mobile" onclick="toggleChat()" title="Close chat">✕</button>
                    <div class="user-list" id="user-list"></div>
                </div>
                <div id="chat-messages"></div>
                <div class="chat-input">
                    <div class="chat-input-box">
                        <button class="upload-file-btn" onclick="document.getElementById('fileUpload').click()" title="Upload image or video">📎</button>
                        <input type="file" id="fileUpload" accept="image/*,video/*" style="display: none;" onchange="handleFileUpload(this)">
                        <input type="text" id="messageInput" placeholder="Type a message..." maxlength="500">
                        <button onclick="sendMessage()">Send</button>
                    </div>
                    <div id="uploadStatus" style="display: none; font-size: 11px; color: #71717a; margin-top: 8px;"></div>
                </div>
            </div><!-- End chat-section -->
            
        </div><!-- End main-content -->
    </div><!-- End cinema-container -->
    
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script>
        const socket = io();
        const roomId = '{{ room_id }}';
        const isHost = {{ 'true' if is_host else 'false' }};
        
        // TMDB Configuration
        const TMDB_API_BASE = 'https://api.themoviedb.org/3';
        const TMDB_IMAGE_BASE = 'https://image.tmdb.org/t/p/w500';
        const TMDB_SEARCH_URL = TMDB_API_BASE + '/search/multi';
        const TMDB_TRENDING_URL = TMDB_API_BASE + '/trending/movie/week';
        const TMDB_TV_DETAILS_URL = TMDB_API_BASE + '/tv';
        const TMDB_TV_SEASON_URL = TMDB_API_BASE + '/tv';
        const SERVER1_BASE = 'https://vidlink.pro/movie/';
        const SERVER1_TV_BASE = 'https://vidlink.pro/tv/';
        const SERVER2_BASE = 'https://embed.su/embed/movie/';
        const SERVER2_TV_BASE = 'https://embed.su/embed/tv/';
        const TMDB_API_KEY = 'a70c8a42b2be3a8ca8ed815e25d8dc8f';
        const COOKIE_NAME = 'pozMovieTheaterWatchHistory';
        const MAX_WATCH_HISTORY = 12;
        
        let debounceTimer;
        let currentSearchQuery = '';
        let currentMediaData = null;
        let userUniqueId = null;
        let currentSeasons = [];
        let currentSeasonNumber = 1;
        let currentEpisodes = [];
        let currentEpisodeNumber = 1;
        let currentServer = 'server1';
        let isSyncing = false;
        
        // DOM Elements
        const searchInput = document.getElementById('movieSearch');
        const searchResults = document.getElementById('searchResults');
        const searchLoader = document.getElementById('searchLoader');
        const playerContainer = document.getElementById('player-container');
        let moviePlayer = document.getElementById('moviePlayer');
        const nowPlaying = document.getElementById('nowPlaying');
        const closePlayer = document.getElementById('closePlayer');
        const trendingGrid = document.getElementById('trendingGrid');
        const continueWatchingSection = document.getElementById('continueWatchingSection');
        const continueWatchingGrid = document.getElementById('continueWatchingGrid');
        const seasonSelector = document.getElementById('seasonSelector');
        const episodeList = document.getElementById('episodeList');
        const tvShowInfo = document.getElementById('tvShowInfo');
        
        let userNickname = '';
        let playerReady = false;
        
        // Monitor iframe load
        if (moviePlayer) {
            moviePlayer.addEventListener('load', function() {
                console.log('VidLink player iframe loaded and ready');
                playerReady = true;
            });
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            if (isHost) {
                setupSearch();
                fetchTrending();
                setupUserIdentifier();
                loadContinueWatching();
            }
            setupPopupBlocker();
            
            if (isHost) {
                closePlayer.addEventListener('click', closePlayerHandler);
                document.getElementById('server1Btn').addEventListener('click', switchToServer1);
                document.getElementById('server2Btn').addEventListener('click', switchToServer2);
            }
            
            // Socket events
            socket.emit('join', { room: roomId });
            
            socket.on('joined', function() {
                // Auto-join chat
                userNickname = isHost ? '{{ session.host_nickname or "Host" }}' : '{{ session.user_nickname or "User" }}';
                socket.emit('user_joined_chat', {
                    room: roomId,
                    nickname: userNickname,
                    isHost: isHost
                });
            });
            
            socket.on('media_changed', function(data) {
                if (!isSyncing) {
                    loadMediaFromSync(data);
                }
            });
            
            socket.on('chat_message', function(data) {
                addChatMessage(data.nickname, data.message, data.isHost);
            });
            
            socket.on('chat_history', function(messages) {
                messages.forEach(function(msg) {
                    // Handle both formats: {type: 'message', data: {...}} and direct data
                    const msgData = msg.type === 'message' ? msg.data : msg;
                    if (msgData.nickname && msgData.message) {
                        addChatMessage(msgData.nickname, msgData.message, msgData.isHost);
                    }
                });
            });
            
            socket.on('user_list', function(users) {
                updateUserList(users);
                updateViewerCount(Object.keys(users).length);
            });
            
            // Room deleted event
            socket.on('room_deleted', function(data) {
                alert('Room has been deleted by the host. You will be redirected to the home page.');
                window.location.href = '/';
            });
            
            // Socket error handler
            socket.on('error', function(error) {
                console.error('Socket error:', error);
                if (error.message) {
                    showControlFeedback('❌ Error: ' + error.message);
                }
            });
            
            // VidLink Player Event Tracking
            window.addEventListener('message', function(event) {
                // Only accept messages from VidLink
                if (event.origin !== 'https://vidlink.pro') return;
                
                if (event.data?.type === 'PLAYER_EVENT') {
                    const playerData = event.data.data;
                    
                    // Track host's current time for manual controls
                    if (isHost && playerData.currentTime !== undefined) {
                        hostCurrentTime = playerData.currentTime;
                    }
                    
                    // Only log important events (not timeupdate spam)
                    if (playerData.event !== 'timeupdate') {
                        console.log('Player event:', playerData.event, 'at', playerData.currentTime, 's');
                    }
                    
                    // DISABLED: Automatic broadcast removed - now using manual sync button only
                    // This was causing viewers to constantly reload with every host action
                    /*
                    if (isHost) {
                        socket.emit('player_event', {
                            room: roomId,
                            event: playerData.event,
                            currentTime: playerData.currentTime,
                            duration: playerData.duration
                        });
                    }
                    */
                }
                
                // Watch progress tracking
                if (event.data?.type === 'MEDIA_DATA') {
                    const mediaData = event.data.data;
                    localStorage.setItem('vidLinkProgress', JSON.stringify(mediaData));
                }
            });
            
            // DISABLED: Old automatic sync - now using manual sync button only
            // Automatic sync was causing constant reloads, now sync only happens when host clicks button
            /*
            socket.on('player_sync', function(data) {
                // Disabled - use manual sync button instead
            });
            */
            
            // Receive manual host control commands (viewers only)
        // Viewer control - reload player with play/pause control only
        socket.on('host_control_sync', function(data) {
            if (!isHost && currentMediaData) {
                const timestamp = data.timestamp;
                const action = data.action || 'play';
                
                // Only process play and pause actions
                if (action !== 'play' && action !== 'pause') {
                    console.log('⚠️ Ignoring unsupported action:', action);
                    return;
                }
                
                console.log('🔄 Viewer received:', action, 'at', timestamp, 's');
                
                // Find the player wrapper by class (more reliable than parentElement)
                const playerWrapper = document.querySelector('.player-wrapper');
                if (!playerWrapper) {
                    console.log('⚠️ Player wrapper not found, cannot sync');
                    return;
                }
                
                // NUCLEAR OPTION: We can't access VidLink's iframe localStorage (cross-origin)
                // But we CAN clear OUR localStorage and force a complete iframe reload
                try {
                    // Clear our page's storage (VidLink might check parent page too)
                    localStorage.clear(); // Clear EVERYTHING
                    sessionStorage.clear();
                    
                    // Clear ALL cookies
                    document.cookie.split(";").forEach(function(c) { 
                        document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
                    });
                    
                    console.log('✅ Nuked all storage');
                } catch (e) {
                    console.log('⚠️ Could not clear storage:', e);
                }
                
                // Build URL with startAt parameter
                let baseUrl;
                if (currentMediaData.media_type === 'movie') {
                    baseUrl = (currentServer === 'server1' ? SERVER1_BASE : SERVER2_BASE) + currentMediaData.id;
                } else if (currentMediaData.media_type === 'tv') {
                    baseUrl = (currentServer === 'server1' ? SERVER1_TV_BASE : SERVER2_TV_BASE) + 
                              currentMediaData.id + '/' + currentSeasonNumber + '/' + currentEpisodeNumber;
                }
                
                // Find and remove old iframe if it exists
                const oldIframe = document.getElementById('moviePlayer');
                if (oldIframe) {
                    oldIframe.remove();
                }
                
                // Create brand new iframe (bypasses all caching)
                const newIframe = document.createElement('iframe');
                newIframe.id = 'moviePlayer';
                newIframe.allowFullscreen = true;
                newIframe.allow = 'autoplay; fullscreen; picture-in-picture; encrypted-media';
                
                // Build URL with AGGRESSIVE cache busting (multiple random params)
                const cacheBuster = Date.now();
                const random = Math.random().toString(36).substring(7);
                let syncUrl = baseUrl + '?startAt=' + Math.floor(timestamp) + 
                              '&t=' + cacheBuster + 
                              '&r=' + random + 
                              '&force=' + Math.floor(Math.random() * 999999);
                
                if (action === 'pause') {
                    syncUrl += '&autoplay=false';
                    console.log('⏸ Pausing at', Math.floor(timestamp), 's');
                } else {
                    console.log('▶ Playing at', Math.floor(timestamp), 's');
                }
                
                // Add hash to force browser cache bypass
                syncUrl += '#' + cacheBuster;
                
                newIframe.src = syncUrl;
                
                // Add to DOM
                playerWrapper.appendChild(newIframe);
                
                // Update reference
                moviePlayer = newIframe;
            }
        });
        });
        
        function closePlayerHandler() {
            if (isHost) {
                if (confirm('Close player for everyone?')) {
                    socket.emit('movie_room_close_player', { room: roomId });
                    closePlayerLocal();
                }
            } else {
                closePlayerLocal();
            }
        }
        
        function closePlayerLocal() {
            playerContainer.style.display = 'none';
            moviePlayer.src = '';
            currentMediaData = null;
            if (isHost && tvShowInfo) {
                tvShowInfo.style.display = 'none';
            }
            // Hide host controls
            if (isHost) {
                const hostControls = document.getElementById('hostControls');
                if (hostControls) {
                    hostControls.style.display = 'none';
                }
            }
            // Show "Waiting for Host" message again for viewers
            if (!isHost) {
                const waitingDiv = document.getElementById('waiting-for-host');
                if (waitingDiv) {
                    waitingDiv.style.display = 'block';
                }
            }
        }
        
        // Helper function for control feedback (defined early for use in error handlers)
        function showControlFeedback(message) {
            const toast = document.getElementById('toast');
            if (toast) {
                toast.textContent = message;
                toast.classList.add('show');
                setTimeout(() => {
                    toast.classList.remove('show');
                    toast.textContent = 'Link copied!';
                }, 2000);
            }
        }
        
        // Simple sync controls
        let hostCurrentTime = 0;
        let lastSyncTime = 0;
        const SYNC_COOLDOWN = 3000; // 3 seconds between syncs
        
        function playEveryone() {
            if (!currentMediaData) {
                showControlFeedback('❌ No media playing');
                return;
            }
            const now = Date.now();
            if (now - lastSyncTime < SYNC_COOLDOWN) {
                showControlFeedback('⏳ Wait 3 seconds between controls');
                return;
            }
            lastSyncTime = now;
            
            // Reload host's player too
            reloadPlayerWithAction('play', hostCurrentTime);
            
            // Tell viewers to play
            socket.emit('host_control', {
                room: roomId,
                action: 'play',
                timestamp: hostCurrentTime
            });
            showControlFeedback('▶ Playing for everyone');
        }
        
        function pauseEveryone() {
            if (!currentMediaData) {
                showControlFeedback('❌ No media playing');
                return;
            }
            const now = Date.now();
            if (now - lastSyncTime < SYNC_COOLDOWN) {
                showControlFeedback('⏳ Wait 3 seconds between controls');
                return;
            }
            lastSyncTime = now;
            
            // Reload host's player too
            reloadPlayerWithAction('pause', hostCurrentTime);
            
            // Tell viewers to pause
            socket.emit('host_control', {
                room: roomId,
                action: 'pause',
                timestamp: hostCurrentTime
            });
            showControlFeedback('⏸ Paused for everyone');
        }
        
        // Helper function to reload player with action
        function reloadPlayerWithAction(action, timestamp) {
            const playerWrapper = document.querySelector('.player-wrapper');
            if (!playerWrapper) return;
            
            // Clear all storage (can't access VidLink's iframe localStorage due to cross-origin)
            try {
                localStorage.clear(); // Nuke everything
                sessionStorage.clear();
            } catch (e) {}
            
            // Build URL
            let baseUrl;
            if (currentMediaData.media_type === 'movie') {
                baseUrl = (currentServer === 'server1' ? SERVER1_BASE : SERVER2_BASE) + currentMediaData.id;
            } else if (currentMediaData.media_type === 'tv') {
                baseUrl = (currentServer === 'server1' ? SERVER1_TV_BASE : SERVER2_TV_BASE) + 
                          currentMediaData.id + '/' + currentSeasonNumber + '/' + currentEpisodeNumber;
            }
            
            // Remove old iframe
            const oldIframe = document.getElementById('moviePlayer');
            if (oldIframe) oldIframe.remove();
            
            // Create new iframe
            const newIframe = document.createElement('iframe');
            newIframe.id = 'moviePlayer';
            newIframe.allowFullscreen = true;
            newIframe.allow = 'autoplay; fullscreen; picture-in-picture; encrypted-media';
            
            // Build URL with AGGRESSIVE cache busting
            const cacheBuster = Date.now();
            const random = Math.random().toString(36).substring(7);
            let syncUrl = baseUrl + '?startAt=' + Math.floor(timestamp) + 
                          '&t=' + cacheBuster + 
                          '&r=' + random + 
                          '&force=' + Math.floor(Math.random() * 999999);
            
            if (action === 'pause') {
                syncUrl += '&autoplay=false';
            }
            
            // Add hash to force browser cache bypass
            syncUrl += '#' + cacheBuster;
            
            newIframe.src = syncUrl;
            playerWrapper.appendChild(newIframe);
            moviePlayer = newIframe;
        }
        
        
        socket.on('player_closed', function() {
            closePlayerLocal();
        });
        
        function setupUserIdentifier() {
            userUniqueId = getCookie('pozMovieTheaterUniqueId');
            if (!userUniqueId) {
                userUniqueId = 'user_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
                setCookie('pozMovieTheaterUniqueId', userUniqueId, 365 * 10);
            }
        }
        
        function setupSearch() {
            searchInput.addEventListener('input', function() {
                const query = searchInput.value.trim();
                clearTimeout(debounceTimer);
                
                if (query === '') {
                    searchResults.style.display = 'none';
                    currentSearchQuery = '';
                    return;
                }
                
                searchLoader.style.display = 'block';
                
                debounceTimer = setTimeout(() => {
                    if (query !== currentSearchQuery) {
                        currentSearchQuery = query;
                        performSearch(query);
                    }
                }, 300);
            });
            
            document.addEventListener('click', function(event) {
                if (!searchResults.contains(event.target) && event.target !== searchInput) {
                    searchResults.style.display = 'none';
                }
            });
            
            searchInput.addEventListener('focus', function() {
                if (currentSearchQuery !== '') {
                    searchResults.style.display = 'block';
                }
            });
        }
        
        async function performSearch(query) {
            try {
                const url = TMDB_SEARCH_URL + '?api_key=' + TMDB_API_KEY + '&language=en-US&query=' + encodeURIComponent(query) + '&page=1&include_adult=true';
                const response = await fetch(url);
                if (!response.ok) throw new Error('HTTP error! Status: ' + response.status);
                const data = await response.json();
                displaySearchResults(data);
            } catch (error) {
                console.error('Error fetching search results:', error);
                searchResults.innerHTML = '<div class="search-result-item">Error fetching results. Please try again.</div>';
                searchResults.style.display = 'block';
            } finally {
                searchLoader.style.display = 'none';
            }
        }
        
        function displaySearchResults(data) {
            searchResults.innerHTML = '';
            
            if (!data.results || data.results.length === 0) {
                searchResults.innerHTML = '<div class="search-result-item">No results found</div>';
                searchResults.style.display = 'block';
                return;
            }
            
            const resultsToShow = data.results.slice(0, 10);
            
            resultsToShow.forEach(item => {
                if (!['movie', 'tv'].includes(item.media_type)) return;
                
                const resultItem = document.createElement('div');
                resultItem.className = 'search-result-item';
                
                const posterUrl = item.poster_path 
                    ? TMDB_IMAGE_BASE + item.poster_path
                    : 'https://via.placeholder.com/50x75?text=No+Image';
                
                const title = item.media_type === 'movie' ? item.title : item.name;
                const releaseYear = item.release_date 
                    ? new Date(item.release_date).getFullYear()
                    : (item.first_air_date ? new Date(item.first_air_date).getFullYear() : 'N/A');
                const mediaTypeLabel = item.media_type === 'tv' ? 'TV Show' : 'Movie';
                
                resultItem.innerHTML = `
                    <div class="result-poster" style="background-image: url('` + posterUrl + `')"></div>
                    <div class="result-info">
                        <div class="result-title">` + title + `</div>
                        <div>
                            <span class="result-type">` + mediaTypeLabel + `</span>
                            <span class="result-year">` + releaseYear + `</span>
                        </div>
                        <div class="result-overview">` + (item.overview || 'No description available') + `</div>
                    </div>
                `;
                
                resultItem.addEventListener('click', function() {
                    if (isHost) {
                        if (item.media_type === 'movie') {
                            playMedia(item.id, title, item.poster_path, 'movie');
                        } else {
                            playTVShow(item.id, title, item.poster_path);
                        }
                        // Scroll to top to show player
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                    } else {
                        alert('Only the host can change the media.');
                    }
                });
                
                searchResults.appendChild(resultItem);
            });
            
            searchResults.style.display = 'block';
        }
        
        async function playTVShow(id, title, posterPath) {
            try {
                const url = TMDB_TV_DETAILS_URL + '/' + id + '?api_key=' + TMDB_API_KEY + '&language=en-US';
                const response = await fetch(url);
                if (!response.ok) throw new Error('HTTP error! Status: ' + response.status);
                const data = await response.json();
                
                currentMediaData = {
                    id: id,
                    title: title,
                    poster_path: posterPath,
                    media_type: 'tv',
                    seasons: data.seasons
                };
                
                currentSeasons = data.seasons.filter(season => season.season_number > 0);
                currentSeasonNumber = currentSeasons.length > 0 ? currentSeasons[0].season_number : 1;
                currentEpisodeNumber = 1;
                
                nowPlaying.textContent = 'Now Playing: ' + title;
                playerContainer.style.display = 'block';
                searchResults.style.display = 'none';
                
                if (isHost) {
                    renderSeasonSelector();
                    await loadSeasonEpisodes(currentSeasonNumber);
                    
                    tvShowInfo.style.display = 'block';
                    
                    // Show host controls
                    const hostControls = document.getElementById('hostControls');
                    if (hostControls) {
                        hostControls.style.display = 'block';
                    }
                }
                const url_to_play = (currentServer === 'server1' ? SERVER1_TV_BASE : SERVER2_TV_BASE) + id + '/' + currentSeasonNumber + '/1';
                moviePlayer.src = url_to_play;
                
                if (isHost) {
                    saveToWatchHistory(id, title, posterPath, 'tv');
                }
                
                if (isHost) {
                    isSyncing = true;
                    socket.emit('movie_room_media_change', {
                        room: roomId,
                        media: {
                            id: id,
                            title: title,
                            poster_path: posterPath,
                            media_type: 'tv',
                            season: currentSeasonNumber,
                            episode: 1,
                            server: currentServer
                        }
                    });
                    setTimeout(() => { isSyncing = false; }, 1000);
                }
            } catch (error) {
                console.error('Error fetching TV show details:', error);
                alert('Error loading TV show details. Please try again.');
            }
        }
        
        function renderSeasonSelector() {
            seasonSelector.innerHTML = '';
            currentSeasons.forEach(season => {
                const seasonBtn = document.createElement('button');
                seasonBtn.className = 'season-btn' + (season.season_number === currentSeasonNumber ? ' active' : '');
                seasonBtn.textContent = 'Season ' + season.season_number;
                seasonBtn.addEventListener('click', async () => {
                    if (!isHost) {
                        alert('Only the host can change seasons.');
                        return;
                    }
                    currentSeasonNumber = season.season_number;
                    document.querySelectorAll('.season-btn').forEach(btn => btn.classList.remove('active'));
                    seasonBtn.classList.add('active');
                    await loadSeasonEpisodes(currentSeasonNumber);
                });
                seasonSelector.appendChild(seasonBtn);
            });
        }
        
        async function loadSeasonEpisodes(seasonNumber) {
            try {
                const url = TMDB_TV_SEASON_URL + '/' + currentMediaData.id + '/season/' + seasonNumber + '?api_key=' + TMDB_API_KEY + '&language=en-US';
                const response = await fetch(url);
                if (!response.ok) throw new Error('HTTP error! Status: ' + response.status);
                const data = await response.json();
                currentEpisodes = data.episodes;
                renderEpisodes();
            } catch (error) {
                console.error('Error fetching season episodes:', error);
                episodeList.innerHTML = '<div class="error-message">Error loading episodes. Please try again.</div>';
            }
        }
        
        function renderEpisodes() {
            episodeList.innerHTML = '';
            currentEpisodes.forEach(episode => {
                const episodeItem = document.createElement('div');
                episodeItem.className = 'episode-item';
                episodeItem.innerHTML = `
                    <div class="episode-title">` + episode.name + `</div>
                    <div class="episode-number">Episode ` + episode.episode_number + `</div>
                    <div class="episode-overview">` + (episode.overview || 'No description available') + `</div>
                `;
                episodeItem.addEventListener('click', () => {
                    if (isHost) {
                        playEpisode(episode.episode_number);
                    } else {
                        alert('Only the host can change episodes.');
                    }
                });
                episodeList.appendChild(episodeItem);
            });
        }
        
        function playEpisode(episodeNumber) {
            currentEpisodeNumber = episodeNumber;
            const url_to_play = (currentServer === 'server1' ? SERVER1_TV_BASE : SERVER2_TV_BASE) + currentMediaData.id + '/' + currentSeasonNumber + '/' + episodeNumber;
            moviePlayer.src = url_to_play;
            nowPlaying.textContent = 'Now Playing: ' + currentMediaData.title + ' - S' + currentSeasonNumber + 'E' + episodeNumber;
            
            if (isHost) {
                isSyncing = true;
                socket.emit('movie_room_media_change', {
                    room: roomId,
                    media: {
                        id: currentMediaData.id,
                        title: currentMediaData.title,
                        poster_path: currentMediaData.poster_path,
                        media_type: 'tv',
                        season: currentSeasonNumber,
                        episode: episodeNumber,
                        server: currentServer
                    }
                });
                setTimeout(() => { isSyncing = false; }, 1000);
            }
        }
        
        function playMedia(id, title, posterPath = null, mediaType = 'movie') {
            currentMediaData = {
                id: id,
                title: title,
                poster_path: posterPath,
                media_type: mediaType
            };
            
            const url_to_play = (currentServer === 'server1' ? SERVER1_BASE : SERVER2_BASE) + id;
            moviePlayer.src = url_to_play;
            
            nowPlaying.textContent = 'Now Playing: ' + title;
            playerContainer.style.display = 'block';
            searchResults.style.display = 'none';
            if (isHost && tvShowInfo) {
                tvShowInfo.style.display = 'none';
            }
            
            // Show host controls
            if (isHost) {
                const hostControls = document.getElementById('hostControls');
                if (hostControls) {
                    hostControls.style.display = 'block';
                }
            }
            
            if (isHost) {
                saveToWatchHistory(id, title, posterPath, mediaType);
            }
            
            if (isHost) {
                isSyncing = true;
                socket.emit('movie_room_media_change', {
                    room: roomId,
                    media: {
                        id: id,
                        title: title,
                        poster_path: posterPath,
                        media_type: mediaType,
                        server: currentServer
                    }
                });
                setTimeout(() => { isSyncing = false; }, 1000);
            }
        }
        
        function loadMediaFromSync(mediaData) {
            if (!mediaData) {
                closePlayerLocal();
                return;
            }
            
            currentMediaData = mediaData;
            currentServer = mediaData.server || 'server1';
            
            if (isHost) {
                document.getElementById('server1Btn').classList.toggle('active', currentServer === 'server1');
                document.getElementById('server2Btn').classList.toggle('active', currentServer === 'server2');
            }
            
            // Hide "Waiting for Host" message for viewers
            if (!isHost) {
                const waitingDiv = document.getElementById('waiting-for-host');
                if (waitingDiv) {
                    waitingDiv.style.display = 'none';
                }
            }
            
            if (mediaData.media_type === 'movie') {
                const url_to_play = (currentServer === 'server1' ? SERVER1_BASE : SERVER2_BASE) + mediaData.id;
                moviePlayer.src = url_to_play;
                nowPlaying.textContent = 'Now Playing: ' + mediaData.title;
                playerContainer.style.display = 'block';
                if (isHost && tvShowInfo) {
                    tvShowInfo.style.display = 'none';
                }
            } else if (mediaData.media_type === 'tv') {
                currentSeasonNumber = mediaData.season || 1;
                currentEpisodeNumber = mediaData.episode || 1;
                const url_to_play = (currentServer === 'server1' ? SERVER1_TV_BASE : SERVER2_TV_BASE) + mediaData.id + '/' + currentSeasonNumber + '/' + currentEpisodeNumber;
                moviePlayer.src = url_to_play;
                nowPlaying.textContent = 'Now Playing: ' + mediaData.title + ' - S' + currentSeasonNumber + 'E' + currentEpisodeNumber;
                playerContainer.style.display = 'block';
                
                if (isHost) {
                    tvShowInfo.style.display = 'block';
                    // Load TV show details for season/episode selection
                    playTVShow(mediaData.id, mediaData.title, mediaData.poster_path);
                }
            }
            
            // Show host controls when loading synced media
            if (isHost) {
                const hostControls = document.getElementById('hostControls');
                if (hostControls) {
                    hostControls.style.display = 'block';
                }
            }
            
            // Scroll player to top of viewport
            playerContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
        function switchToServer1() {
            if (!isHost) {
                alert('Only the host can change servers.');
                return;
            }
            if (!currentMediaData) return;
            
            currentServer = 'server1';
            document.getElementById('server1Btn').classList.add('active');
            document.getElementById('server2Btn').classList.remove('active');
            
            if (currentMediaData.media_type === 'movie') {
                moviePlayer.src = SERVER1_BASE + currentMediaData.id;
            } else {
                moviePlayer.src = SERVER1_TV_BASE + currentMediaData.id + '/' + currentSeasonNumber + '/' + currentEpisodeNumber;
            }
            
            isSyncing = true;
            socket.emit('movie_room_server_change', {
                room: roomId,
                server: 'server1'
            });
            setTimeout(() => { isSyncing = false; }, 1000);
        }
        
        function switchToServer2() {
            if (!isHost) {
                alert('Only the host can change servers.');
                return;
            }
            if (!currentMediaData) return;
            
            currentServer = 'server2';
            document.getElementById('server1Btn').classList.remove('active');
            document.getElementById('server2Btn').classList.add('active');
            
            if (currentMediaData.media_type === 'movie') {
                moviePlayer.src = SERVER2_BASE + currentMediaData.id;
            } else {
                moviePlayer.src = SERVER2_TV_BASE + currentMediaData.id + '/' + currentSeasonNumber + '/' + currentEpisodeNumber;
            }
            
            isSyncing = true;
            socket.emit('movie_room_server_change', {
                room: roomId,
                server: 'server2'
            });
            setTimeout(() => { isSyncing = false; }, 1000);
        }
        
        socket.on('server_changed', function(data) {
            if (!isSyncing && currentMediaData) {
                currentServer = data.server;
                
                if (isHost) {
                    document.getElementById('server1Btn').classList.toggle('active', currentServer === 'server1');
                    document.getElementById('server2Btn').classList.toggle('active', currentServer === 'server2');
                }
                
                if (currentMediaData.media_type === 'movie') {
                    moviePlayer.src = (currentServer === 'server1' ? SERVER1_BASE : SERVER2_BASE) + currentMediaData.id;
                } else {
                    moviePlayer.src = (currentServer === 'server1' ? SERVER1_TV_BASE : SERVER2_TV_BASE) + currentMediaData.id + '/' + currentSeasonNumber + '/' + currentEpisodeNumber;
                }
            }
        });
        
        function saveToWatchHistory(id, title, posterPath, mediaType) {
            const watchHistory = getWatchHistory();
            const filteredHistory = watchHistory.filter(item => item.id !== id);
            filteredHistory.unshift({
                id: id,
                title: title,
                poster_path: posterPath,
                media_type: mediaType,
                last_watched: new Date().toISOString()
            });
            const limitedHistory = filteredHistory.slice(0, MAX_WATCH_HISTORY);
            setWatchHistory(limitedHistory);
            loadContinueWatching();
        }
        
        function getWatchHistory() {
            const cookieValue = getCookie(COOKIE_NAME);
            if (!cookieValue) return [];
            try {
                return JSON.parse(cookieValue);
            } catch (e) {
                return [];
            }
        }
        
        function setWatchHistory(history) {
            setCookie(COOKIE_NAME, JSON.stringify(history), 365 * 10);
        }
        
        function loadContinueWatching() {
            const watchHistory = getWatchHistory();
            if (watchHistory.length === 0) {
                continueWatchingSection.style.display = 'none';
                return;
            }
            
            continueWatchingSection.style.display = 'block';
            continueWatchingGrid.innerHTML = '';
            
            watchHistory.forEach(item => {
                const card = document.createElement('div');
                card.className = 'movie-card';
                const posterUrl = item.poster_path ? TMDB_IMAGE_BASE + item.poster_path : 'https://via.placeholder.com/180x270?text=No+Image';
                const lastWatched = new Date(item.last_watched);
                const formattedDate = lastWatched.toLocaleDateString();
                
                card.innerHTML = `
                    <div class="card-poster" style="background-image: url('` + posterUrl + `')"></div>
                    <div class="card-info">
                        <div class="card-title">` + item.title + `</div>
                        <div class="card-progress">
                            <span class="card-date">Watched: ` + formattedDate + `</span>
                            ` + (item.media_type === 'tv' ? '<span class="tv-label">TV</span>' : '') + `
                        </div>
                    </div>
                `;
                
                card.addEventListener('click', function() {
                    if (isHost) {
                        if (item.media_type === 'movie') {
                            playMedia(item.id, item.title, item.poster_path, 'movie');
                        } else {
                            playTVShow(item.id, item.title, item.poster_path);
                        }
                        // Scroll to top to show player
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                    } else {
                        alert('Only the host can change the media.');
                    }
                });
                
                continueWatchingGrid.appendChild(card);
            });
        }
        
        async function fetchTrending() {
            try {
                const url = TMDB_TRENDING_URL + '?api_key=' + TMDB_API_KEY + '&language=en-US';
                trendingGrid.innerHTML = '<div class="loading-indicator"><div class="spinner"></div><p>Loading trending movies...</p></div>';
                const response = await fetch(url);
                if (!response.ok) throw new Error('HTTP error! Status: ' + response.status);
                const data = await response.json();
                displayTrendingMovies(data.results);
            } catch (error) {
                console.error('Error fetching trending movies:', error);
                trendingGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 20px;"><p>Error loading trending movies. Please refresh the page.</p></div>';
            }
        }
        
        function displayTrendingMovies(movies) {
            trendingGrid.innerHTML = '';
            const moviesToShow = movies.slice(0, 12);
            
            moviesToShow.forEach(movie => {
                const card = document.createElement('div');
                card.className = 'movie-card';
                const posterUrl = movie.poster_path ? TMDB_IMAGE_BASE + movie.poster_path : 'https://via.placeholder.com/180x270?text=No+Image';
                
                card.innerHTML = `
                    <div class="card-poster" style="background-image: url('` + posterUrl + `')"></div>
                    <div class="card-info">
                        <div class="card-title">` + movie.title + `</div>
                        <div class="card-year-rating">
                            <span>` + new Date(movie.release_date).getFullYear() + `</span>
                            <span class="card-rating"><i class="fas fa-star"></i>` + movie.vote_average.toFixed(1) + `</span>
                        </div>
                    </div>
                `;
                
                card.addEventListener('click', function() {
                    if (isHost) {
                        playMedia(movie.id, movie.title, movie.poster_path, 'movie');
                        // Scroll to top to show player
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                    } else {
                        alert('Only the host can change the media.');
                    }
                });
                
                trendingGrid.appendChild(card);
            });
        }
        
        function setupPopupBlocker() {
            const originalWindowOpen = window.open;
            window.open = function() { return null; };
            window.showModalDialog = function() { return null; };
        }
        
        function setCookie(name, value, days) {
            const expires = new Date();
            expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
            document.cookie = name + '=' + encodeURIComponent(value) + ';expires=' + expires.toUTCString() + ';path=/;SameSite=Lax';
        }
        
        function getCookie(name) {
            const nameEQ = name + '=';
            const ca = document.cookie.split(';');
            for (let i = 0; i < ca.length; i++) {
                let c = ca[i];
                while (c.charAt(0) === ' ') c = c.substring(1, c.length);
                if (c.indexOf(nameEQ) === 0) return decodeURIComponent(c.substring(nameEQ.length, c.length));
            }
            return null;
        }
        
        // Chat functions
        function toggleChat() {
            document.getElementById('chat-section').classList.toggle('show');
        }
        
        function sendMessage() {
            const messageInput = document.getElementById('messageInput');
            const message = messageInput.value.trim();
            if (message && userNickname) {
                socket.emit('chat_message', {
                    room: roomId,
                    nickname: userNickname,
                    message: message,
                    isHost: isHost
                });
                messageInput.value = '';
            }
        }
        
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
        
        function isImageUrl(url) {
            return /\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(url);
        }
        
        function isVideoUrl(url) {
            return /\.(mp4|webm|mov|avi)$/i.test(url);
        }
        
        function formatMessageContent(message) {
            // Check if message is a file URL
            if (message.startsWith('https://jerrrycans-file.hf.space/files/')) {
                if (isImageUrl(message)) {
                    return `<img src="${message}" style="max-width: 250px; max-height: 250px; border-radius: 8px; margin-top: 8px; cursor: pointer;" onclick="window.open('${message}', '_blank')">`;
                } else if (isVideoUrl(message)) {
                    return `<video src="${message}" controls style="max-width: 250px; border-radius: 8px; margin-top: 8px;"></video>`;
                }
            }
            return message;
        }
        
        function addChatMessage(nickname, message, isHostMsg = false) {
            const chatMessages = document.getElementById('chat-messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            
            const messageHeader = document.createElement('div');
            messageHeader.className = 'message-header';
            
            const nicknameSpan = document.createElement('span');
            nicknameSpan.className = 'message-nickname' + (isHostMsg ? ' host' : '');
            nicknameSpan.textContent = nickname;
            messageHeader.appendChild(nicknameSpan);
            
            if (isHostMsg) {
                const hostBadge = document.createElement('span');
                hostBadge.className = 'message-badge';
                hostBadge.textContent = 'HOST';
                messageHeader.appendChild(hostBadge);
            }
            
            const messageText = document.createElement('div');
            messageText.className = 'message-text';
            messageText.innerHTML = formatMessageContent(message);
            
            messageDiv.appendChild(messageHeader);
            messageDiv.appendChild(messageText);
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const uploadStatus = document.getElementById('uploadStatus');
            uploadStatus.style.display = 'block';
            uploadStatus.textContent = 'Uploading...';
            
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const response = await fetch('https://jerrrycans-file.hf.space/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const data = await response.json();
                    const fileUrl = 'https://jerrrycans-file.hf.space' + data.url;
                    
                    // Send the file URL as a message
                    socket.emit('chat_message', {
                        room: roomId,
                        nickname: userNickname,
                        message: fileUrl,
                        isHost: isHost
                    });
                    
                    uploadStatus.textContent = '✓ Upload complete!';
                    setTimeout(() => {
                        uploadStatus.style.display = 'none';
                    }, 2000);
                } else {
                    uploadStatus.textContent = '✗ Upload failed';
                    setTimeout(() => {
                        uploadStatus.style.display = 'none';
                    }, 3000);
                }
            } catch (error) {
                console.error('Upload error:', error);
                uploadStatus.textContent = '✗ Upload failed';
                setTimeout(() => {
                    uploadStatus.style.display = 'none';
                }, 3000);
            }
            
            // Clear the input
            input.value = '';
        }
        
        function updateUserList(users) {
            const userListDiv = document.getElementById('user-list');
            userListDiv.innerHTML = '';
            
            Object.keys(users).forEach(function(userId) {
                const user = users[userId];
                const userChip = document.createElement('div');
                userChip.className = 'user-chip' + (user.isHost ? ' host' : '');
                userChip.innerHTML = '<span class="user-icon">👤</span>' + user.nickname;
                userListDiv.appendChild(userChip);
            });
        }
        
        function updateViewerCount(count) {
            document.getElementById('viewer-count').textContent = count;
        }
        
        function copyRoomLink() {
            const roomLink = window.location.origin + '/join/' + roomId;
            navigator.clipboard.writeText(roomLink).then(function() {
                const btn = document.querySelector('.copy-link-btn');
                const originalText = btn.textContent;
                btn.textContent = '✓ Copied!';
                btn.style.background = '#18181b';
                btn.style.color = '#22c55e';
                setTimeout(function() {
                    btn.textContent = originalText;
                    btn.style.background = '';
                    btn.style.color = '';
                }, 2000);
            }).catch(function(err) {
                alert('Failed to copy link. Please copy manually: ' + roomLink);
            });
        }
        
        function deleteRoom() {
            if (confirm('Are you sure you want to delete this room? All users will be disconnected.')) {
                fetch('/delete_room', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        room_id: roomId
                    })
                }).then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Room deleted successfully');
                        window.location.href = '/';
                    } else {
                        alert('Error deleting room: ' + data.error);
                    }
                });
            }
        }
    </script>
</body>
</html>
"""

def get_current_time(room_data):
    """Calculate the actual current video time accounting for playback"""
    if not room_data['playing']:
        return room_data['current_time']
    
    # If playing, add the elapsed time since last update
    elapsed = time.time() - room_data['last_update']
    return room_data['current_time'] + elapsed

def create_vm(app_to_launch=None, timeout=3600, width=1920, height=1080, dpi=120):
    """Create a VM with e2b Desktop Sandbox"""
    try:
        # Calculate optimal resolution based on user's screen size
        # Use provided resolution or calculate based on screen size for better quality
        vm_width = min(width, 2560)  # Cap at 2560 for performance
        vm_height = min(height, 1440)  # Cap at 1440 for performance

        # Ensure minimum resolution for usability
        vm_width = max(vm_width, 1280)
        vm_height = max(vm_height, 720)

        # Create a new desktop sandbox with resolution settings and timeout
        desktop = Sandbox.create(
            timeout=timeout,  # Use the timeout parameter
            resolution=(vm_width, vm_height),  # Use calculated resolution
            dpi=dpi  # Set DPI for better scaling
        )
        
        if app_to_launch:
            # Launch the application
            desktop.launch(app_to_launch)
            # Wait for the application to open
            desktop.wait(5000)  # Wait 5 seconds
        
        # Start the stream with authentication
        desktop.stream.start(require_auth=True)
        
        # Get the stream auth key
        auth_key = desktop.stream.get_auth_key()
        
        # Get the stream URL
        stream_url = desktop.stream.get_url(auth_key=auth_key)
        
        return {
            'success': True,
            'sandbox_id': desktop.sandbox_id,
            'stream_url': stream_url,
            'auth_key': auth_key
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def index():
    if request.method == 'POST':
        room_type = request.form.get('room_type', 'cinema')
        password = request.form.get('password', '').strip()
        
        # Validate room type
        if room_type not in ['cinema', 'movie_room', 'sports', 'vm']:
            return render_template_string(LOGIN_HTML, error='Invalid room type')
        
        # Sanitize and validate password
        if password:
            password = sanitize_message(password)
            if len(password) > 50:
                return render_template_string(LOGIN_HTML, error='Password too long (max 50 characters)')
        
        room_id = str(uuid.uuid4())[:6]
        
        if room_type == 'cinema':
            nickname = sanitize_nickname(request.form.get('nickname', '').strip())
            if not nickname:
                return render_template_string(LOGIN_HTML, error='Nickname is required')
            
            if len(nickname) < 2:
                return render_template_string(LOGIN_HTML, error='Nickname must be at least 2 characters')
            
            # Get all video URLs from form (supports multiple)
            video_urls = request.form.getlist('video_url')
            
            # Filter and validate video URLs
            validated_urls = []
            for video_url in video_urls:
                video_url = video_url.strip()
                if not video_url:
                    continue
                
                # Validate URL format
                if not re.match(r'^https?://', video_url):
                    return render_template_string(LOGIN_HTML, error=f'Invalid video URL: {video_url[:50]}...')
                
                # Limit URL length
                if len(video_url) > 2000:
                    return render_template_string(LOGIN_HTML, error='Video URL too long')
                
                validated_urls.append(video_url)
            
            # Ensure at least one video URL
            if not validated_urls:
                return render_template_string(LOGIN_HTML, error='At least one video URL is required')
            
            # Generate session ID for host
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
            session['is_host'] = True
            session['room_id'] = room_id
            session['host_nickname'] = nickname
            
            # Generate CSRF token
            generate_csrf_token()
            
            rooms[room_id] = {
                'type': 'cinema',
                'password': password if password else None,
                'video_queue': validated_urls,  # List of video URLs
                'current_video_index': 0,  # Current video in queue
                'playing': False,
                'current_time': 0,
                'last_update': time.time(),
                'messages': [],
                'users': {},
                'host_nickname': nickname,
                'host_session_id': session_id
            }
        elif room_type == 'sports':
            nickname = sanitize_nickname(request.form.get('nickname', '').strip())
            if not nickname:
                return render_template_string(LOGIN_HTML, error='Nickname is required')
            
            if len(nickname) < 2:
                return render_template_string(LOGIN_HTML, error='Nickname must be at least 2 characters')
            
            # Generate session ID for host
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
            session['is_host'] = True
            session['room_id'] = room_id
            session['host_nickname'] = nickname
            
            # Generate CSRF token
            generate_csrf_token()
            
            rooms[room_id] = {
                'type': 'sports',
                'password': password if password else None,
                'current_match': None,
                'current_source': None,
                'current_stream_url': None,
                'messages': [],
                'users': {},
                'host_nickname': nickname,
                'host_session_id': session_id
            }
        elif room_type == 'movie_room':
            nickname = sanitize_nickname(request.form.get('nickname', '').strip())
            if not nickname:
                return render_template_string(LOGIN_HTML, error='Nickname is required')
            
            if len(nickname) < 2:
                return render_template_string(LOGIN_HTML, error='Nickname must be at least 2 characters')
            
            # Generate session ID for host
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
            session['is_host'] = True
            session['room_id'] = room_id
            session['host_nickname'] = nickname
            
            # Generate CSRF token
            generate_csrf_token()
            
            rooms[room_id] = {
                'type': 'movie_room',
                'password': password if password else None,
                'current_media': None,  # Will store {id, title, media_type, season, episode}
                'current_server': 'server1',  # Default to server1
                'playing': False,
                'current_time': 0,
                'last_update': time.time(),
                'messages': [],
                'users': {},
                'host_nickname': nickname,
                'host_session_id': session_id
            }
        else:  # VM room
            nickname = sanitize_nickname(request.form.get('nickname', '').strip())
            if not nickname:
                return render_template_string(LOGIN_HTML, error='Nickname is required for VM rooms')
            
            if len(nickname) < 2:
                return render_template_string(LOGIN_HTML, error='Nickname must be at least 2 characters')
            
            application = sanitize_message(request.form.get('application', ''))
            
            try:
                timeout = int(request.form.get('timeout', 3600))
                timeout = max(60, min(timeout, 7200))  # Increased max timeout to 2 hours
            except (ValueError, TypeError):
                timeout = 3600

            # Get screen size parameters with validation
            try:
                screen_width = int(request.form.get('screen_width', 1920))
                screen_width = max(800, min(screen_width, 3840))  # Limit to reasonable range
            except (ValueError, TypeError):
                screen_width = 1920
            
            try:
                screen_height = int(request.form.get('screen_height', 1080))
                screen_height = max(600, min(screen_height, 2160))  # Limit to reasonable range
            except (ValueError, TypeError):
                screen_height = 1080
            
            try:
                dpi = int(request.form.get('dpi', 120))
                dpi = max(72, min(dpi, 240))  # Limit to reasonable range
            except (ValueError, TypeError):
                dpi = 120

            # Create VM in background
            vm_result = create_vm(application if application else None, timeout, screen_width, screen_height, dpi)
            
            if not vm_result['success']:
                return render_template_string(LOGIN_HTML, error=f'Failed to create VM: {vm_result["error"]}')
            
            # Generate session ID for host
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
            session['is_host'] = True
            session['room_id'] = room_id
            session['host_nickname'] = nickname
            
            # Generate CSRF token
            generate_csrf_token()
            
            rooms[room_id] = {
                'type': 'vm',
                'password': password if password else None,
                'vm_url': vm_result['stream_url'],
                'vm_sandbox_id': vm_result['sandbox_id'],
                'vm_app': application,
                'messages': [],
                'users': {},
                'controller': None,  # Socket ID of user with control
                'host_socket_id': None,  # Will be set when host joins
                'host_nickname': nickname,  # Store host nickname
                'host_session_id': session_id
            }
        
        share_url = request.url_root + 'join/' + room_id
        watch_url = request.url_root + 'watch/' + room_id
        
        return render_template_string(SHARE_HTML, 
                                    room_id=room_id,
                                    share_url=share_url,
                                    watch_url=watch_url,
                                    has_password=bool(password),
                                    room_type=room_type.upper(),
                                    vm_app=rooms[room_id].get('vm_app'))
    
    return render_template_string(LOGIN_HTML)

@app.route('/join/<room_id>', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def join_room_route(room_id):
    # Validate room_id format
    if not re.match(r'^[a-f0-9\-]{6}$', room_id):
        return "Invalid room ID", 400
    
    with rooms_lock:
        if room_id not in rooms:
            return "Room not found", 404
        
        room = rooms[room_id]
    
    needs_password = room['password'] is not None
    
    if request.method == 'POST':
        nickname = sanitize_nickname(request.form.get('nickname', '').strip())
        if not nickname:
            return render_template_string(JOIN_HTML, 
                                         room_id=room_id,
                                         room_type=room['type'].title(),
                                         needs_password=needs_password,
                                         error='Nickname is required')
        
        if len(nickname) < 2:
            return render_template_string(JOIN_HTML, 
                                         room_id=room_id,
                                         room_type=room['type'].title(),
                                         needs_password=needs_password,
                                         error='Nickname must be at least 2 characters')
        
        # Check for duplicate nicknames in the room
        with rooms_lock:
            for user_id, user_data in room['users'].items():
                if user_data.get('nickname', '').lower() == nickname.lower():
                    return render_template_string(JOIN_HTML, 
                                                 room_id=room_id,
                                                 room_type=room['type'].title(),
                                                 needs_password=needs_password,
                                                 error='This nickname is already taken in this room')
        
        if needs_password:
            password = request.form.get('password', '')
            if password != room['password']:
                # Add delay to prevent brute force attacks
                time.sleep(1)
                return render_template_string(JOIN_HTML, 
                                             room_id=room_id,
                                             room_type=room['type'].title(),
                                             needs_password=needs_password,
                                             error='Wrong password')
        
        # Generate session ID for user
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
        session['room_id'] = room_id
        session['is_host'] = False
        session['user_nickname'] = nickname
        
        # Generate CSRF token
        generate_csrf_token()
        
        return redirect(url_for('watch_room', room_id=room_id))
    
    return render_template_string(JOIN_HTML, 
                                 room_id=room_id,
                                 room_type=room['type'].title(),
                                 needs_password=needs_password)

@app.route('/watch/<room_id>')
@limiter.limit("30 per minute")
def watch_room(room_id):
    # Validate room_id format
    if not re.match(r'^[a-f0-9\-]{6}$', room_id):
        return "Invalid room ID", 400
    
    # Validate session
    if room_id not in rooms or session.get('room_id') != room_id:
        return redirect(url_for('join_room_route', room_id=room_id))
    
    with rooms_lock:
        room = rooms[room_id]
        room_type = room['type']
        room_data = dict(room)  # Create a copy
    
    is_host = session.get('is_host', False)
    
    # Check if user has control (initially only host has control for VM rooms)
    has_control = False
    if room_type == 'vm':
        if is_host:
            has_control = True
        # Will be updated via websocket
    
    template_vars = {
        'room_id': room_id,
        'room_type': room_type,
        'is_host': is_host,
        'has_control': has_control
    }
    
    if room_type == 'cinema':
        # Get current video from queue
        current_index = room_data.get('current_video_index', 0)
        video_queue = room_data.get('video_queue', [])
        template_vars['video_url'] = video_queue[current_index] if video_queue else ''
        template_vars['video_queue'] = video_queue
        template_vars['current_video_index'] = current_index
        return render_template_string(WATCH_HTML, **template_vars)
    elif room_type == 'movie_room':
        return render_template_string(MOVIE_ROOM_HTML, **template_vars)
    elif room_type == 'sports':
        template_vars['current_match'] = room_data.get('current_match')
        template_vars['current_source'] = room_data.get('current_source')
        template_vars['current_stream_url'] = room_data.get('current_stream_url')
        return render_template_string(WATCH_HTML, **template_vars)
    else:
        template_vars['vm_url'] = room_data['vm_url']
        return render_template_string(WATCH_HTML, **template_vars)

@app.route('/vm-url/<room_id>')
@limiter.limit("30 per minute")
def get_vm_url(room_id):
    # Validate room_id format
    if not re.match(r'^[a-f0-9\-]{6}$', room_id):
        return {'error': 'Invalid room ID'}, 400
    
    # Verify user has access to this room
    if session.get('room_id') != room_id:
        return {'error': 'Unauthorized'}, 403
    
    with rooms_lock:
        if room_id not in rooms:
            return {'error': 'Room not found'}, 404
        
        room = rooms[room_id]
        if room['type'] != 'vm':
            return {'error': 'Not a VM room'}, 400
        
        vm_url = room['vm_url']
    
    # Add timestamp to make URL harder to cache/reuse
    timestamp = int(time.time())
    
    return {
        'url': vm_url,
        'timestamp': timestamp,
        'room_id': room_id
    }

@socketio.on('join')
def on_join(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate room_id format
    if not room_id or not re.match(r'^[a-f0-9\-]{6}$', room_id):
        emit('error', {'message': 'Invalid room ID'})
        return
    
    # Validate session
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid:
        emit('error', {'message': 'Invalid session. Please rejoin the room.'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            emit('error', {'message': 'Room not found'})
            return
        
        room = rooms[room_id]
        
        # Get validated user info from session
        is_host = user_info['is_host']
        user_nickname = user_info['nickname']
        
        if room['type'] == 'vm' and is_host:
            room['host_socket_id'] = socket_id
            if room['controller'] is None:
                room['controller'] = socket_id
        
        # Store user with validated info
        room['users'][socket_id] = {
            'nickname': user_nickname,
            'isHost': is_host,
            'hasControl': room.get('controller') == socket_id
        }
    
    join_room(room_id)
    emit('joined')
    
    # Send room-specific data
    with rooms_lock:
        if room['type'] == 'cinema':
            current_time = get_current_time(room)
            emit('sync_state', {
                'playing': room['playing'],
                'time': current_time
            })
            # Send queue info
            emit('queue_updated', {
                'queue': room.get('video_queue', []),
                'current_index': room.get('current_video_index', 0)
            })
        elif room['type'] == 'movie_room':
            # Send current media state to the newly joined user
            if room.get('current_media'):
                emit('media_changed', room['current_media'])
        
        # Send chat history
        emit('chat_history', room['messages'])
        
        # Send user list to all in room
        emit('user_list', room['users'], room=room_id)
    
    print(f"User {user_nickname} joined room: {room_id}, type: {room['type']}")

@socketio.on('disconnect')
def on_disconnect():
    # Remove user from all rooms
    for room_id, room in rooms.items():
        socket_id = request.sid
        if socket_id in room['users']:
            nickname = room['users'][socket_id].get('nickname')
            del room['users'][socket_id]
            
            # If controller disconnected, give control back to host
            if room.get('type') == 'vm' and room.get('controller') == socket_id:
                if room['host_socket_id'] and room['host_socket_id'] in room['users']:
                    room['controller'] = room['host_socket_id']
                    emit('control_changed', {
                        'userId': room['host_socket_id'],
                        'nickname': 'Host'
                    }, room=room_id)
            
            # Update user list
            emit('user_list', room['users'], room=room_id)
            
            if nickname:
                emit('user_left_chat', {'nickname': nickname}, room=room_id)

@socketio.on('grant_control')
def on_grant_control(data):
    socket_id = request.sid
    room_id = data.get('room')
    target_user_id = data.get('userId')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can grant control'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        
        # Only VM rooms have control
        if room['type'] != 'vm':
            return
        
        # Verify target user exists in room
        if target_user_id not in room['users']:
            emit('error', {'message': 'Target user not found in room'})
            return
        
        # Update control
        room['controller'] = target_user_id
        
        # Update user hasControl status
        for uid, user in room['users'].items():
            user['hasControl'] = (uid == target_user_id)
        
        # Get target nickname
        target_nickname = room['users'].get(target_user_id, {}).get('nickname', 'Unknown')
    
    # Notify all users
    emit('control_changed', {
        'userId': target_user_id,
        'nickname': target_nickname
    }, room=room_id)

@socketio.on('remove_all_control')
def on_remove_all_control(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can revoke control'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        
        # Only VM rooms have control
        if room['type'] != 'vm':
            return
        
        # Remove control from everyone (including host)
        room['controller'] = None
        
        # Update user hasControl status - no one has control
        for uid, user in room['users'].items():
            user['hasControl'] = False
    
    # Notify all users
    emit('control_changed', {
        'userId': None,
        'nickname': 'None'
    }, room=room_id)

@socketio.on('user_joined_chat')
def on_user_joined_chat(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid:
        emit('error', {'message': 'Invalid session'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        
        # Verify the socket is in the room's user list
        if socket_id not in room['users']:
            return
        
        # Get nickname from stored user data (NOT from client!)
        nickname = room['users'][socket_id].get('nickname', 'Unknown')
        
        # Verify nickname matches session
        if nickname != user_info['nickname']:
            emit('error', {'message': 'Nickname mismatch'})
            return
        
        # Add system message
        system_message = {
            'type': 'system',
            'message': f'{nickname} joined the chat',
            'timestamp': time.time()
        }
        room['messages'].append(system_message)
    
    # Notify all users in room
    emit('user_joined_chat', {'nickname': nickname}, room=room_id)
    
    # Send updated user list
    with rooms_lock:
        emit('user_list', room['users'], room=room_id)

@socketio.on('chat_message')
def on_chat_message(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check - messages
    if not check_socket_rate_limit(socket_id, 'messages'):
        emit('error', {'message': 'You are sending messages too fast. Please slow down.'})
        return
    
    # Validate session
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid:
        emit('error', {'message': 'Invalid session'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        
        # Verify the socket is in the room's user list
        if socket_id not in room['users']:
            emit('error', {'message': 'You are not in this room'})
            return
        
        # Get user info from room data (NOT from client!)
        user = room['users'][socket_id]
        nickname = user.get('nickname', 'Unknown')
        is_host = user.get('isHost', False)
        has_control = user.get('hasControl', False)
    
    # Sanitize message
    message = sanitize_message(data.get('message', ''))
    
    if not message:
        return
    
    # Verify nickname matches session (prevent spoofing)
    if nickname != user_info['nickname']:
        emit('error', {'message': 'Nickname mismatch'})
        return
    
    # Store message
    message_data = {
        'type': 'message',
        'data': {
            'nickname': nickname,
            'message': message,
            'isHost': is_host,
            'hasControl': has_control,
            'timestamp': time.time()
        }
    }
    
    with rooms_lock:
        room['messages'].append(message_data)
        
        # Keep only last 100 messages
        if len(room['messages']) > 100:
            room['messages'] = room['messages'][-100:]
    
    # Broadcast to all users in room
    emit('chat_message', message_data['data'], room=room_id)

# Cinema room specific events
@socketio.on('play_command')
def on_play_command(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can control playback'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        # Validate time value
        try:
            play_time = float(data.get('time', 0))
            play_time = max(0, play_time)  # Ensure non-negative
        except (ValueError, TypeError):
            return
        
        room['playing'] = True
        room['current_time'] = play_time
        room['last_update'] = time.time()
    
    emit('play_signal', {'time': play_time}, room=room_id, include_self=False)

@socketio.on('pause_command')
def on_pause_command(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can control playback'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        # Validate time value
        try:
            pause_time = float(data.get('time', 0))
            pause_time = max(0, pause_time)  # Ensure non-negative
        except (ValueError, TypeError):
            return
        
        room['playing'] = False
        room['current_time'] = pause_time
        room['last_update'] = time.time()
    
    emit('pause_signal', {'time': pause_time}, room=room_id, include_self=False)

@socketio.on('seek_command')
def on_seek_command(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can control playback'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        # Validate time value
        try:
            seek_time = float(data.get('time', 0))
            seek_time = max(0, seek_time)  # Ensure non-negative
        except (ValueError, TypeError):
            return
        
        room['current_time'] = seek_time
        room['last_update'] = time.time()
    
    emit('seek_signal', {'time': seek_time}, room=room_id, include_self=False)

@socketio.on('time_update')
def on_time_update(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        # Validate values
        try:
            current_time = float(data.get('time', 0))
            current_time = max(0, current_time)  # Ensure non-negative
            playing = bool(data.get('playing', False))
        except (ValueError, TypeError):
            return
        
        room['current_time'] = current_time
        room['playing'] = playing
        room['last_update'] = time.time()

@socketio.on('request_sync')
def on_request_sync(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        return
    
    # Validate session
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid:
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
    if room['type'] != 'cinema':
        return
    
    current_time = get_current_time(room)
    emit('sync_state', {
        'playing': room['playing'],
        'time': current_time
    })

@socketio.on('add_to_queue')
def on_add_to_queue(data):
    socket_id = request.sid
    room_id = data.get('room')
    video_url = data.get('url', '').strip()
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can add videos to queue'})
        return
    
    # Validate URL
    if not video_url:
        emit('error', {'message': 'Video URL is required'})
        return
    
    if not re.match(r'^https?://', video_url):
        emit('error', {'message': 'Invalid video URL'})
        return
    
    if len(video_url) > 2000:
        emit('error', {'message': 'Video URL too long'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        # Add video to queue
        room['video_queue'].append(video_url)
        
        queue_data = {
            'queue': room['video_queue'],
            'current_index': room['current_video_index']
        }
    
    # Notify all users about queue update
    emit('queue_updated', queue_data, room=room_id)
    emit('success', {'message': 'Video added to queue'})

@socketio.on('next_video')
def on_next_video(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can skip videos'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        video_queue = room['video_queue']
        current_index = room['current_video_index']
        
        # Check if there's a next video
        if current_index + 1 < len(video_queue):
            room['current_video_index'] = current_index + 1
            room['current_time'] = 0
            room['playing'] = False
            room['last_update'] = time.time()
            
            next_video_data = {
                'url': video_queue[room['current_video_index']],
                'index': room['current_video_index'],
                'queue': video_queue
            }
            
            # Notify all users to load next video
            emit('load_next_video', next_video_data, room=room_id)
        else:
            emit('info', {'message': 'Queue finished - All videos played'})

@socketio.on('previous_video')
def on_previous_video(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can change videos'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        video_queue = room['video_queue']
        current_index = room['current_video_index']
        
        # Check if there's a previous video
        if current_index > 0:
            room['current_video_index'] = current_index - 1
            room['current_time'] = 0
            room['playing'] = False
            room['last_update'] = time.time()
            
            prev_video_data = {
                'url': video_queue[room['current_video_index']],
                'index': room['current_video_index'],
                'queue': video_queue
            }
            
            # Notify all users to load previous video
            emit('load_next_video', prev_video_data, room=room_id)
        else:
            emit('error', {'message': 'Already at first video'})

@socketio.on('remove_from_queue')
def on_remove_from_queue(data):
    socket_id = request.sid
    room_id = data.get('room')
    index = data.get('index')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can remove videos'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'cinema':
            return
        
        video_queue = room['video_queue']
        current_index = room['current_video_index']
        
        # Validate index
        if not isinstance(index, int) or index < 0 or index >= len(video_queue):
            emit('error', {'message': 'Invalid video index'})
            return
        
        # Don't allow removing the currently playing video
        if index == current_index:
            emit('error', {'message': 'Cannot remove currently playing video'})
            return
        
        # Remove video from queue
        video_queue.pop(index)
        
        # Adjust current index if needed
        if index < current_index:
            room['current_video_index'] = current_index - 1
        
        queue_data = {
            'queue': video_queue,
            'current_index': room['current_video_index']
        }
    
    # Notify all users about queue update
    emit('queue_updated', queue_data, room=room_id)
    emit('success', {'message': 'Video removed from queue'})

# Sports room specific events
@socketio.on('match_selected')
def on_match_selected(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can select matches'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'sports':
            return
        
        # Sanitize and validate data
        match_data = sanitize_message(str(data.get('match', '')))
        source_data = sanitize_message(str(data.get('source', '')))
        stream_url = data.get('streamUrl', '')
        
        # Validate URL if provided
        if stream_url and not re.match(r'^https?://', stream_url):
            emit('error', {'message': 'Invalid stream URL'})
            return
        
        if len(stream_url) > 2000:
            emit('error', {'message': 'Stream URL too long'})
            return
        
        # Update room state
        room['current_match'] = match_data
        room['current_source'] = source_data
        room['current_stream_url'] = stream_url
    
    # Broadcast to all viewers
    emit('match_selected', {
        'match': match_data,
        'source': source_data,
        'streamUrl': stream_url
    }, room=room_id, include_self=False)

@socketio.on('source_changed')
def on_source_changed(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can change sources'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'sports':
            return
        
        # Sanitize and validate data
        source_data = sanitize_message(str(data.get('source', '')))
        stream_url = data.get('streamUrl', '')
        
        # Validate URL if provided
        if stream_url and not re.match(r'^https?://', stream_url):
            emit('error', {'message': 'Invalid stream URL'})
            return
        
        if len(stream_url) > 2000:
            emit('error', {'message': 'Stream URL too long'})
            return
        
        # Update room state
        room['current_source'] = source_data
        room['current_stream_url'] = stream_url
    
    # Broadcast to all viewers
    emit('source_changed', {
        'source': source_data,
        'streamUrl': stream_url
    }, room=room_id, include_self=False)

@socketio.on('stream_closed')
def on_stream_closed(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can close streams'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'sports':
            return
        
        # Clear room state
        room['current_match'] = None
        room['current_source'] = None
        room['current_stream_url'] = None
    
    # Broadcast to all viewers
    emit('stream_closed', {}, room=room_id, include_self=False)

@socketio.on('movie_room_media_change')
def on_movie_room_media_change(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can change media'})
        return
    
    media = data.get('media')
    if not media:
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'movie_room':
            return
        
        # Update room state
        room['current_media'] = media
        room['current_server'] = media.get('server', 'server1')
    
    # Broadcast to all users in the room
    emit('media_changed', media, room=room_id, include_self=False)

@socketio.on('movie_room_server_change')
def on_movie_room_server_change(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can change servers'})
        return
    
    server = data.get('server')
    if not server or server not in ['server1', 'server2']:
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'movie_room':
            return
        
        # Update room state
        room['current_server'] = server
        if room['current_media']:
            room['current_media']['server'] = server
    
    # Broadcast to all users in the room
    emit('server_changed', {'server': server}, room=room_id, include_self=False)

@socketio.on('player_event')
def on_player_event(data):
    # DISABLED: Automatic sync removed - now using manual sync button only
    # This was causing viewers to constantly reload
    pass

@socketio.on('host_control')
def on_host_control(data):
    room_id = data.get('room')
    timestamp = data.get('timestamp')
    action = data.get('action', 'sync')
    
    # Validate host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can control viewers'})
        return
    
    with rooms_lock:
        if room_id not in rooms or rooms[room_id]['type'] != 'movie_room':
            return
    
    # Broadcast control command to all viewers (play, pause, sync, jump)
    emit('host_control_sync', {
        'timestamp': timestamp,
        'action': action
    }, room=room_id, include_self=False)

@socketio.on('movie_room_close_player')
def on_movie_room_close_player(data):
    socket_id = request.sid
    room_id = data.get('room')
    
    # Rate limit check
    if not check_socket_rate_limit(socket_id, 'actions'):
        emit('error', {'message': 'Too many requests. Please slow down.'})
        return
    
    # Validate session and host permission
    is_valid, user_info = validate_session_for_room(room_id)
    if not is_valid or not user_info['is_host']:
        emit('error', {'message': 'Only the host can close the player'})
        return
    
    with rooms_lock:
        if room_id not in rooms:
            return
        
        room = rooms[room_id]
        if room['type'] != 'movie_room':
            return
        
        # Clear current media
        room['current_media'] = None
    
    # Broadcast to all users in the room
    emit('player_closed', {}, room=room_id, include_self=False)

@app.route('/delete_room', methods=['POST'])
@limiter.limit("5 per minute")
def delete_room():
    """Delete a room and clean up all associated data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid request'}), 400
        
        room_id = data.get('room_id')
        
        # Validate room_id format
        if not room_id or not re.match(r'^[a-f0-9\-]{6}$', room_id):
            return jsonify({'success': False, 'error': 'Invalid room ID'}), 400
        
        with rooms_lock:
            if room_id not in rooms:
                return jsonify({'success': False, 'error': 'Room not found'}), 404
            
            room = rooms[room_id]
            
            # Check if user is the host
            session_id = session.get('session_id')
            host_session_id = room.get('host_session_id')
            
            if not session_id or host_session_id != session_id:
                return jsonify({'success': False, 'error': 'Only the host can delete the room'}), 403
            
            # Clean up E2B sandbox if it exists
            if room.get('sandbox_id'):
                try:
                    # Note: In a real implementation, you'd want to properly kill the sandbox
                    # For now, we'll just remove the reference
                    pass
                except Exception as e:
                    print(f"Error cleaning up sandbox: {e}")
            
            # Notify all users in the room that it's being deleted (BEFORE deleting the room)
            socketio.emit('room_deleted', {'message': 'Room has been deleted by the host'}, to=room_id)
            
            # Remove the room from the rooms dictionary
            del rooms[room_id]
        
        # Clear session data
        session.pop('room_id', None)
        session.pop('is_host', None)
        session.pop('host_nickname', None)
        session.pop('user_nickname', None)
        
        return jsonify({'success': True, 'message': 'Room deleted successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=7860, allow_unsafe_werkzeug=True)
