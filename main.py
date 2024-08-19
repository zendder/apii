from flask import Flask, jsonify, send_file, render_template_string, redirect, request
from PIL import Image
import io
import requests
import os
import subprocess

# Install Pillow if not already installed
try:
    import PIL
except ImportError:
    subprocess.check_call(["pip", "install", "Pillow"])

app = Flask(__name__)

ROBLOX_THUMBNAIL_API = "https://thumbnails.roblox.com/v1/assets"
ROBLOX_USERS_API = "https://users.roblox.com/v1/users"
ROBLOX_INVENTORY_API = "https://inventory.roblox.com/v2/users"
RETRY_DELAY = 1
TIMEOUT = 10

# Store the received data
flury_data = []
flury_data_v2 = []

@app.route('/')
def home():
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>RBXG APIS</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                    text-align: center;
                }
                h2 {
                    color: #666;
                    margin-top: 30px;
                }
                p {
                    color: #777;
                    line-height: 1.6;
                }
                code {
                    background-color: #eee;
                    padding: 2px 4px;
                    border-radius: 4px;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                    background-color: #fff;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>RBXG APIs</h1>
                <h2>Asset Thumbnail API</h2>
                <p>Endpoint: <code>/asset/&lt;asset_id&gt;</code></p>
                <p>Description: gets the thumbnail image for a Roblox asset.</p>
                <p>Example: https://rbxgleaks.pythonanywhere.com/asset/17495495308.</p>
                <p>Parameters:</p>
                <ul>
                    <li><code>asset_id</code> (required): The ID of the Roblox asset.</li>
                </ul>
                <h2>Asset Thumbnail API (v2)</h2>
                <p>Endpoint: <code>/asset/v2/&lt;asset_id&gt;</code></p>
                <p>Description: Redirects to the thumbnail image URL.</p>
                <p>Example: https://rbxgleaks.pythonanywhere.com/asset/v2/17495495308</p>
                <p>Parameters:</p>
                <ul>
                    <li><code>asset_id</code> (required): The ID of the Roblox asset.</li>
                </ul>
                <h2>Users API</h2>
                <p>Endpoint: <code>/users/&lt;user_ids&gt;</code></p>
                <p>Description: Shows user info separated with commas.</p>
                <p>Example: https://rbxgleaks.pythonanywhere.com/users/1,2</p>
                <p>Parameters:</p>
                <ul>
                    <li><code>user_ids</code> (required): A comma-separated list of Roblox user IDs.</li>
                </ul>
                <h2>Inventory API</h2>
                <p>Endpoint: <code>/inventory/&lt;user_id&gt;</code></p>
                <p>Description: gets the inventory of a Roblox user(latest on top).</p>
                <p>Example: https://rbxgleaks.pythonanywhere.com/inventory/2966707071</p>
                <p>Parameters:</p>
                <ul>
                    <li><code>user_id</code> (required): The ID of the Roblox user.</li>
                </ul>
            </div>
        </body>
        </html>
    ''')

@app.route('/asset/<int:asset_id>')
def get_asset(asset_id):
    try:
        params = {
            'assetIds': asset_id,
            'size': '420x420',
            'format': 'Png'
        }
        response = requests.get(ROBLOX_THUMBNAIL_API, params=params, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()

        if data.get('data') and data['data'][0].get('imageUrl'):
            image_url = data['data'][0]['imageUrl']

            # Download the image
            image_data = requests.get(image_url).content
            image = Image.open(io.BytesIO(image_data))

            # Resize the image to the maximum size while maintaining the aspect ratio
            max_size = (420, 420)
            image.thumbnail(max_size, Image.LANCZOS)

            # Create a new image with a transparent background
            background = Image.new('RGBA', max_size, (0, 0, 0, 0))

            # Paste the resized image onto the transparent background
            background.paste(image, ((max_size[0] - image.size[0]) // 2, (max_size[1] - image.size[1]) // 2))

            # Convert the image to PNG
            byte_arr = io.BytesIO()
            background.save(byte_arr, format='PNG')
            byte_arr.seek(0)

            # Serve the image
            return send_file(byte_arr, mimetype='image/png')
        else:
            return render_template_string('<h1>No image found</h1>')
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/asset/v2/<int:asset_id>')
def get_asset_v2(asset_id):
    try:
        params = {
            'assetIds': asset_id,
            'size': '420x420',
            'format': 'Png'
        }
        response = requests.get(ROBLOX_THUMBNAIL_API, params=params, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()

        if data.get('data') and data['data'][0].get('imageUrl'):
            image_url = data['data'][0]['imageUrl']
            return redirect(image_url)
        else:
            return redirect(f"https://www.roblox.com/catalog/{asset_id}")
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/users/<user_ids>')
def get_users(user_ids):
    try:
        user_id_list = user_ids.split(',')
        user_data = []

        for user_id in user_id_list:
            response = requests.get(f"{ROBLOX_USERS_API}/{user_id}", timeout=TIMEOUT)
            if response.status_code == 200:
                user_info = response.json()
                user_data.append(user_info)
            else:
                user_data.append(None)

        # Return user information as JSON response
        return jsonify(user_data)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/flury', methods=['POST', 'GET', 'DELETE'])
def handle_flury():
    try:
        if request.method == 'POST':
            data = request.get_json()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        flury_data.append(item)
            elif isinstance(data, dict):
                flury_data.append(data)
            return jsonify({'message': 'corrects'})
        elif request.method == 'GET':
            return jsonify(flury_data)
        elif request.method == 'DELETE':
            data = request.get_json()
            if isinstance(data, list):
                for entry in data:
                    flury_data[:] = [item for item in flury_data if not all(item.get(k) == v for k, v in entry.items())]
                return jsonify({'message': 'ok'})
            else:
                return jsonify({'message': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/v2/flury', methods=['POST', 'GET', 'DELETE'])
def handle_flury_v2():
    try:
        if request.method == 'POST':
            data = request.get_json()
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        flury_data_v2.append(item)
            elif isinstance(data, dict):
                flury_data_v2.append(data)
            return jsonify({'message': 'corrects'})
        elif request.method == 'GET':
            return jsonify(flury_data_v2)
        elif request.method == 'DELETE':
            data = request.get_json()
            if isinstance(data, list):
                for entry in data:
                    flury_data_v2[:] = [item for item in flury_data_v2 if not all(item.get(k) == v for k, v in entry.items())]
                return jsonify({'message': 'ok'})
            else:
                return jsonify({'message': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/inventory/<int:user_id>')
def get_inventory(user_id):
    try:
        asset_types = [1, 3, 4, 5, 9, 10, 13, 21, 24, 62, 40]
        all_inventory_data = []

        for asset_type in asset_types:
            cursor = ''
            while True:
                url = f"{ROBLOX_INVENTORY_API}/{user_id}/inventory/{asset_type}?cursor={cursor}&limit=100&sortOrder=Desc"
                response = requests.get(url, timeout=TIMEOUT)

                if response.status_code != 200:
                    break

                data = response.json()
                if "errors" in data:
                    error_code = data["errors"][0].get("code")
                    if error_code == 2:  # Skip invalid asset type
                        break

                all_inventory_data.extend(data.get('data', []))
                cursor = data.get('nextPageCursor')

                if not cursor:
                    break

        # Sort the inventory data by the 'created' field in descending order
        all_inventory_data.sort(key=lambda x: x['created'], reverse=True)

        return jsonify(all_inventory_data)
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == "__main__":
    # Check if Python is installed and available in the system's PATH
    if os.system('python --version') != 0:
        print("Python is not installed or not available in the system's PATH.")
        exit(1)

    # Check if the required dependencies are installed
    try:
        import flask
        import requests
    except ImportError:
        print("Required dependencies are missing. Please install them using 'pip install -r requirements.txt'.")
        exit(1)

    # Check if the port number matches the one expected by Cyclic
    port = int(os.environ.get('PORT', 3000))

    # Start the Flask application
    app.run(host="0.0.0.0", port=port)
