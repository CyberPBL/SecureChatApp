import eventlet
eventlet.monkey_patch()

print("Running app.py")

import os
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room # Added leave_room for completeness
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables from .env file
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"

# Ensure MONGO_URI is set
if not MONGO_URI:
    raise Exception("❌ MONGO_URI not set in .env file")

# Establish MongoDB connection
try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    # Ping the admin database to confirm a successful connection
    client.admin.command('ping')
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    raise Exception(f"❌ MongoDB connection failed: {e}")

# Select the database and collections
db = client["securechat_db"]
users_collection = db["users"]
messages_collection = db["messages"] # Added messages collection for storing chat history

# Initialize Flask app and CORS
app = Flask(__name__)
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            "https://securechat-frontend-9qs2.onrender.com"
        ]
    }
})

# Initialize Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins=[
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "https://securechat-frontend-9qs2.onrender.com"
])

# --- Local active_users dictionary (for backward compatibility or minor local logic) ---
# As per step 1, this is now just an empty dictionary.
# The socket_id tracking primarily moves to MongoDB.
active_users = {} # ✅ Just an empty dict as per fix (Step 1)

# AES Encryption class (from your original code)
class AesEncryption:
    @staticmethod
    def encrypt(message, key):
        if not key or len(key.encode()) not in {16, 24, 32}:
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        iv = os.urandom(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_message, key):
        if not key or len(key.encode()) not in {16, 24, 32}:
            raise ValueError("AES key must be 16, 24, or 32 bytes.")
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)
        return decrypted.decode('utf-8')

# --- Flask Routes ---

# Endpoint for searching users by username
@app.route('/search_user')
def search_user():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({"success": False, "message": "No query provided", "users": []})
    # Find users whose username matches the query, return only username field
    results = list(users_collection.find({"username": query}, {"_id": 0, "username": 1}))
    return jsonify({"success": True, "users": results})

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print("📥 Received data:", data)

        username = data.get("username")
        pin = data.get("pin")
        public_key = data.get("publicKey")

        if not username or not pin or not public_key:
            return jsonify({"success": False, "message": "Username, PIN, and Public Key are required"}), 400

        # Check for duplicate usernames
        if users_collection.find_one({"username": username}):
            return jsonify({"success": False, "message": "Username already exists"}), 409

        # Hash PIN and save
        hashed_pin = generate_password_hash(pin)

        # Insert new user into the users collection
        users_collection.insert_one({
            "username": username,
            "pin": hashed_pin,
            "public_key": public_key
        })

        return jsonify({"success": True, "message": "User registered successfully"}), 201

    except Exception as e:
        print("❌ Error in /register:", str(e))
        return jsonify({"success": False, "message": str(e)}), 500

# Endpoint to retrieve a user's public key
@app.route('/get_public_key')
def get_public_key():
    username = request.args.get('username')
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400

    # Find the user and return their public key
    user = users_collection.find_one({"username": username}, {"_id": 0, "public_key": 1})
    if user:
        return jsonify({"success": True, "public_key": user["public_key"]})
    return jsonify({"success": False, "message": "User not found"}), 404

# Endpoint for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    pin = data.get('pin')

    if not username or not pin:
        return jsonify({"success": False, "message": "Username and PIN are required"}), 400

    # Find the user and verify their PIN
    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['pin'], pin):
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

# --- SocketIO Event Handlers ---

# Event handler for client connection
@socketio.on('connect')
def handle_connect():
    print(f"🔗 Client connected: {request.sid}")

# Event handler for user registration via SocketIO (Step 2)
@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    sid = request.sid # Get the unique session ID of the connected client

    if username:
        # Save or update the socket_id in MongoDB for the given username.
        # This ensures that even if a user reconnects, their latest socket_id is updated.
        users_collection.update_one(
            {"username": username}, # Query to find the user
            {"$set": {"socket_id": sid}}, # Set the new socket_id
            upsert=True # Create the document if it doesn't exist
        )
        print(f"🔵 User registered: {username} with SID: {sid}")
        # Emit a confirmation back to the registered user
        emit('registered', {'message': f'User {username} registered successfully.'}, room=sid)
    else:
        # If username is missing, send an error back to the client
        emit('error', {'message': 'Username missing in registration.'}, room=sid)

# New event handler to get currently online users
@socketio.on('get_online_users')
def handle_get_online_users():
    # Fetch users who have a 'socket_id' field, indicating they are currently online
    online_users_cursor = users_collection.find({"socket_id": {"$exists": True}}, {"username": 1, "_id": 0})
    online_users = [user['username'] for user in online_users_cursor]
    print(f"👥 Online users requested. Currently online: {online_users}")
    # Emit the list of online users back to the requesting client
    emit('online_users', {'users': online_users}, room=request.sid)

# Event handler for sending a chat request to another user (Step 3)
@socketio.on('send_chat_request')
def handle_send_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')

    if not from_user or not to_user:
        emit('error', {'message': 'Missing sender or receiver in chat request.'}, room=request.sid)
        return

    # Find the target user in MongoDB to get their current socket_id
    target_user = users_collection.find_one({"username": to_user})

    if target_user and "socket_id" in target_user:
        target_sid = target_user["socket_id"]
        # Emit the chat request to the target user's socket_id
        emit('chat_request', {'from_user': from_user}, room=target_sid)
        print(f"📨 Chat request sent from {from_user} to {to_user} (SID: {target_sid})")
    else:
        # If target user is not found or not online, notify the sender
        emit('error', {'message': f'User {to_user} not online or does not exist.'}, room=request.sid)
        print(f"❌ Failed to send chat request: {to_user} not online or does not exist.")

# Event handler for approving or denying a chat request (Step 4)
@socketio.on('approve_chat_request')
def handle_approve_chat_request(data):
    from_user = data.get('from_user') # The user who sent the original request
    to_user = data.get('to_user')   # The user who is approving/denying
    approved = data.get('approved') # Boolean: True if approved, False if denied

    if not from_user or not to_user or approved is None:
        emit('error', {'message': 'Missing required fields in approval request.'}, room=request.sid)
        return

    # Find the original requester's socket_id in MongoDB
    requester_user = users_collection.find_one({"username": from_user})

    if requester_user and "socket_id" in requester_user:
        requester_sid = requester_user["socket_id"]
        # Emit the approval/denial status back to the original requester
        emit('chat_request_approved', {'by_user': to_user, 'approved': approved}, room=requester_sid)
        print(f"✅ Chat request from {from_user} approved by {to_user}: {approved}")
    else:
        # If requester is not found or not online, notify the approver
        emit('error', {'message': f'User {from_user} not online or does not exist.'}, room=request.sid)
        print(f"❌ Failed to approve chat request: {from_user} not online or does not exist.")

# Event handler for joining a chat room
@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = data.get('username')
    if room and username:
        join_room(room)
        print(f"{username} joined room {room}")
        # Notify the joining user about the chat partner (room name parsing)
        chat_partner = room.replace(username + '_', '').replace('_' + username, '')
        emit('chat_approved', {'with': chat_partner}, room=request.sid)
    else:
        emit('error', {'message': 'Missing room or username in join.'})

# Event handler for sending encrypted chat messages
@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user') # This can be used for logging/database, but room handles broadcast
    message = data.get('message') # This should be the already encrypted message
    room = data.get('room')
    # chat_key is NOT directly used here for encryption, as encryption happens client-side.
    # It might be used for validation or logging if needed, but the message itself is already encrypted.
    # chat_key = data.get('chat_key') # Removed as it's not used for encryption here

    if not all([from_user, message, room]): # Removed to_user and chat_key as mandatory for direct emission
        emit('error', {'message': 'Missing from_user, message, or room in send_message.'}, room=request.sid)
        return

    # Store message in MongoDB (encrypted form)
    # Using a simple timestamp for now. In a real app, use `datetime.utcnow()`
    messages_collection.insert_one({
        "from_user": from_user,
        "to_user": to_user, # Still include to_user for message history lookup
        "message": message, # Store the encrypted message
        "room": room,
        "timestamp": os.getpid() # Placeholder, use proper datetime
    })
    print(f"💬 Encrypted message from {from_user} to {to_user} in room {room} stored.")

    # Emit the encrypted message to all clients in the specific room
    # The message is expected to be encrypted by the client before sending
    emit('receive_message', {
        'username': from_user,
        'message': message # This is already the encrypted message
    }, room=room, include_self=True) # include_self=True ensures sender also sees their message

# Event handler for client disconnection (Step 5)
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    # When a socket disconnects, find the user associated with that socket_id
    # and remove the 'socket_id' field from their document in MongoDB.
    # This marks them as offline without deleting their user record.
    result = users_collection.update_one(
        {"socket_id": sid},
        {"$unset": {"socket_id": ""}} # Unset (remove) the socket_id field
    )
    if result.modified_count > 0:
        # Retrieve the username of the disconnected user for logging
        disconnected_user_doc = users_collection.find_one({"socket_id": {"$exists": False}, "_id": result.upserted_id or result.matched_count})
        disconnected_username = disconnected_user_doc.get("username") if disconnected_user_doc else "Unknown"
        print(f"❌ User '{disconnected_username}' associated with socket {sid} disconnected (socket_id removed from DB).")
    else:
        print(f"❌ Socket disconnected: {sid} (no associated user found or socket_id already removed).")


# --- After Request Hook for CORS Headers ---
@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# --- Run the application ---
if __name__ == '__main__':
    # Run the SocketIO server.
    # debug=True is useful for development, disable in production.
    # allow_unsafe_werkzeug=True is sometimes needed for the reloader with eventlet.
    socketio.run(app, host='0.0.0.0', port=8000, debug=DEBUG_MODE, allow_unsafe_werkzeug=True)
