import eventlet
eventlet.monkey_patch()

print("Running app.py")

import os
import base64
import datetime # Import for proper timestamps
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Import the AesEncryption and RSAEncryption classes from your encryption.py
from encryption import AesEncryption, RSAEncryption # Consolidated encryption logic

# Load environment variables from .env file
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"
# ✅ IMPORTANT: Get port from environment variable, default to 8000 for local development
PORT = int(os.environ.get("PORT", 8000))

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
messages_collection = db["messages"] # Collection to store chat history

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

# --- Local active_users dictionary (no longer used for socket_id mapping, primarily for debugging if needed) ---
active_users = {} # Just an empty dict as socket_ids are now managed by MongoDB

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

# Event handler for user registration via SocketIO
@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    sid = request.sid # Get the unique session ID of the connected client

    if username:
        # Save or update the socket_id in MongoDB for the given username.
        users_collection.update_one(
            {"username": username},
            {"$set": {"socket_id": sid}},
            upsert=True
        )
        print(f"🔵 User registered: {username} with SID: {sid}")
        # Emit a confirmation back to the registered user
        emit('registered', {'message': f'User {username} registered successfully.'}, room=sid)
    else:
        emit('error', {'message': 'Username missing in registration.'}, room=sid)

# Event handler to get currently online users
@socketio.on('get_online_users')
def handle_get_online_users():
    online_users_cursor = users_collection.find({"socket_id": {"$exists": True}}, {"username": 1, "_id": 0})
    online_users = [user['username'] for user in online_users_cursor]
    print(f"👥 Online users requested. Currently online: {online_users}")
    emit('online_users', {'users': online_users}, room=request.sid)

# Event handler for sending a chat request to another user
@socketio.on('send_chat_request')
def handle_send_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')

    if not from_user or not to_user:
        emit('error', {'message': 'Missing sender or receiver in chat request.'}, room=request.sid)
        return

    target_user = users_collection.find_one({"username": to_user})

    if target_user and "socket_id" in target_user:
        target_sid = target_user["socket_id"]
        # Emit the chat request to the target user's socket_id
        emit('chat_request', {'from_user': from_user}, room=target_sid)
        print(f"📨 Chat request sent from {from_user} to {to_user} (SID: {target_sid})")
    else:
        emit('error', {'message': f'User {to_user} not online or does not exist.'}, room=request.sid)
        print(f"❌ Failed to send chat request: {to_user} not online or does not exist.")

# Event handler for approving or denying a chat request
@socketio.on('approve_chat_request')
def handle_approve_chat_request(data):
    from_user = data.get('from_user') # The user who sent the original request
    to_user = data.get('to_user')   # The user who is approving/denying
    approved = data.get('approved') # Boolean: True if approved, False if denied

    if not from_user or not to_user or approved is None:
        emit('error', {'message': 'Missing required fields in approval request.'}, room=request.sid)
        return

    requester_user = users_collection.find_one({"username": from_user})

    if requester_user and "socket_id" in requester_user:
        requester_sid = requester_user["socket_id"]
        # Emit the approval/denial status back to the original requester
        emit('chat_request_approved', {'by_user': to_user, 'approved': approved}, room=requester_sid)
        print(f"✅ Chat request from {from_user} approved by {to_user}: {approved}")
    else:
        emit('error', {'message': f'User {from_user} not online or does not exist.'}, room=request.sid)
        print(f"❌ Failed to approve chat request: {from_user} not online or does not exist.")

# Event handler for passing the encrypted AES key between users
@socketio.on('send_aes_key_encrypted')
def handle_send_aes_key_encrypted(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    encrypted_aes_key = data.get('encrypted_aes_key')

    if not from_user or not to_user or not encrypted_aes_key:
        emit('error', {'message': 'Missing data for encrypted AES key transfer.'}, room=request.sid)
        return

    target_user = users_collection.find_one({"username": to_user})
    if target_user and "socket_id" in target_user:
        target_sid = target_user["socket_id"]
        emit('receive_aes_key_encrypted', {
            'from_user': from_user,
            'encrypted_aes_key': encrypted_aes_key
        }, room=target_sid)
        print(f"🔑 Encrypted AES key sent from {from_user} to {to_user}.")
    else:
        emit('error', {'message': f'User {to_user} not online to receive AES key.'}, room=request.sid)


# Event handler for joining a chat room
@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = data.get('username')
    if room and username:
        join_room(room)
        print(f"{username} joined room {room}")
        chat_partner = room.replace(username + '_', '').replace('_' + username, '')
        emit('chat_approved', {'with': chat_partner, 'room': room}, room=request.sid) # Pass room to frontend

        # Load chat history for the joined room
        history = list(messages_collection.find({"room": room}).sort("timestamp", 1))
        emit('chat_history', {'history': history}, room=request.sid)
        print(f"📜 Chat history for room {room} sent to {username}.")
    else:
        emit('error', {'message': 'Missing room or username in join.'}, room=request.sid)

# Event handler for sending encrypted chat messages
@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    message = data.get('message') # This should be the already encrypted message
    room = data.get('room')

    if not all([from_user, message, room]):
        emit('error', {'message': 'Missing from_user, message, or room in send_message.'}, room=request.sid)
        return

    # Store message in MongoDB (encrypted form) with accurate timestamp
    messages_collection.insert_one({
        "from_user": from_user,
        "to_user": to_user, # For history tracking
        "message": message, # Store the encrypted message
        "room": room,
        "timestamp": datetime.datetime.utcnow() # Use UTC timestamp
    })
    print(f"💬 Encrypted message from {from_user} to {to_user} in room {room} stored.")

    # Emit the encrypted message to all clients in the specific room
    emit('receive_message', {
        'username': from_user,
        'message': message, # This is already the encrypted message
        'timestamp': datetime.datetime.utcnow().isoformat() # Send timestamp to frontend
    }, room=room, include_self=True) # include_self=True ensures sender also sees their message

# Event handler for client disconnection
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    result = users_collection.update_one(
        {"socket_id": sid},
        {"$unset": {"socket_id": ""}} # Unset (remove) the socket_id field
    )
    if result.modified_count > 0:
        print(f"❌ User associated with socket {sid} disconnected (socket_id removed from DB).")
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
    # ✅ IMPORTANT: Listen on the PORT provided by the environment, typically for deployment
    socketio.run(app, host='0.0.0.0', port=PORT, debug=DEBUG_MODE, allow_unsafe_werkzeug=True)

