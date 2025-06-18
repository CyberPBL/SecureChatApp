import eventlet
eventlet.monkey_patch()

import os
import base64
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Import the AesEncryption and RSAEncryption classes from your encryption.py
from encryption import AesEncryption, RSAEncryption

# Load environment variables from .env file
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"
PORT = int(os.environ.get("PORT", 8000))

# Ensure MONGO_URI is set
if not MONGO_URI:
    raise Exception("❌ MONGO_URI not set in .env file")

# Establish MongoDB connection
try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    client.admin.command('ping')
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    raise Exception(f"❌ MongoDB connection failed: {e}")

# Select the database and collections
db = client["securechat_db"]
users_collection = db["users"]
messages_collection = db["messages"] # Collection to store chat history

# ✅ Feature: TTL Index for Messages
# Messages will be automatically deleted 24 hours (86400 seconds) after their 'timestamp'.
# This command is idempotent, meaning it can be run multiple times safely.
try:
    messages_collection.create_index(
        "timestamp",
        expireAfterSeconds=86400 # 24 hours * 60 minutes * 60 seconds
    )
    print("✅ TTL index created on messages_collection for automatic deletion.")
except Exception as e:
    print(f"⚠️ Could not create TTL index on messages_collection: {e}")


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

# --- Flask Routes ---

@app.route('/search_user')
def search_user():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({"success": False, "message": "No query provided", "user": None})

    user_data = users_collection.find_one(
        {"username": query},
        {"_id": 0, "username": 1, "socket_id": 1}
    )

    if user_data:
        is_online = "socket_id" in user_data and user_data["socket_id"] is not None and user_data["socket_id"] != ""
        return jsonify({
            "success": True,
            "user": {
                "username": user_data["username"],
                "is_online": is_online
            },
            "message": "User found." if is_online else "User found but currently offline."
        })
    else:
        return jsonify({"success": False, "message": "User not found.", "user": None})

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print("📥 Received data:", data)

        username = data.get("username").strip()
        pin = data.get("pin")
        public_key = data.get("publicKey")

        if not username or not pin or not public_key:
            return jsonify({"success": False, "message": "Username, PIN, and Public Key are required"}), 400

        if users_collection.find_one({"username": username}):
            return jsonify({"success": False, "message": "Username already exists"}), 409

        hashed_pin = generate_password_hash(pin)

        users_collection.insert_one({
            "username": username,
            "pin": hashed_pin,
            "public_key": public_key,
            "friends": [] # ✅ Feature: Initialize empty friends list
        })

        return jsonify({"success": True, "message": "User registered successfully"}), 201

    except Exception as e:
        print("❌ Error in /register:", str(e))
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/get_public_key')
def get_public_key():
    username = request.args.get('username')
    if not username:
        return jsonify({"success": False, "message": "Username required"}), 400

    user = users_collection.find_one({"username": username}, {"_id": 0, "public_key": 1})
    if user:
        return jsonify({"success": True, "public_key": user["public_key"]})
    return jsonify({"success": False, "message": "User not found"}), 404

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username').strip()
    pin = data.get('pin')

    if not username or not pin:
        return jsonify({"success": False, "message": "Username and PIN are required"}), 400

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['pin'], pin):
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

# --- SocketIO Event Handlers ---

@socketio.on('connect')
def handle_connect():
    print(f"🔗 Client connected: {request.sid}")

@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    if username:
        username = username.strip()
    sid = request.sid

    if username:
        if users_collection.find_one({"username": username}):
            users_collection.update_one(
                {"username": username},
                {"$set": {"socket_id": sid}}
            )
            print(f"🔵 User registered: {username} with SID: {sid}")
            emit('registered', {'message': f'User {username} registered successfully.'}, room=sid)
        else:
            emit('error', {'message': f'User {username} not found in database for socket registration.'}, room=sid)
    else:
        emit('error', {'message': 'Username missing in registration.'}, room=sid)

@socketio.on('get_online_users')
def handle_get_online_users():
    online_users_cursor = users_collection.find({"socket_id": {"$exists": True, "$ne": None, "$ne": ""}}, {"username": 1, "_id": 0})
    online_users = [user['username'] for user in online_users_cursor]
    print(f"👥 Online users requested. Currently online: {online_users}")
    emit('online_users', {'users': online_users}, room=request.sid)

# ✅ Feature: Get Friends List
@socketio.on('get_friends')
def handle_get_friends(data):
    username = data.get('username')
    if not username:
        emit('error', {'message': 'Username missing for get_friends.'}, room=request.sid)
        return

    user = users_collection.find_one({"username": username}, {"_id": 0, "friends": 1})
    if user and "friends" in user:
        # Fetch status for friends if online
        friends_with_status = []
        for friend_username in user['friends']:
            friend_data = users_collection.find_one({"username": friend_username}, {"_id": 0, "socket_id": 1})
            is_online = False
            if friend_data and "socket_id" in friend_data and friend_data["socket_id"] is not None and friend_data["socket_id"] != "":
                is_online = True
            friends_with_status.append({"username": friend_username, "is_online": is_online})
        emit('friends_list', {'friends': friends_with_status}, room=request.sid)
        print(f"👥 Friends list for {username} requested: {user['friends']}")
    else:
        emit('friends_list', {'friends': []}, room=request.sid) # Emit empty list if no friends


@socketio.on('send_chat_request')
def handle_send_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')

    if not from_user or not to_user:
        emit('error', {'message': 'Missing sender or receiver in chat request.'}, room=request.sid)
        return

    target_user = users_collection.find_one({"username": to_user})

    if target_user and "socket_id" in target_user and target_user["socket_id"] is not None and target_user["socket_id"] != "":
        target_sid = target_user["socket_id"]
        emit('chat_request', {'from_user': from_user}, room=target_sid)
        print(f"📨 Chat request sent from {from_user} to {to_user} (SID: {target_sid})")
    else:
        emit('error', {'message': f'User {to_user} not online or does not exist.'}, room=request.sid)
        print(f"❌ Failed to send chat request: {to_user} not online or does not exist.")

@socketio.on('approve_chat_request')
def handle_approve_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    approved = data.get('approved')

    if not from_user or not to_user or approved is None:
        emit('error', {'message': 'Missing required fields in approval request.'}, room=request.sid)
        return

    requester_user = users_collection.find_one({"username": from_user})

    if approved:
        # ✅ Feature: Add to friends list for both users if approved
        users_collection.update_one(
            {"username": from_user},
            {"$addToSet": {"friends": to_user}} # Add to_user to from_user's friends
        )
        users_collection.update_one(
            {"username": to_user},
            {"$addToSet": {"friends": from_user}} # Add from_user to to_user's friends
        )
        print(f"✅ Added {to_user} to {from_user}'s friends and vice-versa.")

    if requester_user and "socket_id" in requester_user and requester_user["socket_id"] is not None and requester_user["socket_id"] != "":
        requester_sid = requester_user["socket_id"]
        emit('chat_request_approved', {'by_user': to_user, 'approved': approved}, room=requester_sid)
        print(f"✅ Chat request from {from_user} approved by {to_user}: {approved}")
    else:
        emit('error', {'message': f'User {from_user} not online or does not exist.'}, room=request.sid)
        print(f"❌ Failed to approve chat request: {from_user} not online or does not exist.")

@socketio.on('send_aes_key_encrypted')
def handle_send_aes_key_encrypted(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    encrypted_aes_key = data.get('encrypted_aes_key')

    if not from_user or not to_user or not encrypted_aes_key:
        emit('error', {'message': 'Missing data for encrypted AES key transfer.'}, room=request.sid)
        return

    target_user = users_collection.find_one({"username": to_user})
    if target_user and "socket_id" in target_user and target_user["socket_id"] is not None and target_user["socket_id"] != "":
        target_sid = target_user["socket_id"]
        emit('receive_aes_key_encrypted', {
            'from_user': from_user,
            'encrypted_aes_key': encrypted_aes_key
        }, room=target_sid)
        print(f"🔑 Encrypted AES key sent from {from_user} to {to_user}.")
    else:
        emit('error', {'message': f'User {to_user} not online to receive AES key.'}, room=request.sid)

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = data.get('username')
    if room and username:
        join_room(room)
        print(f"{username} joined room {room}")
        chat_partner = room.replace(username + '_', '').replace('_' + username, '')
        emit('chat_approved', {'with': chat_partner, 'room': room}, room=request.sid)

        history = list(messages_collection.find({"room": room}).sort("timestamp", 1))
        emit('chat_history', {'history': history}, room=request.sid)
        print(f"📜 Chat history for room {room} sent to {username}.")
    else:
        emit('error', {'message': 'Missing room or username in join.'}, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    message = data.get('message') # This should be the already encrypted message
    room = data.get('room')

    if not all([from_user, message, room]):
        emit('error', {'message': 'Missing from_user, message, or room in send_message.'}, room=request.sid)
        return

    messages_collection.insert_one({
        "from_user": from_user,
        "to_user": to_user, # For history tracking
        "message": message, # Store the encrypted message
        "room": room,
        "timestamp": datetime.datetime.utcnow(), # Use UTC timestamp for TTL
        "last_seen": None # ✅ Feature: Add last_seen for potential future "seen by recipient" deletion
    })
    print(f"💬 Encrypted message from {from_user} to {to_user} in room {room} stored.")

    emit('receive_message', {
        'username': from_user,
        'message': message,
        'timestamp': datetime.datetime.utcnow().isoformat()
    }, room=room, include_self=True)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    result = users_collection.update_one(
        {"socket_id": sid},
        {"$unset": {"socket_id": ""}}
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
    socketio.run(app, host='0.0.0.0', port=PORT, debug=DEBUG_MODE, allow_unsafe_werkzeug=True)
