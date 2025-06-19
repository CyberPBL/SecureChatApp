import eventlet
eventlet.monkey_patch()

print("Running app.py")

import os
import base64
import datetime
import re # Import regex module
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Import the AesEncryption and RSAEncryption classes from your encryption.py
# Assuming encryption.py is in the same directory and contains necessary classes
try:
    from encryption import AesEncryption, RSAEncryption
except ImportError:
    print("WARNING: encryption.py not found or classes missing. RSA/AES functionality might be impaired.")
    # Define dummy classes if encryption.py is missing to prevent crash during Flask startup
    class AesEncryption:
        pass
    class RSAEncryption:
        pass


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

# Feature: TTL Index for Messages
# Messages will be automatically deleted 24 hours (86400 seconds) after their 'timestamp'.
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

# --- Malicious Link Detection Patterns (Backend) ---
# Converted from the provided JavaScript regex patterns
MALICIOUS_PATTERNS = [
    r"https?:\/\/(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|shorte\.st|adf\.ly|rebrand\.ly|cutt\.ly|buff\.ly|lnkd\.in|bl\.ink|trib\.al|snip\.ly|shorturl\.at|shrtco\.de|short\.cm|v\.gd|zi\.mu)",
    r"https?:\/\/.*\.(tk|ml|ga|cf|gq|xyz|top|club|pw|info)(\/|$)",
    r"https?:\/\/(?:000webhostapp\.com|weebly\.com|wixsite\.com|github\.io|firebaseapp\.com|pages\.dev)",
    r"https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
    r"<script.*?>.*?<\/script>", # Detects script tags
    r"onerror\s*=", # Detects onerror attributes
    r"javascript:", # Detects javascript: URIs
    r"data:text\/html", # Detects data URIs for HTML
    r"(login|verify|reset|account|bank|payment|alert).*(free|urgent|click|now|immediately)", # Phishing keywords
    r"https?:\/\/.*(?:paypal|google|facebook|instagram|microsoft|whatsapp)\.[^\.]+?\.(?:tk|ml|ga|cf|gq|xyz|top)", # Typosquatting/Phishing domains
    r"%[0-9a-f]{2}", # URL encoded characters often used in exploits
    r"[\u200B-\u200F\u202A-\u202E]", # Unicode invisible characters
]

def _scan_for_malicious_content(message_content):
    """
    Scans message content for malicious patterns.
    Returns True if malicious content is found, along with the matched pattern.
    Returns False and None otherwise.
    """
    for pattern_str in MALICIOUS_PATTERNS:
        if re.search(pattern_str, message_content, re.IGNORECASE):
            print(f"🚨 Malicious content detected! Matched pattern: {pattern_str}")
            return True, pattern_str
    return False, None

# --- Flask Routes (these are handled by Gunicorn workers, not directly by SocketIO's event loop, so no change needed here) ---

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
            "public_key": public_key, # This is the public key being saved
            "friends": [] # Feature: Initialize empty friends list
        })
        # ✅ New Logging: Print the public key saved to MongoDB
        print(f"✅ Registered {username}. Saved Public Key (first 50 chars): {public_key[:50]}...")


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

def _register_user_background(username, sid):
    with app.app_context(): # ✅ Push app context
        username = username.strip()
        if users_collection.find_one({"username": username}):
            users_collection.update_one(
                {"username": username},
                {"$set": {"socket_id": sid}}
            )
            print(f"🔵 User registered: {username} with SID: {sid}")
            socketio.emit('registered', {'message': f'User {username} registered successfully.'}, room=sid)
        else:
            socketio.emit('error', {'message': f'User {username} not found in database for socket registration. Please register via the login page first.'}, room=sid)

@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    sid = request.sid
    if username:
        socketio.start_background_task(_register_user_background, username, sid)
    else:
        emit('error', {'message': 'Username missing in registration.'}, room=sid)

def _get_online_users_background(sid):
    with app.app_context(): # ✅ Push app context
        online_users_cursor = users_collection.find({"socket_id": {"$exists": True, "$ne": None, "$ne": ""}}, {"username": 1, "_id": 0})
        online_users = [user['username'] for user in online_users_cursor]
        print(f"👥 Online users requested. Currently online: {online_users}")
        socketio.emit('online_users', {'users': online_users}, room=sid)

@socketio.on('get_online_users')
def handle_get_online_users():
    socketio.start_background_task(_get_online_users_background, request.sid)

def _get_friends_background(username, sid):
    with app.app_context(): # ✅ Push app context
        user = users_collection.find_one({"username": username}, {"_id": 0, "friends": 1})
        if user and "friends" in user:
            friends_with_status = []
            for friend_username in user['friends']:
                friend_data = users_collection.find_one({"username": friend_username}, {"_id": 0, "socket_id": 1})
                is_online = False
                if friend_data and "socket_id" in friend_data and friend_data["socket_id"] is not None and friend_data["socket_id"] != "":
                    is_online = True
                friends_with_status.append({"username": friend_username, "is_online": is_online})
            socketio.emit('friends_list', {'friends': friends_with_status}, room=sid)
            print(f"👥 Friends list for {username} requested: {user['friends']}")
        else:
            socketio.emit('friends_list', {'friends': []}, room=sid)

@socketio.on('get_friends')
def handle_get_friends(data):
    username = data.get('username')
    if username:
        socketio.start_background_task(_get_friends_background, username, request.sid)
    else:
        emit('error', {'message': 'Username missing for get_friends.'}, room=request.sid)

def _send_chat_request_background(from_user, to_user, sender_sid):
    with app.app_context(): # ✅ Push app context
        target_user = users_collection.find_one({"username": to_user})
        if target_user and "socket_id" in target_user and target_user["socket_id"] is not None and target_user["socket_id"] != "":
            target_sid = target_user["socket_id"]
            socketio.emit('chat_request', {'from_user': from_user}, room=target_sid)
            print(f"📨 Chat request sent from {from_user} to {to_user} (SID: {target_sid})")
        else:
            socketio.emit('error', {'message': f'User {to_user} not online or does not exist.'}, room=sender_sid)
            print(f"❌ Failed to send chat request: {to_user} not online or does not exist.")

@socketio.on('send_chat_request')
def handle_send_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    if not from_user or not to_user:
        emit('error', {'message': 'Missing sender or receiver in chat request.'}, room=request.sid)
        return
    socketio.start_background_task(_send_chat_request_background, from_user, to_user, request.sid)

def _approve_chat_request_background(from_user, to_user, approved, approver_sid):
    with app.app_context(): # ✅ Push app context
        if approved:
            users_collection.update_one(
                {"username": from_user},
                {"$addToSet": {"friends": to_user}}
            )
            users_collection.update_one(
                {"username": to_user},
                {"$addToSet": {"friends": from_user}}
            )
            print(f"✅ Added {to_user} to {from_user}'s friends and vice-versa.")

        requester_user = users_collection.find_one({"username": from_user})

        if requester_user and "socket_id" in requester_user and requester_user["socket_id"] is not None and requester_user["socket_id"] != "":
            requester_sid = requester_user["socket_id"]
            socketio.emit('chat_request_approved', {'by_user': to_user, 'approved': approved}, room=requester_sid)
            print(f"✅ Chat request from {from_user} approved by {to_user}: {approved}")
            # Also, re-emit friends list to both users if approval happened
            socketio.start_background_task(_get_friends_background, from_user, requester_sid)
            socketio.start_background_task(_get_friends_background, to_user, approver_sid)
        else:
            socketio.emit('error', {'message': f'User {from_user} not online or does not exist.'}, room=approver_sid)
            print(f"❌ Failed to approve chat request: {from_user} not online or does not exist.")

@socketio.on('approve_chat_request')
def handle_approve_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    approved = data.get('approved')
    if not from_user or not to_user or approved is None:
        emit('error', {'message': 'Missing required fields in approval request.'}, room=request.sid)
        return
    socketio.start_background_task(_approve_chat_request_background, from_user, to_user, approved, request.sid)

def _send_aes_key_encrypted_background(from_user, to_user, encrypted_aes_key, sender_sid):
    with app.app_context(): # ✅ Push app context
        target_user = users_collection.find_one({"username": to_user})
        if target_user and "socket_id" in target_user and target_user["socket_id"] is not None and target_user["socket_id"] != "":
            target_sid = target_user["socket_id"]
            # ✅ NEW LOG: Print the encrypted_aes_key right before emitting from backend
            print(f"🔑 Backend emitting encrypted AES key from {from_user} to {to_user} (first 50 chars): {encrypted_aes_key[:50]}...")
            socketio.emit('receive_aes_key_encrypted', {
                'from_user': from_user,
                'encrypted_aes_key': encrypted_aes_key
            }, room=target_sid)
            print(f"🔑 Encrypted AES key sent from {from_user} to {to_user}.")
        else:
            socketio.emit('error', {'message': f'User {to_user} not online to receive AES key.'}, room=sender_sid)

@socketio.on('send_aes_key_encrypted')
def handle_send_aes_key_encrypted(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    encrypted_aes_key = data.get('encrypted_aes_key')
    if not from_user or not to_user or not encrypted_aes_key:
        emit('error', {'message': 'Missing data for encrypted AES key transfer.'}, room=request.sid)
        return
    socketio.start_background_task(_send_aes_key_encrypted_background, from_user, to_user, encrypted_aes_key, request.sid)

def _join_background(room, username, sid_from_request): # Added sid_from_request parameter
    with app.app_context(): # ✅ Push app context
        join_room(room, sid=sid_from_request) # Explicitly pass sid
        print(f"{username} joined room {room}")
        chat_partner = room.replace(username + '_', '').replace('_' + username, '')
        socketio.emit('chat_approved', {'with': chat_partner, 'room': room}, room=sid_from_request) # Use sid_from_request
        # If the user just joined, fetch and send chat history
        history = list(messages_collection.find({"room": room}).sort("timestamp", 1))
        socketio.emit('chat_history', {'history': history}, room=sid_from_request) # Use sid_from_request
        print(f"📜 Chat history for room {room} sent to {username}.")

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = data.get('username')
    if room and username:
        # Pass request.sid to the background task
        socketio.start_background_task(_join_background, room, username, request.sid)
    else:
        emit('error', {'message': 'Missing room or username in join.'}, room=request.sid)

def _send_message_background(from_user, to_user, message, room, sender_sid):
    with app.app_context(): # ✅ Push app context
        # --- Malicious Link Scan ---
        is_malicious, matched_pattern = _scan_for_malicious_content(message)

        if is_malicious:
            print(f"🚨🚨🚨 Blocking malicious message from {from_user} to {to_user}. Matched: {matched_pattern}")

            # Notify sender
            socketio.emit('malicious_message_blocked', {
                'from_user': from_user,
                'to_user': to_user,
                'message': "Your message contained suspicious content and was blocked.",
                'reason': f"Matched pattern: {matched_pattern}"
            }, room=sender_sid)

            # Notify recipient (if online)
            recipient_user = users_collection.find_one({"username": to_user})
            if recipient_user and recipient_user.get("socket_id"):
                socketio.emit('malicious_message_blocked', {
                    'from_user': from_user,
                    'to_user': to_user,
                    'message': f"A message from {from_user} was blocked due to suspicious content.",
                    'reason': "Security Alert"
                }, room=recipient_user["socket_id"])

            # Remove from friend list (both ways)
            users_collection.update_one(
                {"username": from_user},
                {"$pull": {"friends": to_user}}
            )
            users_collection.update_one(
                {"username": to_user},
                {"$pull": {"friends": from_user}}
            )
            print(f"❌ {from_user} and {to_user} removed from each other's friend lists due to malicious activity.")
            # Re-emit friends list to both users to update UI
            socketio.start_background_task(_get_friends_background, from_user, sender_sid)
            if recipient_user and recipient_user.get("socket_id"):
                socketio.start_background_task(_get_friends_background, to_user, recipient_user["socket_id"])

            return # Stop processing, message is blocked

        # If not malicious, proceed with storing and emitting the message
        messages_collection.insert_one({
            "from_user": from_user,
            "to_user": to_user,
            "message": message,
            "room": room,
            "timestamp": datetime.datetime.utcnow(),
            "last_seen": None
        })
        print(f"💬 Encrypted message from {from_user} to {to_user} in room {room} stored.")

        socketio.emit('receive_message', {
            'username': from_user,
            'message': message,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, room=room, include_self=True)

@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    message = data.get('message')
    room = data.get('room')

    if not all([from_user, message, room]):
        emit('error', {'message': 'Missing from_user, message, or room in send_message.'}, room=request.sid)
        return
    socketio.start_background_task(_send_message_background, from_user, to_user, message, room, request.sid)

def _disconnect_background(sid):
    with app.app_context(): # ✅ Push app context
        result = users_collection.update_one(
            {"socket_id": sid},
            {"$unset": {"socket_id": ""}}
        )
        if result.modified_count > 0:
            print(f"❌ User associated with socket {sid} disconnected (socket_id removed from DB).")
        else:
            print(f"❌ Socket disconnected: {sid} (no associated user found or socket_id already removed).")

@socketio.on('disconnect')
def handle_disconnect():
    socketio.start_background_task(_disconnect_background, request.sid)

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
