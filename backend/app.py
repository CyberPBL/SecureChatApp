import eventlet
eventlet.monkey_patch()

print("Running app.py")

import os
import base64
import datetime
import re # Import the re module for regular expressions
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
PORT = int(os.environ.get("PORT", 8000))

if not MONGO_URI:
    raise Exception("❌ MONGO_URI not set in .env file")

try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    client.admin.command('ping')
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    raise Exception(f"❌ MongoDB connection failed: {e}")

db = client["securechat_db"]
users_collection = db["users"]
chat_rooms_collection = db["chat_rooms"]

app = Flask(__name__)

FRONTEND_URL = os.getenv("FRONTEND_URL", "https://securechat-frontend-9qs2.onrender.com") # Use an environment variable for safety

CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            FRONTEND_URL
        ]
    }
})

socketio = SocketIO(app, cors_allowed_origins=[
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    FRONTEND_URL
])

online_users_sockets = {}
socket_id_to_username = {}

# --- NEW: Malicious Content Detection Function ---
def is_malicious_content(message):
    suspicious_patterns = [
        re.compile(r"https?:\/\/(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|shorte\.st|adf\.ly|rebrand\.ly|cutt\.ly|buff\.ly|lnkd\.in|bl\.ink|trib\.al|snip\.ly|shorturl\.at|shrtco\.de|short\.cm|v\.gd|zi\.mu)", re.IGNORECASE),
        re.compile(r"https?:\/\/.*\.(tk|ml|ga|cf|gq|xyz|top|club|pw|info)(\/|$)", re.IGNORECASE),
        re.compile(r"https?:\/\/(?:000webhostapp\.com|weebly\.com|wixsite\.com|github\.io|firebaseapp\.com|pages\.dev)", re.IGNORECASE),
        re.compile(r"https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}", re.IGNORECASE),
        re.compile(r"<script.?>.?<\/script>", re.IGNORECASE),
        re.compile(r"onerror\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"data:text\/html", re.IGNORECASE),
        re.compile(r"(login|verify|reset|account|bank|payment|alert).*(free|urgent|click|now|immediately)", re.IGNORECASE),
        re.compile(r"https?:\/\/.*(paypal|google|facebook|instagram|microsoft|whatsapp)\.[^\.]+?\.(tk|ml|ga|cf|gq|xyz|top)", re.IGNORECASE),
        re.compile(r"%[0-9a-f]{2}", re.IGNORECASE),
        re.compile(r"[\u200B-\u200F\u202A-\u202E]"),
    ]
    for pattern in suspicious_patterns:
        if pattern.search(message):
            return True
    return False
# --- END NEW ---


# --- Flask Routes (No changes here from your last provided app.py) ---

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print("📥 Received registration data:", data)

        username = data.get("username", "").strip()
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
            "friends": [],
            "pending_requests": []
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
    username = data.get('username', '').strip()
    pin = data.get('pin')

    if not username or not pin:
        return jsonify({"success": False, "message": "Username and PIN are required"}), 400

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['pin'], pin):
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/friends', methods=['GET'])
def get_friends_list():
    username = request.args.get('username', '').strip()
    print(f"Backend: GET /friends endpoint HIT for user: {username}")
    if not username:
        print("Backend: /friends - Username parameter missing.")
        return jsonify({"success": False, "message": "Username parameter is required."}), 400

    try:
        user_doc = users_collection.find_one({"username": username})
        if not user_doc:
            print(f"Backend: /friends - User '{username}' not found.")
            return jsonify({"success": False, "message": "User not found."}), 404

        friends_data = []
        if 'friends' in user_doc and user_doc['friends']:
            for friend_info in user_doc['friends']:
                friend_username = friend_info['username']
                friend_public_key = friend_info['public_key']
                is_online = friend_username in online_users_sockets
                friends_data.append({
                    "username": friend_username,
                    "publicKey": friend_public_key,
                    "status": "online" if is_online else "offline"
                })

        pending_requests = user_doc.get('pending_requests', [])

        print(f"Backend: Sending friends data for {username}: Friends={friends_data}, Pending={pending_requests}")
        return jsonify({
            "success": True,
            "friends": friends_data,
            "pendingRequests": pending_requests
        }), 200

    except Exception as e:
        print(f"❌ Backend: Error in /friends route for {username}: {str(e)}")
        return jsonify({"success": False, "message": "Server error fetching friends."}), 500

# --- SocketIO Event Handlers (MODIFIED send_message) ---

@socketio.on('connect')
def handle_connect():
    print(f"🔗 Client connected: {request.sid}")

@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    sid = request.sid

    if username:
        username = username.strip()
        user_doc = users_collection.find_one({"username": username})
        if user_doc:
            users_collection.update_one(
                {"username": username},
                {"$set": {"socket_id": sid}}
            )
            online_users_sockets[username] = sid
            socket_id_to_username[sid] = username
            print(f"🔵 User registered (SocketIO): {username} with SID: {sid}")

            current_online_users = list(online_users_sockets.keys())
            emit('registered', {'message': f'User {username} registered successfully.', 'onlineUsers': current_online_users}, room=sid)

            emit('online_users', current_online_users, broadcast=True)
        else:
            print(f"❌ User '{username}' not found in DB for socket registration.")
            emit('error', {'message': f'User {username} not found in database for socket registration.'}, room=sid)
    else:
        print("❌ Username missing in Socket.IO registration.")
        emit('error', {'message': 'Username missing in registration.'}, room=sid)

@socketio.on('search_user')
def handle_search_user(data):
    query_username = data.get('username', '').strip()
    print(f"Backend: Socket.IO search_user for: {query_username}")

    if not query_username:
        return emit('error', {'message': 'Search query missing.'}, room=request.sid)

    user_data = users_collection.find_one(
        {"username": query_username},
        {"_id": 0, "username": 1, "public_key": 1}
    )

    if user_data:
        emit('user_found', {
            "foundUser": user_data["username"],
            "publicKey": user_data["public_key"]
        }, room=request.sid)
        print(f"Backend: User '{query_username}' found.")
    else:
        emit('user_found', {
            "searchedUser": query_username,
            "foundUser": None
        }, room=request.sid)
        print(f"Backend: User '{query_username}' not found.")

@socketio.on('send_friend_request')
def handle_send_friend_request(data):
    sender = data.get('sender', '').strip()
    receiver = data.get('receiver', '').strip()
    print(f"Backend: Received send_friend_request from {sender} to {receiver}")

    if not sender or not receiver:
        return emit('error', {'message': 'Sender or receiver missing in friend request.'}, room=request.sid)
    if sender == receiver:
        return emit('error', {'message': 'Cannot send friend request to yourself.'}, room=request.sid)

    try:
        sender_user = users_collection.find_one({"username": sender})
        receiver_user = users_collection.find_one({"username": receiver})

        if not sender_user:
            return emit('error', {'message': f"Sender '{sender}' not found."}, room=request.sid)
        if not receiver_user:
            return emit('error', {'message': f"Receiver '{receiver}' not found."}, room=request.sid)

        if any(f['username'] == receiver for f in sender_user.get('friends', [])):
            return emit('error', {'message': f"{receiver} is already your friend."}, room=request.sid)
        if any(f['username'] == sender for f in receiver_user.get('friends', [])):
            return emit('error', {'message': f"You are already friends with {receiver}." }, room=request.sid)

        if receiver in sender_user.get('pending_requests', []):
            return emit('error', {'message': f"Friend request already sent to {receiver}."}, room=request.sid)

        if sender in receiver_user.get('pending_requests', []):
            return emit('error', {'message': f"{receiver} has already sent you a friend request. Accept it instead."}, room=request.sid)

        users_collection.update_one(
            {"username": receiver},
            {"$addToSet": {"pending_requests": sender}}
        )

        emit('friend_request_sent', {'receiver': receiver}, room=request.sid)

        receiver_sid = online_users_sockets.get(receiver)
        if receiver_sid:
            emit('friend_request_received', {'sender': sender}, room=receiver_sid)
            print(f"Backend: Friend request from {sender} to {receiver} received (online).")
        else:
            print(f"Backend: Friend request from {sender} to {receiver} sent (offline).")

        if receiver_sid:
            emit('friend_list_updated', {}, room=receiver_sid)
        emit('friend_list_updated', {}, room=request.sid)

    except Exception as e:
        print(f"❌ Backend: Error in send_friend_request: {str(e)}")
        emit('error', {'message': 'Server error sending friend request.'}, room=request.sid)

@socketio.on('accept_friend_request')
def handle_accept_friend_request(data):
    acceptor = data.get('acceptor', '').strip()
    requester = data.get('requester', '').strip()
    print(f"Backend: Received accept_friend_request: {acceptor} accepting {requester}")

    if not acceptor or not requester:
        return emit('error', {'message': 'Acceptor or requester missing.'}, room=request.sid)

    try:
        acceptor_user = users_collection.find_one({"username": acceptor})
        requester_user = users_collection.find_one({"username": requester})

        if not acceptor_user or not requester_user:
            return emit('error', {'message': 'User not found for acceptance.'}, room=request.sid)

        users_collection.update_one(
            {"username": acceptor},
            {"$pull": {"pending_requests": requester}}
        )

        users_collection.update_one(
            {"username": acceptor},
            {"$addToSet": {"friends": {"username": requester, "public_key": requester_user['public_key']}}}
        )
        users_collection.update_one(
            {"username": requester},
            {"$addToSet": {"friends": {"username": acceptor, "public_key": acceptor_user['public_key']}}}
        )

        emit('friend_request_accepted', {'requester': requester}, room=request.sid)

        requester_sid = online_users_sockets.get(requester)
        if requester_sid:
            emit('friend_request_accepted', {'requester': acceptor}, room=requester_sid)
            print(f"Backend: Friend request from {requester} accepted by {acceptor} (requester online).")
        else:
            print(f"Backend: Friend request from {requester} accepted by {acceptor} (requester offline).")

        emit('friend_list_updated', {}, room=request.sid)
        if requester_sid:
            emit('friend_list_updated', {}, room=requester_sid)

    except Exception as e:
        print(f"❌ Backend: Error in accept_friend_request: {str(e)}")
        emit('error', {'message': 'Server error accepting friend request.'}, room=request.sid)

@socketio.on('reject_friend_request')
def handle_reject_friend_request(data):
    rejecter = data.get('rejecter', '').strip()
    requester = data.get('requester', '').strip()
    print(f"Backend: Received reject_friend_request: {rejecter} rejecting {requester}")

    if not rejecter or not requester:
        return emit('error', {'message': 'Rejecter or requester missing.'}, room=request.sid)

    try:
        rejecter_user = users_collection.find_one({"username": rejecter})

        if not rejecter_user:
            return emit('error', {'message': 'Rejecter not found.'}, room=request.sid)

        users_collection.update_one(
            {"username": rejecter},
            {"$pull": {"pending_requests": requester}}
        )

        emit('friend_request_rejected', {'rejecter': rejecter}, room=request.sid)

        requester_sid = online_users_sockets.get(requester)
        if requester_sid:
            emit('friend_request_rejected', {'rejecter': rejecter}, room=requester_sid)
            print(f"Backend: Friend request from {requester} rejected by {rejecter} (requester online).")
        else:
            print(f"Backend: Friend request from {requester} rejected by {rejecter} (requester offline).")

        emit('friend_list_updated', {}, room=request.sid)
        if requester_sid:
            emit('friend_list_updated', {}, room=requester_sid)

    except Exception as e:
        print(f"❌ Backend: Error in reject_friend_request: {str(e)}")
        emit('error', {'message': 'Server error rejecting friend request.'}, room=request.sid)

@socketio.on('request_chat')
def handle_request_chat(data):
    sender = data.get('sender', '').strip()
    receiver = data.get('receiver', '').strip()
    print(f"Backend: Received request_chat from {sender} with {receiver}")

    if not sender or not receiver:
        return emit('error', {'message': 'Sender or receiver missing in chat request.'}, room=request.sid)

    try:
        sender_user = users_collection.find_one({"username": sender})
        receiver_user = users_collection.find_one({"username": receiver})

        if not sender_user or not receiver_user:
            return emit('error', {'message': 'Chat partner not found.'}, room=request.sid)

        if not any(f['username'] == receiver for f in sender_user.get('friends', [])):
            return emit('error', {'message': 'You are not friends with this user. Send a friend request first.'}, room=request.sid)

        participants_sorted = sorted([sender, receiver])
        room_id = "_".join(participants_sorted)

        chat_room = chat_rooms_collection.find_one({"room_id": room_id})
        if not chat_room:
            chat_room = {
                "room_id": room_id,
                "participants": participants_sorted,
                "messages": []
            }
            chat_rooms_collection.insert_one(chat_room)
            print(f"Backend: Created new chat room: {room_id}")

        join_room(room_id)
        receiver_sid = online_users_sockets.get(receiver)
        if receiver_sid:
            socketio.emit('join_room', room_id, room=receiver_sid)
            join_room(room_id, sid=receiver_sid)
            print(f"Backend: {sender} and {receiver} joined room {room_id}")
        else:
            print(f"Backend: {sender} joined room {room_id}. {receiver} is offline.")

        history_messages = chat_room.get('messages', [])

        emit('chat_approved', {
            'partner': receiver,
            'room': room_id,
            'history': history_messages
        }, room=request.sid)
        print(f"Backend: Chat approved for {sender} with {receiver} in room {room_id}. History sent.")

    except Exception as e:
        print(f"❌ Backend: Error in request_chat: {str(e)}")
        emit('error', {'message': 'Server error initiating chat.'}, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('sender', '').strip()
    to_user = data.get('receiver', '').strip()
    room = data.get('room', '').strip()
    message_for_receiver = data.get('messageForReceiver')
    message_for_self = data.get('messageForSelf')
    original_message_content = data.get('originalMessageContent') # NEW: Unencrypted message content for backend scan

    if not all([from_user, to_user, room, message_for_receiver, message_for_self, original_message_content]): # Ensure all are present
        print(f"Backend: send_message missing data: {data}")
        return emit('error', {'message': 'Missing data in send_message.'}, room=request.sid)

    try:
        # --- NEW: Backend malicious content check ---
        if is_malicious_content(original_message_content):
            print(f"🚨 Malicious content detected from {from_user} to {to_user}. Message blocked.")
            emit('message_blocked', {'reason': 'malicious_content_detected'}, room=request.sid)
            # Notify the receiver that a message from sender was blocked
            receiver_sid = online_users_sockets.get(to_user)
            if receiver_sid:
                emit('message_from_friend_blocked', {'sender': from_user, 'reason': 'malicious_content_detected'}, room=receiver_sid)
            return # Do not proceed with storing or forwarding the message
        # --- END NEW ---

        chat_rooms_collection.update_one(
            {"room_id": room},
            {"$push": {
                "messages": {
                    "sender": from_user,
                    "message": message_for_self,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                }
            }}
        )
        print(f"💬 Encrypted message from {from_user} to {to_user} in room {room} stored.")

        emit('receive_message', {
            'sender': from_user,
            'message': message_for_receiver,
            'room': room,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, room=room, include_self=True)

    except Exception as e:
        print(f"❌ Backend: Error in send_message: {str(e)}")
        emit('error', {'message': 'Server error sending message.'}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    username = socket_id_to_username.get(sid)

    if username:
        online_users_sockets.pop(username, None)
        socket_id_to_username.pop(sid, None)

        users_collection.update_one(
            {"username": username},
            {"$unset": {"socket_id": ""}}
        )
        print(f"❌ User '{username}' (SID: {sid}) disconnected (socket_id removed from DB and in-memory maps).")

        current_online_users = list(online_users_sockets.keys())
        emit('online_users', current_online_users, broadcast=True)
        emit('user_disconnected', {'username': username}, broadcast=True)
    else:
        print(f"❌ Socket disconnected: {sid} (no associated user found or socket_id already removed).")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=PORT, debug=True, allow_unsafe_werkzeug=True)
