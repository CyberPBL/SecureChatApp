import eventlet
eventlet.monkey_patch()

print("Running app.py")

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

# Assuming these are correctly implemented in your encryption.py
# from encryption import AesEncryption, RSAEncryption 

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
# DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true" # Not directly used by socketio.run debug
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
# Renaming messages_collection to chat_rooms_collection for clarity based on new structure
chat_rooms_collection = db["chat_rooms"] 

app = Flask(__name__)

# IMPORTANT: Set your actual frontend URL here
FRONTEND_URL = "https://securechat-frontend-9qs2.onrender.com" # !!! REPLACE THIS WITH YOUR REAL FRONTEND URL !!!

CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            FRONTEND_URL # Use the variable
        ]
    }
})

socketio = SocketIO(app, cors_allowed_origins=[
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    FRONTEND_URL # Use the variable
])

# --- Global Dictionaries for online user tracking (temporary, for real-time only) ---
# For persistent tracking, user's socket_id should be updated in MongoDB
online_users_sockets = {} # {username: socket_id} - Maps username to current socket ID
socket_id_to_username = {} # {socket_id: username} - Maps socket ID to username

# --- Flask Routes ---

# No longer needed as search is handled via Socket.IO
# @app.route('/search_user')
# def search_user_http():
#     # ... (Removed, logic moved to SocketIO)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print("📥 Received registration data:", data)

        username = data.get("username", "").strip() # Ensure stripping even if not present
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
            "friends": [],           # Initialize friends list
            "pending_requests": []   # Initialize pending requests
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
    username = data.get('username', '').strip() # Ensure stripping
    pin = data.get('pin')

    if not username or not pin:
        return jsonify({"success": False, "message": "Username and PIN are required"}), 400

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['pin'], pin):
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

# --- NEW: /friends endpoint to retrieve friend list and pending requests ---
@app.route('/friends', methods=['GET'])
def get_friends_list():
    username = request.args.get('username', '').strip()
    print(f"Backend: GET /friends endpoint HIT for user: {username}") # Crucial log
    if not username:
        print("Backend: /friends - Username parameter missing.")
        return jsonify({"success": False, "message": "Username parameter is required."}), 400

    try:
        user_doc = users_collection.find_one({"username": username})
        if not user_doc:
            print(f"Backend: /friends - User '{username}' not found.")
            return jsonify({"success": False, "message": "User not found."}), 404

        # Prepare friends list with their public keys and online status
        friends_data = []
        if 'friends' in user_doc and user_doc['friends']:
            for friend_info in user_doc['friends']:
                friend_username = friend_info['username']
                friend_public_key = friend_info['public_key'] # Make sure this is stored when friends are added
                is_online = friend_username in online_users_sockets
                friends_data.append({
                    "username": friend_username,
                    "publicKey": friend_public_key,
                    "status": "online" if is_online else "offline"
                })
        
        # Prepare pending requests list
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

# --- SocketIO Event Handlers ---

@socketio.on('connect')
def handle_connect():
    print(f"🔗 Client connected: {request.sid}")

@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    sid = request.sid

    if username:
        username = username.strip() # Strip username to ensure consistency
        user_doc = users_collection.find_one({"username": username})
        if user_doc:
            # Update socket_id in DB and in our in-memory maps
            users_collection.update_one(
                {"username": username},
                {"$set": {"socket_id": sid}}
            )
            online_users_sockets[username] = sid
            socket_id_to_username[sid] = username
            print(f"🔵 User registered (SocketIO): {username} with SID: {sid}")
            
            # Get current online users to send to the newly connected client
            current_online_users = list(online_users_sockets.keys())
            emit('registered', {'message': f'User {username} registered successfully.', 'onlineUsers': current_online_users}, room=sid)
            
            # Notify all other clients that a user came online
            emit('online_users', current_online_users, broadcast=True) # Send just array, as expected by frontend
        else:
            print(f"❌ User '{username}' not found in DB for socket registration.")
            emit('error', {'message': f'User {username} not found in database for socket registration.'}, room=sid)
    else:
        print("❌ Username missing in Socket.IO registration.")
        emit('error', {'message': 'Username missing in registration.'}, room=sid)

# --- REPLACED HTTP SEARCH WITH SOCKET.IO SEARCH ---
@socketio.on('search_user')
def handle_search_user(data):
    query_username = data.get('username', '').strip()
    print(f"Backend: Socket.IO search_user for: {query_username}")

    if not query_username:
        return emit('error', {'message': 'Search query missing.'}, room=request.sid)

    user_data = users_collection.find_one(
        {"username": query_username},
        {"_id": 0, "username": 1, "public_key": 1} # Fetch public_key now as frontend needs it
    )

    if user_data:
        # If user is found, their public_key is also retrieved
        emit('user_found', {
            "foundUser": user_data["username"],
            "publicKey": user_data["public_key"] # Pass public key to frontend for encryption
        }, room=request.sid)
        print(f"Backend: User '{query_username}' found.")
    else:
        emit('user_found', {
            "searchedUser": query_username, # Send back what was searched for
            "foundUser": None
        }, room=request.sid)
        print(f"Backend: User '{query_username}' not found.")

# --- NEW: send_friend_request handler (matching frontend) ---
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

        # Check if already friends
        if any(f['username'] == receiver for f in sender_user.get('friends', [])):
            return emit('error', {'message': f"{receiver} is already your friend."}, room=request.sid)
        if any(f['username'] == sender for f in receiver_user.get('friends', [])):
             return emit('error', {'message': f"You are already friends with {receiver}." }, room=request.sid)

        # Check if request already pending from sender to receiver
        if receiver in sender_user.get('pending_requests', []): # Receiver has pending request from sender
            return emit('error', {'message': f"Friend request already sent to {receiver}."}, room=request.sid)
        
        # Check if receiver already sent request to sender
        if sender in receiver_user.get('pending_requests', []):
            return emit('error', {'message': f"{receiver} has already sent you a friend request. Accept it instead."}, room=request.sid)
            

        # Add sender to receiver's pending_requests
        users_collection.update_one(
            {"username": receiver},
            {"$addToSet": {"pending_requests": sender}} # $addToSet prevents duplicates
        )

        emit('friend_request_sent', {'receiver': receiver}, room=request.sid)

        # Notify receiver if online
        receiver_sid = online_users_sockets.get(receiver)
        if receiver_sid:
            emit('friend_request_received', {'sender': sender}, room=receiver_sid)
            print(f"Backend: Friend request from {sender} to {receiver} received (online).")
        else:
            print(f"Backend: Friend request from {sender} to {receiver} sent (offline).")
        
        # Trigger frontend to refetch friends for both users involved if online
        if receiver_sid:
            emit('friend_list_updated', {}, room=receiver_sid)
        emit('friend_list_updated', {}, room=request.sid) # For sender

    except Exception as e:
        print(f"❌ Backend: Error in send_friend_request: {str(e)}")
        emit('error', {'message': 'Server error sending friend request.'}, room=request.sid)

# --- NEW: accept_friend_request handler (matching frontend) ---
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

        # 1. Remove from acceptor's pending requests
        users_collection.update_one(
            {"username": acceptor},
            {"$pull": {"pending_requests": requester}}
        )

        # 2. Add each other to friends list (ensure public keys are passed)
        users_collection.update_one(
            {"username": acceptor},
            {"$addToSet": {"friends": {"username": requester, "public_key": requester_user['public_key']}}}
        )
        users_collection.update_one(
            {"username": requester},
            {"$addToSet": {"friends": {"username": acceptor, "public_key": acceptor_user['public_key']}}}
        )

        emit('friend_request_accepted', {'requester': requester}, room=request.sid) # Notify acceptor
        
        # Notify requester if online
        requester_sid = online_users_sockets.get(requester)
        if requester_sid:
            emit('friend_request_accepted', {'requester': acceptor}, room=requester_sid) # Notify requester
            print(f"Backend: Friend request from {requester} accepted by {acceptor} (requester online).")
        else:
            print(f"Backend: Friend request from {requester} accepted by {acceptor} (requester offline).")

        # Trigger frontend to refetch friends for both users involved
        emit('friend_list_updated', {}, room=request.sid)
        if requester_sid:
            emit('friend_list_updated', {}, room=requester_sid)

    except Exception as e:
        print(f"❌ Backend: Error in accept_friend_request: {str(e)}")
        emit('error', {'message': 'Server error accepting friend request.'}, room=request.sid)

# --- NEW: reject_friend_request handler (matching frontend) ---
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

        # Remove from rejecter's pending requests
        users_collection.update_one(
            {"username": rejecter},
            {"$pull": {"pending_requests": requester}}
        )

        emit('friend_request_rejected', {'rejecter': rejecter}, room=request.sid) # Notify rejecter
        
        # Notify requester if online
        requester_sid = online_users_sockets.get(requester)
        if requester_sid:
            emit('friend_request_rejected', {'rejecter': rejecter}, room=requester_sid) # Notify requester
            print(f"Backend: Friend request from {requester} rejected by {rejecter} (requester online).")
        else:
            print(f"Backend: Friend request from {requester} rejected by {rejecter} (requester offline).")
        
        # Trigger frontend to refetch friends for both users involved
        emit('friend_list_updated', {}, room=request.sid)
        if requester_sid:
            emit('friend_list_updated', {}, room=requester_sid)

    except Exception as e:
        print(f"❌ Backend: Error in reject_friend_request: {str(e)}")
        emit('error', {'message': 'Server error rejecting friend request.'}, room=request.sid)

# --- NEW: request_chat handler (matching frontend) ---
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

        # Check if they are friends
        if not any(f['username'] == receiver for f in sender_user.get('friends', [])):
            return emit('error', {'message': 'You are not friends with this user. Send a friend request first.'}, room=request.sid)

        # Determine a consistent room ID (e.g., sorted usernames)
        participants_sorted = sorted([sender, receiver])
        room_id = "_".join(participants_sorted)

        # Find or create chat room
        chat_room = chat_rooms_collection.find_one({"room_id": room_id})
        if not chat_room:
            chat_room = {
                "room_id": room_id,
                "participants": participants_sorted,
                "messages": []
            }
            chat_rooms_collection.insert_one(chat_room)
            print(f"Backend: Created new chat room: {room_id}")

        # Have both users join the specific Socket.IO room for this chat
        join_room(room_id) # Sender joins
        receiver_sid = online_users_sockets.get(receiver)
        if receiver_sid:
            socketio.emit('join_room', room_id, room=receiver_sid) # Instruct receiver to join room
            join_room(room_id, sid=receiver_sid) # Also join receiver's socket to room on backend
            print(f"Backend: {sender} and {receiver} joined room {room_id}")
        else:
            print(f"Backend: {sender} joined room {room_id}. {receiver} is offline.")


        # Send chat_approved back to the sender with room ID and history
        # History messages should be fetched and formatted correctly
        history_messages = chat_room.get('messages', [])
        
        emit('chat_approved', {
            'partner': receiver,
            'room': room_id,
            'history': history_messages # Send encrypted messages from DB
        }, room=request.sid)
        print(f"Backend: Chat approved for {sender} with {receiver} in room {room_id}. History sent.")

    except Exception as e:
        print(f"❌ Backend: Error in request_chat: {str(e)}")
        emit('error', {'message': 'Server error initiating chat.'}, room=request.sid)

# --- MODIFIED: send_message handler (matching frontend expectations) ---
@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('sender', '').strip() # Changed from_user to sender
    to_user = data.get('receiver', '').strip() # Added receiver
    room = data.get('room', '').strip()
    # Frontend now sends two encrypted messages: one for receiver, one for self
    message_for_receiver = data.get('messageForReceiver')
    message_for_self = data.get('messageForSelf')

    if not all([from_user, to_user, room, message_for_receiver, message_for_self]):
        print(f"Backend: send_message missing data: {data}")
        return emit('error', {'message': 'Missing data in send_message.'}, room=request.sid)

    try:
        # Update messages in the chat room document
        chat_rooms_collection.update_one(
            {"room_id": room},
            {"$push": {
                "messages": {
                    "sender": from_user,
                    # Store message encrypted for self (sender) for history retrieval
                    "message": message_for_self, 
                    "timestamp": datetime.datetime.utcnow().isoformat() # Use ISO format for consistency
                }
            }}
        )
        print(f"💬 Encrypted message from {from_user} to {to_user} in room {room} stored.")

        # Emit the message to the receiver in the room. 
        # Frontend will handle decryption based on whether it's sent or received.
        # We broadcast to the room, and the sender (who sent the message) also receives it
        # because the frontend expects it to display on its own side.
        emit('receive_message', {
            'sender': from_user,
            'message': message_for_receiver, # Send the message encrypted for the receiver
            'room': room,
            'timestamp': datetime.datetime.utcnow().isoformat()
        }, room=room, include_self=True) # include_self=True ensures sender also gets it for display

    except Exception as e:
        print(f"❌ Backend: Error in send_message: {str(e)}")
        emit('error', {'message': 'Server error sending message.'}, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    username = socket_id_to_username.get(sid)

    if username:
        # Remove from in-memory maps
        online_users_sockets.pop(username, None)
        socket_id_to_username.pop(sid, None)

        # Update socket_id in DB (set to None)
        users_collection.update_one(
            {"username": username},
            {"$unset": {"socket_id": ""}} # Or {"$set": {"socket_id": None}} if you prefer None
        )
        print(f"❌ User '{username}' (SID: {sid}) disconnected (socket_id removed from DB and in-memory maps).")
        
        # Notify all other clients that this user went offline
        current_online_users = list(online_users_sockets.keys())
        emit('online_users', current_online_users, broadcast=True)
        emit('user_disconnected', {'username': username}, broadcast=True) # Tell frontend who disconnected
    else:
        print(f"❌ Socket disconnected: {sid} (no associated user found or socket_id already removed).")


# No longer needed, CORS is applied by Flask-CORS directly
# @app.after_request
# def apply_cors(response):
#     response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin")
#     response.headers["Access-Control-Allow-Credentials"] = "true"
#     response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
#     response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
#     return response

if __name__ == '__main__':
    # Use allow_unsafe_werkzeug=True only for development, or ensure proper WSGI server in production
    socketio.run(app, host='0.0.0.0', port=PORT, debug=True, allow_unsafe_werkzeug=True) # Set debug=True for development to see more errors
