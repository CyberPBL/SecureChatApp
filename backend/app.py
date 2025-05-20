print("Running app.py")

import os
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"

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

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://securechat-frontend-9qs2.onrender.com"}})
socketio = SocketIO(app, cors_allowed_origins="https://securechat-frontend-9qs2.onrender.com")

# Track active users and their socket IDs
active_users = {}  # username -> sid

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

@app.route('/search_user')
def search_user():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({"success": False, "message": "No query provided", "users": []})
    results = list(users_collection.find({"username": query}, {"_id": 0, "username": 1}))
    return jsonify({"success": True, "users": results})

@socketio.on('connect')
def handle_connect():
    print('✅ Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    user_to_remove = None
    for username, user_sid in active_users.items():
        if user_sid == sid:
            user_to_remove = username
            break
    if user_to_remove:
        del active_users[user_to_remove]
        print(f"❌ User disconnected: {user_to_remove}")

@socketio.on('register_user')
def handle_register_user(data):
    username = data.get('username')
    if username:
        active_users[username] = request.sid
        print(f"🔵 User registered: {username} with SID: {request.sid}")
        emit('registered', {'message': f'User {username} registered successfully.'})
    else:
        emit('error', {'message': 'Username missing in registration.'})

@socketio.on('send_chat_request')
def handle_send_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    if not from_user or not to_user:
        emit('error', {'message': 'Missing from_user or to_user in chat request.'})
        return

    target_sid = active_users.get(to_user)
    if target_sid:
        emit('chat_request', {'from_user': from_user}, room=target_sid)
        print(f"📨 Chat request sent from {from_user} to {to_user}")
    else:
        emit('error', {'message': f'User {to_user} not online or does not exist.'})

@socketio.on('approve_chat_request')
def handle_approve_chat_request(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    approved = data.get('approved')

    if not from_user or not to_user or approved is None:
        emit('error', {'message': 'Missing from_user, to_user, or approved in approval request.'})
        return

    requester_sid = active_users.get(from_user)
    if requester_sid:
        emit('chat_request_approved', {'by_user': to_user, 'approved': approved}, room=requester_sid)
        print(f"✅ Chat request from {from_user} approved by {to_user}: {approved}")
    else:
        emit('error', {'message': f'User {from_user} not online or does not exist.'})

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    username = data.get('username')
    if room and username:
        join_room(room)
        print(f"{username} joined room {room}")
        emit('chat_approved', {'with': room.replace(username+'_', '').replace('_'+username, '')}, room=request.sid)
    else:
        emit('error', {'message': 'Missing room or username in join.'})

@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    message = data.get('message')
    room = data.get('room')

    if not all([from_user, to_user, message, room]):
        emit('error', {'message': 'Missing data in send_message.'})
        return

    print(f"Message from {from_user} to {to_user} in room {room}: {message}")

    emit('receive_message', {
        'username': from_user,
        'message': message
    }, room=room)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8000, debug=DEBUG_MODE)
