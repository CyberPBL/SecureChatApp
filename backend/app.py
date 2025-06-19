# --- Updated app.py with AES-GCM, secure scanning, case-insensitive search, and key logging ---

import eventlet
eventlet.monkey_patch()

print("Running app.py")

import os
import base64
import datetime
import re
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

try:
    from encryption import AesEncryption, RSAEncryption
except ImportError:
    print("CRITICAL ERROR: encryption.py not found or classes missing.")
    class AesEncryption:
        @staticmethod
        def encrypt(message, key): raise NotImplementedError("AES encryption not available.")
        @staticmethod
        def decrypt(encrypted_message, key): raise NotImplementedError("AES decryption not available.")
    class RSAEncryption:
        @staticmethod
        def generate_keys(): raise NotImplementedError("RSA key generation not available.")
        @staticmethod
        def encrypt_with_public_key(message, public_key_str): raise NotImplementedError("RSA encryption not available.")
        @staticmethod
        def decrypt_with_private_key(encrypted_message_b64, private_key_str): raise NotImplementedError("RSA decryption not available.")

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
DEBUG_MODE = os.getenv("DEBUG", "False").lower() == "true"
PORT = int(os.environ.get("PORT", 8000))

if not MONGO_URI:
    raise Exception("❌ MONGO_URI not set in .env file")

client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
client.admin.command('ping')
print("✅ Connected to MongoDB successfully!")

db = client["securechat_db"]
users_collection = db["users"]
messages_collection = db["messages"]

try:
    messages_collection.create_index("timestamp", expireAfterSeconds=86400)
    print("✅ TTL index created on messages_collection.")
except Exception as e:
    print(f"⚠️ TTL index creation failed: {e}")

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500", "https://securechat-frontend-9qs2.onrender.com"]}})

socketio = SocketIO(app, cors_allowed_origins=["http://127.0.0.1:5500", "http://localhost:5500", "https://securechat-frontend-9qs2.onrender.com"])

MALICIOUS_PATTERNS = [
    r"https?:\/\/(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|shorte\.st|adf\.ly|rebrand\.ly|cutt\.ly|buff\.ly|lnkd\.in|bl\.ink|trib\.al|snip\.ly|shorturl\.at|shrtco\.de|short\.cm|v\.gd|zi\.mu)",
    r"https?:\/\/.*\.(tk|ml|ga|cf|gq|xyz|top|club|pw|info)(\/|$)",
    r"https?:\/\/(?:000webhostapp\.com|weebly\.com|wixsite\.com|github\.io|firebaseapp\.com|pages\.dev)",
    r"https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
    r"<script.*?>.*?<\/script>",
    r"onerror\s*=",
    r"javascript:",
    r"data:text\/html",
    r"(login|verify|reset|account|bank|payment|alert).*(free|urgent|click|now|immediately)",
    r"https?:\/\/.*(?:paypal|google|facebook|instagram|microsoft|whatsapp)\.[^\.]+?\.(?:tk|ml|ga|cf|gq|xyz|top)",
    r"%[0-9a-f]{2}",
    r"[\u200B-\u200F\u202A-\u202E]",
]

def _scan_for_malicious_content(message_content):
    for pattern_str in MALICIOUS_PATTERNS:
        if re.search(pattern_str, message_content, re.IGNORECASE):
            print(f"🚨 Malicious content detected! Pattern: {pattern_str}")
            return True, pattern_str
    return False, None

@app.route('/search_user')
def search_user():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({"success": False, "message": "No query provided", "user": None})

    user_data = users_collection.find_one(
        {"username": {"$regex": f"^{re.escape(query)}$", "$options": "i"}},
        {"_id": 0, "username": 1, "socket_id": 1}
    )

    if user_data:
        is_online = user_data.get("socket_id") not in (None, "")
        return jsonify({
            "success": True,
            "user": {"username": user_data["username"], "is_online": is_online},
            "message": "User found." if is_online else "User found but offline."
        })
    else:
        return jsonify({"success": False, "message": "User not found."}), 404

@socketio.on('send_message')
def handle_send_message(data):
    from_user = data.get('from_user')
    to_user = data.get('to_user')
    encrypted_message = data.get('message')
    room = data.get('room')

    if not all([from_user, to_user, encrypted_message, room]):
        emit('error', {'message': 'Missing fields in message.'}, room=request.sid)
        return

    aes_key = data.get('aes_key')  # Optional: include key if needed for backend scan
    decrypted = ""
    try:
        if aes_key:
            decrypted = AesEncryption.decrypt(encrypted_message, aes_key)
            print(f"🔓 Decrypted message for scan: {decrypted[:50]}...")
        else:
            decrypted = encrypted_message  # fallback: scan encoded if key missing
    except Exception as e:
        print(f"❌ AES Decryption failed: {e}")
        decrypted = encrypted_message

    is_malicious, matched = _scan_for_malicious_content(decrypted)
    if is_malicious:
        print(f"🚨 Blocking message from {from_user} to {to_user}: {matched}")
        emit('malicious_message_blocked', {
            'from_user': from_user,
            'to_user': to_user,
            'message': "Blocked due to policy violation",
            'reason': matched
        }, room=request.sid)
        return

    messages_collection.insert_one({
        "from_user": from_user,
        "to_user": to_user,
        "message": encrypted_message,
        "room": room,
        "timestamp": datetime.datetime.utcnow(),
        "last_seen": None
    })
    socketio.emit('receive_message', {
        'username': from_user,
        'message': encrypted_message,
        'timestamp': datetime.datetime.utcnow().isoformat()
    }, room=room, include_self=True)
