
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os
import json

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # For testing only


USERS_FILE = 'users.json'

# Load users from file
def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            data = json.load(f)
            return data.get("users", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Save users to file
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump({"users": users}, f, indent=4)

# Initialize users_db from file
users_db = load_users()
chat_requests = {}  # {username: [requesters]}
chats = {}          # {sender: {receiver: [messages]}}

class AesEncryption:
    @staticmethod
    def encrypt(message, key):
        if len(key.encode()) not in {16, 24, 32}:
            raise ValueError("Invalid AES key length. Key must be 16, 24, or 32 bytes.")
        iv = os.urandom(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted_message).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_message, key):
        if len(key.encode()) not in {16, 24, 32}:
            raise ValueError("Invalid AES key length. Key must be 16, 24, or 32 bytes.")
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        encrypted_message = data[16:]
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        return decrypted_message.decode('utf-8')

@app.route('/check-user', methods=['POST'])
def check_user():
    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"exists": False, "message": "No username provided"}), 400
    return jsonify({"exists": username in users_db})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    hashed_pin = data.get('pin')  # Already hashed from frontend

    if not username or not hashed_pin:
        return jsonify({"success": False, "message": "Missing username or pin"}), 400

    if username in users_db:
        return jsonify({
            "success": False,
            "message": f"User already exists.",
        })

    users_db[username] = hashed_pin
    save_users(users_db)
    return jsonify({
        "success": True,
        "message": f"Registration successful! Welcome, {username}!",
        "is_new_user": True
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    hashed_pin = data.get('pin')

    if not username or not hashed_pin:
        return jsonify({"success": False, "message": "Missing username or pin"}), 400

    if username not in users_db:
        return jsonify({"success": False, "message": "User not registered."})

    if users_db[username] != hashed_pin:
        return jsonify({"success": False, "message": "Incorrect PIN."})

    return jsonify({"success": True, "message": f"Login successful! Welcome back, {username}!"})

@app.route('/request-chat', methods=['POST'])
def request_chat():
    data = request.get_json()
    from_user = data['from']
    to_user = data['to']
    if to_user not in users_db:
        return jsonify({"success": False, "message": "User not found."})
    if to_user not in chat_requests:
        chat_requests[to_user] = []
    chat_requests[to_user].append(from_user)
    return jsonify({"success": True, "message": "Chat request sent."})

@app.route('/accept-request', methods=['POST'])
def accept_request():
    data = request.get_json()
    to_user = data['to']
    from_user = data['from']
    if from_user not in chat_requests.get(to_user, []):
        return jsonify({"success": False, "message": "Request not found."})
    chat_requests[to_user].remove(from_user)
    if to_user not in chats:
        chats[to_user] = {}
    chats[to_user][from_user] = []
    return jsonify({"success": True, "message": "Chat request accepted."})

@app.route('/reject-request', methods=['POST'])
def reject_request():
    data = request.get_json()
    to_user = data['to']
    from_user = data['from']
    if from_user not in chat_requests.get(to_user, []):
        return jsonify({"success": False, "message": "Request not found."})
    chat_requests[to_user].remove(from_user)
    return jsonify({"success": True, "message": "Chat request rejected."})

@app.route('/get-inbox', methods=['POST'])
def get_inbox():
    data = request.get_json()
    username = data.get("username")
    if username not in users_db:
        return jsonify({"success": False, "message": "User not found"}), 404
    return jsonify({
        "success": True,
        "inbox": [{"from": requester} for requester in chat_requests.get(username, [])]
    })

@app.route('/send-message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender = data['sender']
    receiver = data['receiver']
    message = data['message']
    if receiver not in chats.get(sender, {}):
        return jsonify({"success": False, "message": "No chat found with this user."})
    chats[sender][receiver].append({"sender": sender, "message": message})
    if receiver not in chats:
        chats[receiver] = {}
    if sender not in chats[receiver]:
        chats[receiver][sender] = []
    chats[receiver][sender].append({"sender": sender, "message": message})
    return jsonify({"success": True, "message": "Message sent."})

@app.route('/get-messages', methods=['POST'])
def get_messages():
    data = request.get_json()
    user1 = data['user1']
    user2 = data['user2']
    if user1 not in chats or user2 not in chats[user1]:
        return jsonify({"success": False, "message": "No messages found."})
    return jsonify({"success": True, "messages": chats[user1][user2]})

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5000, debug=True)

