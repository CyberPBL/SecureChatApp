from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

users = {}          # username: pin
messages = {}       # (user1, user2): list of messages
pending_requests = {}  # username: list of requesters

@app.route("/start-chat", methods=["POST"])
def start_chat():
    data = request.json
    username = data.get("username")
    pin = data.get("pin")

    if not username or not pin:
        return jsonify({"success": False, "message": "Username and PIN required"}), 400

    # Register user if not exists
    if username not in users:
        users[username] = pin
        pending_requests[username] = []
        return jsonify({"success": True, "message": "User registered successfully"})

    # Validate PIN
    if users[username] != pin:
        return jsonify({"success": False, "message": "Incorrect PIN"}), 401

    return jsonify({"success": True, "message": "Welcome back!"})

@app.route("/send-message", methods=["POST"])
def send_message():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    text = data.get("message")

    if not all([sender, receiver, text]):
        return jsonify({"success": False, "message": "Missing fields"}), 400

    if receiver not in users:
        return jsonify({"success": False, "message": "Receiver not found"}), 404

    key = tuple(sorted([sender, receiver]))
    if key not in messages:
        messages[key] = []

    messages[key].append({"sender": sender, "text": text})
    return jsonify({"success": True, "message": "Message sent"})

@app.route("/get-messages", methods=["POST"])
def get_messages():
    data = request.json
    user1 = data.get("user1")
    user2 = data.get("user2")

    if not all([user1, user2]):
        return jsonify([])

    key = tuple(sorted([user1, user2]))
    return jsonify(messages.get(key, []))

@app.route("/get-inbox", methods=["POST"])
def get_inbox():
    data = request.json
    username = data.get("username")

    if username not in pending_requests:
        return jsonify([])

    return jsonify(pending_requests[username])

@app.route("/accept-request", methods=["POST"])
def accept_request():
    data = request.json
    to_user = data.get("to")
    from_user = data.get("from")

    if not to_user or not from_user:
        return jsonify({"success": False, "message": "Invalid data"}), 400

    if to_user in pending_requests and from_user in pending_requests[to_user]:
        pending_requests[to_user].remove(from_user)
        return jsonify({"success": True})

    return jsonify({"success": False, "message": "Request not found"}), 404

@app.route("/request-chat", methods=["POST"])
def request_chat():
    data = request.json
    from_user = data.get("from")
    to_user = data.get("to")

    if to_user not in users:
        return jsonify({"success": False, "message": "User not found"}), 404

    if to_user not in pending_requests:
        pending_requests[to_user] = []

    if from_user not in pending_requests[to_user]:
        pending_requests[to_user].append(from_user)

    return jsonify({"success": True, "message": "Request sent"})

if __name__ == "__main__":
    app.run(debug=True)
