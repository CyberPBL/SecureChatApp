from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Store messages in memory (temporary)
messages = []

@app.route("/start-chat", methods=["POST"])
def start_chat():
    data = request.json
    username = data.get("username")
    pin = data.get("pin")

    if not username or not pin:
        return jsonify({"success": False, "message": "Missing credentials"}), 400

    return jsonify({"success": True, "message": f"Hello {username}, chat session initiated!"})

@app.route("/send-message", methods=["POST"])
def send_message():
    data = request.json
    username = data.get("username")
    message = data.get("message")

    if not username or not message:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    messages.append({"user": username, "text": message})
    return jsonify({"success": True})

@app.route("/get-messages", methods=["GET"])
def get_messages():
    return jsonify(messages)
    
if __name__ == "__main__":
    app.run(debug=True)
