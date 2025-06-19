from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets  # <-- Use secrets for secure OTP
import time

app = Flask(__name__)  # <-- fixed here
CORS(app)  # Enable CORS for all routes

otp_store = {}

@app.route('/')
def home():
    return "OTP Backend server is running!" # Changed for clarity

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    # Generate a secure 6-digit OTP
    otp = secrets.randbelow(900000) + 100000  # generates from 100000 to 999999 inclusive
    timestamp = time.time()
    otp_store[username] = {'otp': otp, 'timestamp': timestamp}

    print(f"OTP for {username}: {otp}")  # For testing purposes - In production, send via email/SMS

    return jsonify({'message': f'OTP sent to {username}', 'otp': otp}) # otp included for dev testing

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    username = data.get('username')
    entered_otp = data.get('otp')

    if not username or not entered_otp:
        return jsonify({'error': 'Username and OTP are required'}), 400

    stored_data = otp_store.get(username)
    if not stored_data:
        return jsonify({'status': 'fail', 'message': 'OTP not found or expired (backend restart)'}), 401

    current_time = time.time()
    otp_time = stored_data['timestamp']
    otp_valid = (current_time - otp_time) <= 15  # 15 seconds validity

    # Remove OTP from store after successful verification or expiry to prevent reuse
    if otp_valid and str(stored_data['otp']) == str(entered_otp):
        del otp_store[username] # Remove after use
        return jsonify({'status': 'success', 'message': 'OTP verified successfully'})
    elif not otp_valid:
        if username in otp_store:
            del otp_store[username] # Remove expired OTP
        return jsonify({'status': 'fail', 'message': 'OTP expired'}), 401
    else:
        return jsonify({'status': 'fail', 'message': 'Invalid OTP'}), 401

if __name__ == '__main__':  # <-- fixed here
    app.run(debug=True, port=5001) # Assign a different port, e.g., 5001
