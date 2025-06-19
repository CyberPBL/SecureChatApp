# # otp_server.py

# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import secrets
# import time
# import os # Import os to get environment variables for CORS

# app = Flask(__name__)

# # Load environment variables for FRONTEND_URL to configure CORS securely
# # You might need a .env file for otp_server.py if it's deployed independently
# # For development, you can hardcode, but environment variables are better.
# load_dotenv() # Make sure to import load_dotenv if you're using it here
# FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500") # Default for local testing

# CORS(app, supports_credentials=True, resources={
#     r"/*": {
#         "origins": [
#             "http://127.0.0.1:5500",
#             "http://localhost:5500",
#             FRONTEND_URL # Ensure this matches your actual frontend URL when deployed
#         ]
#     }
# })

# otp_store = {} # In-memory store for OTPs. For production, consider a database.

# @app.route('/')
# def home():
#     return "OTP Backend server is running!"

# @app.route('/send_otp', methods=['POST'])
# def send_otp():
#     data = request.get_json()
#     username = data.get('username')
#     if not username:
#         return jsonify({'error': 'Username is required'}), 400

#     otp = secrets.randbelow(900000) + 100000
#     timestamp = time.time()
#     otp_store[username] = {'otp': otp, 'timestamp': timestamp}

#     print(f"OTP for {username}: {otp}") # IMPORTANT: In a real app, this OTP would be sent via email/SMS.

#     return jsonify({'message': f'OTP sent to {username}', 'otp': otp}) # otp is returned for testing purposes

# @app.route('/verify_otp', methods=['POST'])
# def verify_otp():
#     data = request.get_json()
#     username = data.get('username')
#     entered_otp = data.get('otp')

#     if not username or not entered_otp:
#         return jsonify({'error': 'Username and OTP are required'}), 400

#     stored_data = otp_store.get(username)
#     if not stored_data:
#         return jsonify({'status': 'fail', 'message': 'OTP not found or not sent'}), 401

#     current_time = time.time()
#     otp_time = stored_data['timestamp']
#     otp_validity_seconds = 15 # OTP valid for 15 seconds
#     otp_expired = (current_time - otp_time) > otp_validity_seconds

#     if str(stored_data['otp']) == str(entered_otp) and not otp_expired:
#         # Clear the OTP after successful verification to prevent reuse
#         del otp_store[username]
#         return jsonify({'status': 'success', 'message': 'OTP verified successfully'})
#     elif otp_expired:
#         # If expired, remove it from store
#         if username in otp_store:
#             del otp_store[username]
#         return jsonify({'status': 'fail', 'message': f'OTP expired. Valid for {otp_validity_seconds} seconds.'}), 401
#     else:
#         return jsonify({'status': 'fail', 'message': 'Invalid OTP'}), 401

# if __name__ == '__main__':
#     # You can set a specific port for the OTP server
#     OTP_PORT = int(os.environ.get("OTP_PORT", 5000)) # Default to 5000
#     app.run(host='0.0.0.0', port=OTP_PORT, debug=True)
