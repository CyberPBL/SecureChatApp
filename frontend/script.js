// script.js (Auth/Login/Register File)

const CHAT_BACKEND_URL = "https://securechatapp-ys8y.onrender.com";
const OTP_BACKEND_URL = "http://localhost:5000"; // IMPORTANT: Set this to your OTP server's URL/port

console.log("Connecting to chat backend for auth operations:", CHAT_BACKEND_URL);
console.log("Connecting to OTP backend:", OTP_BACKEND_URL);

// Initialize Socket.IO connection (for general auth page feedback, not main chat)
const socket = io(CHAT_BACKEND_URL);

// --- Utility function to display messages ---
function displayMessage(elementId, message, isError = false) {
    const messageElement = document.getElementById(elementId);
    if (messageElement) {
        messageElement.textContent = message;
        messageElement.style.color = isError ? "red" : "green";
        setTimeout(() => {
            messageElement.textContent = "";
        }, 5000);
    }
}

// --- Socket.IO Event Listener (for auth page) ---
socket.on('connect', () => {
    console.log("✅ Socket.IO connected for auth with ID:", socket.id);
});

socket.on('error', (data) => {
    console.error("Backend error (auth):", data.message);
    displayMessage("loginMessage", "Error: " + data.message, true); // Use loginMessage for general errors
});

// --- User Login Function (Updated to use new IDs from index.html) ---
async function loginUser() {
    const username = document.getElementById("loginUsername").value.trim();
    const pin = document.getElementById("loginPin").value;

    if (!username || !pin) {
        displayMessage("loginMessage", "Username and PIN are required.", true);
        return;
    }

    try {
        const res = await fetch(`${CHAT_BACKEND_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: username, pin: pin })
        });

        const data = await res.json();
        if (data.success) {
            sessionStorage.setItem("username", username);
            displayMessage("loginMessage", "✅ Login successful, redirecting...", false);

            // Fetch current user's public key from backend if not in session storage
            // This is crucial for later chat encryption if the user logs in from a new device/browser
            const storedPublicKey = sessionStorage.getItem("publicKey");
            if (!storedPublicKey) {
                console.log("Fetching own public key after login...");
                const pkRes = await fetch(`${CHAT_BACKEND_URL}/get_public_key?username=${username}`);
                const pkData = await pkRes.json();
                if (pkData.success) {
                    sessionStorage.setItem("publicKey", pkData.public_key);
                    console.log("Fetched and stored own public key.");
                    // You might also need to fetch and store the PRIVATE KEY here if it's not present.
                    // This is a critical security point: private keys should ideally *never* leave the user's device.
                    // If you're regenerating on login, ensure the user understands and it's a fresh key pair.
                    // For typical secure messaging, the private key is generated once and persists client-side.
                    // If you *don't* store privateKey in sessionStorage, then a user logging in on a new device
                    // will generate a *new* key pair, which means they won't be able to decrypt *old* messages
                    // encrypted with their *old* public key. This is a design choice.
                } else {
                    console.warn("Could not fetch own public key after login:", pkData.message);
                    displayMessage("loginMessage", "Warning: Could not load your public key. Chat functionality might be limited.", true);
                }
            }

            window.location.href = "chat.html"; // Redirect to chat page
        } else {
            displayMessage("loginMessage", "Login failed: " + data.message, true);
        }
    } catch (error) {
        console.error("Error during login:", error);
        displayMessage("loginMessage", "Login failed: " + error.message, true);
    }
}

// --- NEW: OTP-based Registration Functions ---

// Event listener for "Send OTP" button
document.addEventListener('DOMContentLoaded', () => {
    const sendOtpBtn = document.getElementById('sendOtpBtn');
    const verifyAndRegisterBtn = document.getElementById('verifyAndRegisterBtn');
    const otpInput = document.getElementById('otpInput');

    if (sendOtpBtn) {
        sendOtpBtn.addEventListener('click', async () => {
            const username = document.getElementById('registerUsernameOTP').value.trim();
            if (!username) {
                displayMessage('otpMessage', 'Please enter a username for registration.', true);
                return;
            }

            displayMessage('otpMessage', 'Sending OTP...', false);
            sendOtpBtn.disabled = true; // Disable to prevent multiple sends

            try {
                const response = await fetch(`${OTP_BACKEND_URL}/send_otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });
                const data = await response.json();

                if (response.ok) {
                    displayMessage('otpMessage', data.message + ` (OTP: ${data.otp})`, false); // Show OTP for testing
                    otpInput.removeAttribute('disabled');
                    verifyAndRegisterBtn.removeAttribute('disabled');
                    // Consider a timer to re-enable sendOtpBtn if OTP not received
                } else {
                    displayMessage('otpMessage', data.error || 'Failed to send OTP.', true);
                    sendOtpBtn.disabled = false; // Re-enable if failed
                }
            } catch (error) {
                console.error('Error sending OTP:', error);
                displayMessage('otpMessage', 'Network error or OTP server unavailable.', true);
                sendOtpBtn.disabled = false; // Re-enable if network error
            }
        });
    }

    // Event listener for "Verify OTP & Register" button
    if (verifyAndRegisterBtn) {
        verifyAndRegisterBtn.addEventListener('click', async () => {
            const username = document.getElementById('registerUsernameOTP').value.trim();
            const pin = document.getElementById('registerPinOTP').value;
            const enteredOtp = document.getElementById('otpInput').value.trim();

            if (!username || !pin || !enteredOtp) {
                displayMessage('otpMessage', 'Please fill all registration fields.', true);
                return;
            }

            displayMessage('otpMessage', 'Verifying OTP...', false);
            verifyAndRegisterBtn.disabled = true; // Disable during verification

            try {
                // Step 1: Verify OTP with OTP Backend
                const verifyResponse = await fetch(`${OTP_BACKEND_URL}/verify_otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, otp: enteredOtp })
                });
                const verifyData = await verifyResponse.json();

                if (!verifyResponse.ok || verifyData.status === 'fail') {
                    displayMessage('otpMessage', verifyData.message || 'OTP verification failed.', true);
                    verifyAndRegisterBtn.disabled = false; // Re-enable to allow retrying
                    return;
                }

                // Step 2: OTP Verified, now proceed with RSA Key Generation and User Registration
                displayMessage('otpMessage', 'OTP Verified! Generating keys and registering user...', false);

                const keyPair = await window.crypto.subtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: "SHA-256"
                    },
                    true, // extractable
                    ["encrypt", "decrypt"]
                );

                const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
                const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
                const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

                const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
                const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));
                const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----`;

                // Store private key, username, and public key in sessionStorage
                sessionStorage.setItem("privateKey", privateKeyPem);
                sessionStorage.setItem("username", username);
                sessionStorage.setItem("publicKey", publicKeyPem);

                // Step 3: Register user with Chat Backend (including public key)
                const registerResponse = await fetch(`${CHAT_BACKEND_URL}/register`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        username: username,
                        pin: pin,
                        publicKey: publicKeyPem
                    })
                });
                const registerData = await registerResponse.json();

                if (registerData.success) {
                    displayMessage('otpMessage', registerData.message + ". You can now log in.", false);
                    // Clear form and disable OTP related fields after successful registration
                    document.getElementById('registerUsernameOTP').value = '';
                    document.getElementById('registerPinOTP').value = '';
                    otpInput.value = '';
                    otpInput.disabled = true;
                    sendOtpBtn.disabled = false; // Re-enable send OTP for next registration
                    verifyAndRegisterBtn.disabled = true;
                    // Optionally, automatically log in or redirect to login page
                    // loginUser(username, pin); // You could uncomment this if you want auto-login
                } else {
                    displayMessage('otpMessage', registerData.message, true);
                    verifyAndRegisterBtn.disabled = false; // Allow retrying if registration failed after OTP
                }
            } catch (error) {
                console.error('Error during OTP verification or registration:', error);
                displayMessage('otpMessage', 'Network error or server issue during registration.', true);
                verifyAndRegisterBtn.disabled = false; // Allow retrying
            }
        });
    }
});
