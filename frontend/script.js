// script.js (Auth/Login/Register File)

const BASE_URL = "https://securechatapp-ys8y.onrender.com";
console.log("Connecting to backend for auth operations:", BASE_URL);

// Initialize Socket.IO connection (mainly for status/error feedback on login page,
// a dedicated connection for chat is handled in chat.js)
const socket = io(BASE_URL);

/**
 * Displays a message in the authMessage element.
 * @param {string} message The message to display.
 * @param {boolean} isError True if it's an error message (red text), false otherwise (green text).
 */
function displayAuthMessage(message, isError = false) {
    const authMessageElement = document.getElementById("authMessage");
    authMessageElement.textContent = message;
    authMessageElement.style.color = isError ? "red" : "green";
    setTimeout(() => {
        authMessageElement.textContent = "";
    }, 5000);
}

// --- Event Listener for Socket.IO Connection (for auth page) ---
socket.on('connect', () => {
    console.log("✅ Socket.IO connected for auth with ID:", socket.id);
});

socket.on('error', (data) => {
    console.error("Backend error (auth):", data.message);
    displayAuthMessage("Error: " + data.message, true);
});

// --- User Registration Function ---
async function registerUser() {
    const username = document.getElementById("anonymousId").value.trim();
    const pin = document.getElementById("securePin").value;

    if (!username || !pin) {
        displayAuthMessage("Username and PIN are required.", true);
        return;
    }

    try {
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

        console.log("✅ Public Key PEM (first 50 chars):\n", publicKeyPem.substring(0, 50) + '...');

        const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));
        const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----`;

        // Store private key, username, AND PUBLIC KEY in sessionStorage for later use in chat.js
        sessionStorage.setItem("privateKey", privateKeyPem);
        sessionStorage.setItem("username", username);
        sessionStorage.setItem("publicKey", publicKeyPem); // <<< ADDED THIS LINE <<<

        console.log("Attempting to register user:", { username, publicKeyPem: publicKeyPem.substring(0, 50) + '...' });

        const res = await fetch(`${BASE_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                pin,
                publicKey: publicKeyPem
            })
        });

        const data = await res.json();
        if (data.success) {
            displayAuthMessage("✅ Registered successfully", false);
            loginUser(username, pin); // Automatically log in after successful registration
        } else {
            displayAuthMessage("❌ " + data.message, true);
        }
    } catch (error) {
        console.error("Error during registration:", error);
        displayAuthMessage("❌ Registration failed: " + error.message, true);
    }
}

// --- User Login Function ---
async function loginUser(username = null, pin = null) {
    const currentUsername = (username || document.getElementById("anonymousId").value).trim();
    const currentPin = (pin || document.getElementById("securePin").value);

    if (!currentUsername || !currentPin) {
        displayAuthMessage("Username and PIN are required.", true);
        return;
    }

    try {
        const res = await fetch(`${BASE_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: currentUsername, pin: currentPin })
        });

        const data = await res.json();
        if (data.success) {
            sessionStorage.setItem("username", currentUsername);
            displayAuthMessage("✅ Login successful, redirecting...", false);

            // Fetch current user's public key from backend if not in session storage (e.g., new device login, or browser cleared session)
            const storedPublicKey = sessionStorage.getItem("publicKey");
            if (!storedPublicKey) {
                console.log("Fetching own public key after login...");
                const pkRes = await fetch(`${BASE_URL}/get_public_key?username=${currentUsername}`);
                const pkData = await pkRes.json();
                if (pkData.success) {
                    sessionStorage.setItem("publicKey", pkData.public_key);
                    console.log("Fetched and stored own public key.");
                } else {
                    console.warn("Could not fetch own public key after login:", pkData.message);
                    // This might cause issues with encrypting messages for self, as a fallback,
                    // consider warning the user or gracefully degrading functionality.
                }
            }

            window.location.href = "chat.html"; // Redirect to chat page
        } else {
            displayAuthMessage("Login failed: " + data.message, true);
        }
    } catch (error) {
        console.error("Error during login:", error);
        displayAuthMessage("Login failed: " + error.message, true);
    }
}
