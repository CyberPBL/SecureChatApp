// script.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com";
console.log("Connecting to backend:", BASE_URL);

// Initialize Socket.IO connection (for login/registration purposes)
// Note: A separate socket connection will be managed in chat.js for chat functionality
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

// --- Event Listener for Socket.IO Connection ---
// This part is primarily for showing connection status on the login page,
// actual user registration/login is handled via HTTP fetch.
socket.on('connect', () => {
  console.log("✅ Socket.IO connected for auth with ID:", socket.id);
  // No need to emit 'register_user' here, as it's handled after successful login/registration.
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

    // Store private key and username in sessionStorage
    sessionStorage.setItem("privateKey", privateKeyPem);
    sessionStorage.setItem("username", username);

    console.log("Registering user:", { username, pin, publicKeyPem: publicKeyPem.substring(0, 50) + '...' });

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
      window.location.href = "chat.html"; // Redirect to chat page
    } else {
      displayAuthMessage("Login failed: " + data.message, true);
    (error) {
    console.error("Error during login:", error);
    displayAuthMessage("Login failed: " + error.message, true);
  }
}
