// script.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com";
console.log("Connecting to backend:", BASE_URL);

// Initialize Socket.IO connection
const socket = io(BASE_URL); // Connect to your backend Socket.IO server

/**
 * Displays a message in the authMessage element.
 * @param {string} message The message to display.
 * @param {boolean} isError True if it's an error message (red text), false otherwise (green text).
 */
function displayAuthMessage(message, isError = false) {
  const authMessageElement = document.getElementById("authMessage");
  authMessageElement.textContent = message;
  authMessageElement.style.color = isError ? "red" : "green";
  // Optionally, clear message after some time
  setTimeout(() => {
    authMessageElement.textContent = "";
  }, 5000);
}

// --- Event Listener for Socket.IO Connection ---
// This ensures that when the client successfully connects to the WebSocket,
// it registers the user with the backend, allowing the server to associate
// the user's username with their current socket ID in MongoDB.
socket.on('connect', () => {
  console.log("✅ Socket.IO connected with ID:", socket.id);
  // Ensure username is trimmed when retrieved from session storage for registration
  const username = sessionStorage.getItem("username")?.trim();
  if (username) {
    // Emit the register_user event to the backend
    socket.emit("register_user", { username: username });
    console.log(`Sending 'register_user' for: ${username}`);
  } else {
    console.log("No username found in sessionStorage to register upon connect.");
  }
});

socket.on('registered', (data) => {
  console.log("Backend registration confirmation:", data.message);
  // displayAuthMessage(data.message); // Not critical for login/register page
});

socket.on('error', (data) => {
  console.error("Backend error:", data.message);
  displayAuthMessage("Error: " + data.message, true);
});

// --- User Registration Function ---
async function registerUser() {
  // Trim username directly from input
  const username = document.getElementById("anonymousId").value.trim();
  const pin = document.getElementById("securePin").value;

  if (!username || !pin) {
    displayAuthMessage("Username and PIN are required.", true);
    return;
  }

  try {
    // Generate RSA key pair using SubtleCrypto
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true, // Can be extracted later for storage
      ["encrypt", "decrypt"]
    );

    // Export public key to PEM format (for sending to server)
    const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

    console.log("✅ Public Key PEM:\n", publicKeyPem);

    // Export private key to PKCS8 PEM and store in sessionStorage
    const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----`;

    sessionStorage.setItem("privateKey", privateKeyPem); // Store locally
    sessionStorage.setItem("username", username); // Ensure trimmed username is saved

    console.log("Registering user:", { username, pin, publicKeyPem });

    // Send public key to backend
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
      // Automatically log in after successful registration
      loginUser(username, pin);
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
  // Use provided username/pin or get from input fields, trim both
  const currentUsername = (username || document.getElementById("anonymousId").value).trim();
  const currentPin = (pin || document.getElementById("securePin").value); // PIN doesn't need trimming typically

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
      sessionStorage.setItem("username", currentUsername); // Ensure trimmed username is saved
      displayAuthMessage("✅ Login successful, redirecting...", false);
      window.location.href = "chat.html"; // Redirect on success
    } else {
      displayAuthMessage("Login failed: " + data.message, true);
    }
  } catch (error) {
    console.error("Error during login:", error);
    displayAuthMessage("Login failed: " + error.message, true);
  }
}
