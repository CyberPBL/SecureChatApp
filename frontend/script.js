// auth.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com"; // Your Render backend URL

// DOM Elements for Auth
const authContainer = document.getElementById("authContainer");
const chatContainer = document.getElementById("chatContainer");

const loginTab = document.getElementById("loginTab");
const registerTab = document.getElementById("registerTab");
const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");

const loginUsernameInput = document.getElementById("loginUsername");
const loginPinInput = document.getElementById("loginPin");
const loginMessage = document.getElementById("loginMessage");

const registerUsernameInput = document.getElementById("registerUsername");
const registerPinInput = document.getElementById("registerPin");
const confirmPinInput = document.getElementById("confirmPin");
const registerMessage = document.getElementById("registerMessage");

// --- Tab Switching ---
loginTab.addEventListener("click", () => {
    loginTab.classList.add("active");
    registerTab.classList.remove("active");
    loginForm.classList.add("active");
    registerForm.classList.remove("active");
    loginMessage.textContent = ""; // Clear messages
    registerMessage.textContent = "";
});

registerTab.addEventListener("click", () => {
    registerTab.classList.add("active");
    loginTab.classList.remove("active");
    registerForm.classList.add("active");
    loginForm.classList.remove("active");
    loginMessage.textContent = ""; // Clear messages
    registerMessage.textContent = "";
});

// --- Utility Functions for Key Management ---

async function generateKeyPair() {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );
}

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    const pem = arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${pem}\n-----END PUBLIC KEY-----`;
}

async function exportPrivateKey(key) {
    const exported = await window.crypto.subtle.exportKey("pkcs8", key);
    const pem = arrayBufferToBase64(exported);
    return `-----BEGIN PRIVATE KEY-----\n${pem}\n-----END PRIVATE KEY-----`;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).match(/.{1,64}/g).join('\n'); // Format for PEM
}

function displayAuthMessage(element, message, isError = false) {
    element.textContent = message;
    element.className = "message " + (isError ? "error" : "success");
}

// --- Registration Logic ---
async function registerUser() {
    const username = registerUsernameInput.value.trim();
    const pin = registerPinInput.value.trim();
    const confirmPin = confirmPinInput.value.trim();

    if (!username || !pin || !confirmPin) {
        displayAuthMessage(registerMessage, "All fields are required.", true);
        return;
    }

    if (pin.length < 4 || pin.length > 6 || !/^\d+$/.test(pin)) {
        displayAuthMessage(registerMessage, "PIN must be 4-6 digits.", true);
        return;
    }

    if (pin !== confirmPin) {
        displayAuthMessage(registerMessage, "PINs do not match.", true);
        return;
    }

    displayAuthMessage(registerMessage, "Generating cryptographic keys... Please wait.", false);

    try {
        const keyPair = await generateKeyPair();
        const publicKeyPem = await exportPublicKey(keyPair.publicKey);
        const privateKeyPem = await exportPrivateKey(keyPair.privateKey);

        const response = await fetch(`${BASE_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, pin, publicKey: publicKeyPem })
        });

        const data = await response.json();

        if (data.success) {
            displayAuthMessage(registerMessage, data.message, false);
            // Store keys in localStorage upon successful registration
            localStorage.setItem("username", username);
            localStorage.setItem("privateKey", privateKeyPem);
            localStorage.setItem("publicKey", publicKeyPem);

            // Automatically switch to chat view after successful registration
            setTimeout(() => {
                checkLoginStatus(); // Will load chat.js logic
            }, 1000);

        } else {
            displayAuthMessage(registerMessage, data.message, true);
        }
    } catch (error) {
        console.error("Registration error:", error);
        displayAuthMessage(registerMessage, "Registration failed: " + error.message, true);
    }
}

// --- Login Logic ---
async function loginUser() {
    const username = loginUsernameInput.value.trim();
    const pin = loginPinInput.value.trim();

    if (!username || !pin) {
        displayAuthMessage(loginMessage, "Username and PIN are required.", true);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, pin })
        });

        const data = await response.json();

        if (data.success) {
            // Fetch public key for the logged-in user to store it
            const keyResponse = await fetch(`${BASE_URL}/get_public_key?username=${username}`);
            const keyData = await keyResponse.json();

            if (keyData.success) {
                // For login, we need to ensure the client has their private key.
                // In this demo, we assume it's in localStorage from a previous registration.
                // If it's missing, the user will be prompted to re-register.

                const privateKeyFromStorage = localStorage.getItem("privateKey");

                if (!privateKeyFromStorage) {
                    displayAuthMessage(loginMessage, "Private key missing. Please register or re-register to generate keys.", true);
                    console.error("Private key not found in localStorage after login attempt.");
                    return; // Abort login if private key is not found
                }

                localStorage.setItem("username", username);
                localStorage.setItem("publicKey", keyData.public_key);
                // privateKeyPem is already in localStorage from initial registration/key gen

                displayAuthMessage(loginMessage, data.message, false);
                // Redirect to chat or show chat UI
                setTimeout(() => {
                    checkLoginStatus(); // Will load chat.js logic
                }, 1000);

            } else {
                displayAuthMessage(loginMessage, "Failed to retrieve public key. Please try again.", true);
            }
        } else {
            displayAuthMessage(loginMessage, data.message, true);
        }
    } catch (error) {
        console.error("Login error:", error);
        displayAuthMessage(loginMessage, "Login failed: " + error.message, true);
    }
}

// --- Check Login Status on Page Load ---
function checkLoginStatus() {
    const currentUser = localStorage.getItem("username");
    const privateKeyPem = localStorage.getItem("privateKey");
    const publicKeyPem = localStorage.getItem("publicKey");

    if (currentUser && privateKeyPem && publicKeyPem) {
        authContainer.style.display = "none";
        chatContainer.style.display = "flex";
        // chat.js will then initialize using these localStorage values
    } else {
        authContainer.style.display = "block";
        chatContainer.style.display = "none";
        displayAuthMessage(loginMessage, "You are not logged in or missing cryptographic keys. Please log in first.", true);
    }
}

// --- Logout Function (also in chat.js) ---
function logout() {
    localStorage.removeItem("username");
    localStorage.removeItem("privateKey");
    localStorage.removeItem("publicKey");
    // Reload the page to reset the app state
    window.location.reload();
}

// Initial check when the script loads
document.addEventListener("DOMContentLoaded", checkLoginStatus);
