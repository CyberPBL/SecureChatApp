// chat.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com"; // Ensure this matches your backend URL
const socket = io(BASE_URL);

// --- Global Chat Variables ---
let currentRoom = null;
let chattingWith = null;
let currentChatKey = null; // This will be set dynamically via secure key exchange

// --- DOM Elements ---
const chatBox = document.getElementById("chatBox");
const messageInput = document.getElementById("messageInput");
const userNameDisplay = document.getElementById("userNameDisplay");
const searchMessage = document.getElementById("searchMessage");
const searchUserInput = document.getElementById("searchUser");

// --- Utility Functions ---

/**
 * Displays a message in the chat box or as a system notification.
 * @param {string} message The message content.
 * @param {string} type 'system', 'sent', 'received', 'error', 'info'.
 */
function displayChatMessage(message, type = 'info') {
  const msgDiv = document.createElement("div");
  msgDiv.classList.add('chat-message', type);
  msgDiv.textContent = message;
  chatBox.appendChild(msgDiv);
  chatBox.scrollTop = chatBox.scrollHeight; // Auto-scroll to bottom
}

// AES Encryption Utility (client-side implementation using Web Crypto API)
class AesEncryption {
  static async encrypt(message, keyBase64) { // Expects Base64 key string
    // Decode Base64 key string back to Uint8Array
    const keyBytes = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));

    if (![16, 24, 32].includes(keyBytes.byteLength)) {
      throw new Error("AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits).");
    }

    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    const encodedMessage = new TextEncoder().encode(message);

    const importedKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes, // Use the decoded key bytes here
      { name: "AES-CBC" },
      false,
      ["encrypt"]
    );

    const encryptedBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-CBC", iv: iv },
      importedKey,
      encodedMessage
    );

    const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encryptedBuffer), iv.length);

    return btoa(String.fromCharCode(...combined));
  }

  static async decrypt(encryptedBase64, keyBase64) { // Expects Base64 key string
    // Decode Base64 key string back to Uint8Array
    const keyBytes = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));

    if (![16, 24, 32].includes(keyBytes.byteLength)) {
      throw new Error("AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits).");
    }

    const decoded = atob(encryptedBase64);
    const combined = new Uint8Array([...decoded].map(char => char.charCodeAt(0)));

    const iv = combined.slice(0, 16);
    const encryptedData = combined.slice(16);

    const importedKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes, // Use the decoded key bytes here
      { name: "AES-CBC" },
      false,
      ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-CBC", iv: iv },
      importedKey,
      encryptedData
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  static async generateRandomAesKey() {
    const key = await window.crypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256, // 256 bits = 32 bytes
      },
      true, // extractable
      ["encrypt", "decrypt"]
    );
    // Export it as raw bytes and then base64 encode for easy string transmission
    const exportedKey = await window.crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
  }
}

async function fetchPublicKey(username) {
  try {
    const response = await fetch(`${BASE_URL}/get_public_key?username=${encodeURIComponent(username)}`);
    const data = await response.json();
    if (data.success) {
      const pem = data.public_key;
      const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
      const binaryDer = atob(b64);
      const buffer = new Uint8Array([...binaryDer].map(ch => ch.charCodeAt(0))).buffer;
      return await window.crypto.subtle.importKey(
        "spki",
        buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
      );
    } else {
      displayChatMessage("❌ Couldn't fetch public key for " + username + ": " + data.message, 'error');
      return null;
    }
  } catch (error) {
    console.error("Error fetching public key:", error);
    displayChatMessage("❌ Error fetching public key: " + error.message, 'error');
    return null;
  }
}

async function getMyPrivateKey() {
  const privateKeyPem = sessionStorage.getItem("privateKey");
  if (!privateKeyPem) {
    displayChatMessage("❌ Private key not found in sessionStorage. Please log in again.", 'error');
    console.error("Private key PEM not found in sessionStorage.");
    return null;
  }
  try {
    const b64 = privateKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const binaryDer = atob(b64);
    const buffer = new Uint8Array([...binaryDer].map(ch => ch.charCodeAt(0))).buffer;

    const importedKey = await window.crypto.subtle.importKey(
      "pkcs8",
      buffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );
    console.log("✅ Successfully imported private key.");
    return importedKey;
  } catch (error) {
    console.error("❌ Error importing private key from PEM:", error);
    displayChatMessage("❌ Error importing private key. Possible corruption. Please re-register.", 'error');
    return null;
  }
}

function generateRoomName(user1, user2) {
  return [user1, user2].sort().join("_");
}

// --- User Authentication and Setup ---
const username = sessionStorage.getItem("username");
if (!username) {
  displayChatMessage("You are not logged in. Please log in.", 'error');
  window.location.href = "index.html";
} else {
  userNameDisplay.textContent = username;
}

// --- Socket.IO Event Listeners ---
socket.on('connect', () => {
  console.log("✅ Socket.IO connected with ID:", socket.id);
  socket.emit("register_user", { username: username });
});

socket.on('registered', (data) => {
  console.log("Backend registration confirmation:", data.message);
  displayChatMessage(data.message, 'info');
  socket.emit('get_online_users');
});

socket.on('online_users', (data) => {
  console.log('Online users:', data.users);
});

socket.on('error', (data) => {
  console.error("Backend error:", data.message);
  displayChatMessage("Error: " + data.message, 'error');
});

socket.on("chat_request", (data) => {
  const fromUser = data.from_user;
  const accept = confirm(`🔔 ${fromUser} wants to chat with you. Accept?`);
  socket.emit("approve_chat_request", {
    from_user: fromUser,
    to_user: username,
    approved: accept
  });

  if (accept) {
    const roomName = generateRoomName(username, fromUser);
    currentRoom = roomName;
    chattingWith = fromUser;
    socket.emit("join", { room: roomName, username });
    // As the accepter, you wait for the requester to send the encrypted AES key.
  }
});

socket.on("chat_request_approved", async (data) => {
  if (data.approved) {
    const roomName = generateRoomName(username, data.by_user);
    currentRoom = roomName;
    chattingWith = data.by_user;
    socket.emit("join", { room: roomName, username });
    // If I initiated the request and it's approved, I generate and send the AES key
    await generateAndSendAesKey(chattingWith);
  } else {
    displayChatMessage(`${data.by_user} rejected your chat request.`, 'info');
    chattingWith = null;
    currentRoom = null;
    currentChatKey = null;
  }
});

socket.on('receive_aes_key_encrypted', async (data) => {
  console.log("🔑 Received encrypted AES key event.");
  try {
    const encryptedAesKey = data.encrypted_aes_key;
    const sender = data.from_user;

    console.log("Received encrypted AES Key (Base64):", encryptedAesKey);

    const privateKey = await getMyPrivateKey();
    if (!privateKey) {
      displayChatMessage("❌ Failed to get private key for AES key decryption.", 'error');
      console.error("Private key not available to decrypt received AES key.");
      currentChatKey = null; // Ensure no key is used if private key is missing
      return;
    }
    console.log("Private key retrieved:", privateKey);


    // Decrypt the AES key using my RSA private key
    const encryptedKeyBuffer = Uint8Array.from(atob(encryptedAesKey), c => c.charCodeAt(0));
    console.log("Encrypted AES Key Buffer length for decryption:", encryptedKeyBuffer.byteLength);

    const decryptedAesKeyBytes = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedKeyBuffer
    );

    currentChatKey = new TextDecoder().decode(decryptedAesKeyBytes);
    console.log("🔑 Decrypted AES Key (for chat):", currentChatKey); // This should be a readable string
    displayChatMessage(`🔑 Secure chat established with ${sender}. You can now send encrypted messages!`, 'info');

    socket.emit('aes_key_received', {
      from_user: username,
      to_user: sender,
      room: currentRoom,
      status: 'success'
    });

  } catch (error) {
    console.error("❌ Error during receive_aes_key_encrypted (decryption failed):", error);
    displayChatMessage("❌ Failed to establish secure key. Messages will not be encrypted. Check console for details.", 'error');
    currentChatKey = null; // Ensure no key is used if decryption fails
  }
});

socket.on('aes_key_received', (data) => {
  if (data.status === 'success') {
    displayChatMessage(`🔑 ${data.from_user} has received and decrypted the chat key. Secure chat ready!`, 'info');
    console.log(`AES key receipt confirmed by ${data.from_user}.`);
  } else {
    displayChatMessage(`❌ ${data.from_user} failed to receive/decrypt chat key.`, 'error');
    console.error(`AES key receipt failed from ${data.from_user}.`);
  }
});

socket.on("chat_approved", (data) => {
  const chatPartner = data.with;
  currentRoom = data.room;
  console.log(`Chat approved with: ${chatPartner} in room: ${currentRoom}`);
  displayChatMessage(`Chat started with ${chatPartner}.`, 'info');

  searchUserInput.value = "";
  searchMessage.textContent = "";
});

socket.on('chat_history', async (data) => {
  console.log("Received chat history:", data.history);
  chatBox.innerHTML = ''; // Clear current messages before loading history
  if (data.history && data.history.length > 0) {
    displayChatMessage("--- Chat History ---", 'info');
    for (const msg of data.history) {
      try {
        // Ensure currentChatKey is available before attempting to decrypt history
        if (!currentChatKey) {
            displayChatMessage("❌ Cannot decrypt history: Secure key not established.", 'error');
            break; // Stop trying to decrypt history
        }
        const decryptedMessage = await AesEncryption.decrypt(msg.message, currentChatKey);
        const sender = msg.from_user === username ? 'You' : msg.from_user;
        displayChatMessage(`${sender}: ${decryptedMessage}`, msg.from_user === username ? 'sent' : 'received');
      } catch (e) {
        console.error("Error decrypting history message:", e);
        const sender = msg.from_user === username ? 'You' : msg.from_user;
        displayChatMessage(`${sender}: 🔒 (Unable to decrypt history message)`, msg.from_user === username ? 'sent' : 'received');
      }
    }
    displayChatMessage("--- End History ---", 'info');
  } else {
    displayChatMessage("No chat history found for this conversation.", 'info');
  }
});

socket.on("receive_message", async (data) => {
  try {
    const encryptedMessage = data.message;
    const senderUsername = data.username;

    if (!currentChatKey) {
      displayChatMessage(`${senderUsername}: 🔒 (No shared key to decrypt message)`, 'error');
      return;
    }

    const decryptedMessage = await AesEncryption.decrypt(encryptedMessage, currentChatKey);
    displayChatMessage(`${senderUsername}: ${decryptedMessage}`, senderUsername === username ? 'sent' : 'received');
  } catch (e) {
    console.error("❌ Decryption failed", e);
    displayChatMessage(`${data.username}: 🔒 (Unable to decrypt message)`, 'error');
  }
});


// --- Functions to Trigger Actions ---

function searchUser() {
  const searchUsername = searchUserInput.value.trim();
  const currentUser = sessionStorage.getItem("username");

  if (!searchUsername) {
    searchMessage.textContent = "Please enter a username to search.";
    return;
  }

  if (searchUsername === currentUser) {
      searchMessage.textContent = "You cannot chat with yourself.";
      return;
  }

  fetch(`${BASE_URL}/search_user?query=${encodeURIComponent(searchUsername)}`)
    .then(res => res.json())
    .then(data => {
      if (data.success && data.user) {
        if (data.user.is_online) {
          socket.emit("send_chat_request", {
            from_user: currentUser,
            to_user: data.user.username
          });
          searchMessage.textContent = `📨 Request sent to ${data.user.username}! Waiting for approval...`;
          chattingWith = data.user.username;
        } else {
          searchMessage.textContent = `❌ ${data.user.username} is registered but currently offline.`;
        }
      } else {
        searchMessage.textContent = data.message || "❌ User not found.";
      }
    })
    .catch(error => {
      console.error("Error searching user:", error);
      searchMessage.textContent = "Error searching user. Check console for details.";
    });
}

async function generateAndSendAesKey(recipientUsername) {
  console.log("🔑 Generating and sending AES key to:", recipientUsername);
  try {
    const newAesKey = await AesEncryption.generateRandomAesKey();
    currentChatKey = newAesKey; // Set my current chat key

    console.log("Generated new AES Key (Base64):", newAesKey);

    const recipientPublicKey = await fetchPublicKey(recipientUsername);
    if (!recipientPublicKey) {
      displayChatMessage("❌ Could not get recipient's public key to exchange AES key.", 'error');
      currentChatKey = null; // Clear key if cannot send
      console.error("Recipient public key not found.");
      return;
    }
    console.log("Recipient Public Key imported:", recipientPublicKey);

    const encoder = new TextEncoder();
    const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      recipientPublicKey,
      encoder.encode(newAesKey)
    );
    const encryptedAesKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAesKeyBuffer)));
    console.log("🔑 Encrypted AES Key (Base64 for transport):", encryptedAesKeyBase64);


    socket.emit('send_aes_key_encrypted', {
      from_user: username,
      to_user: recipientUsername,
      encrypted_aes_key: encryptedAesKeyBase64
    });

    displayChatMessage(`🔑 Initiated secure key exchange with ${recipientUsername}.`, 'info');

  } catch (error) {
    console.error("❌ Error during AES key generation/encryption/sending:", error);
    displayChatMessage("❌ Failed to initiate secure key exchange.", 'error');
    currentChatKey = null;
  }
}

async function sendMessage() {
  const message = messageInput.value;
  if (!message.trim() || !currentRoom || !chattingWith) {
    displayChatMessage("Please type a message and ensure you are in a chat.", 'info');
    return;
  }

  if (!currentChatKey) {
    displayChatMessage("❌ No secure chat key established. Messages cannot be sent encrypted.", 'error');
    return;
  }

  try {
    const encryptedBase64 = await AesEncryption.encrypt(message, currentChatKey);

    displayChatMessage(`You: ${message}`, 'sent');

    socket.emit("send_message", {
      from_user: username,
      to_user: chattingWith,
      message: encryptedBase64,
      room: currentRoom
    });

    messageInput.value = "";
  } catch (error) {
    console.error("❌ Message encryption/sending failed:", error);
    displayChatMessage("❌ Failed to send message: " + error.message, 'error');
  }
}
