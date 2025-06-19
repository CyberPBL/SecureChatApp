const BASE_URL = "https://securechatapp-ys8y.onrender.com";
const socket = io(BASE_URL);

const username = sessionStorage.getItem("username");
document.getElementById("userNameDisplay").textContent = username;

let room = null;
let toUser = null;
let aesKey = null;

// ⛔ Prevent XSS by escaping message content
function escapeHTML(str) {
  return str.replace(/[&<>"']/g, function (tag) {
    const chars = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return chars[tag] || tag;
  });
}

function getTimestamp() {
  return new Date().toLocaleTimeString();
}

function generateRoomName(user1, user2) {
  return [user1, user2].sort().join("_");
}

socket.on("connect", () => {
  console.log("Connected with Socket ID:", socket.id);
  if (username) {
    socket.emit("register_user", { username });
  }
});

document.getElementById("joinBtn").onclick = async () => {
  toUser = document.getElementById("partnerInput").value.trim();
  if (!toUser || toUser === username) {
    alert("Invalid username to chat with.");
    return;
  }

  room = generateRoomName(username, toUser);
  socket.emit("join", { room, username });

  // Request recipient's public key
  const response = await fetch(`${BASE_URL}/get_public_key?username=${toUser}`);
  const result = await response.json();

  if (result.success) {
    const publicKeyPem = result.public_key;

    // Generate AES key
    aesKey = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    const aesKeyRaw = await window.crypto.subtle.exportKey("raw", aesKey);
    const importedPublicKey = await window.crypto.subtle.importKey(
      "spki",
      pemToArrayBuffer(publicKeyPem),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );

    const encryptedAES = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      importedPublicKey,
      aesKeyRaw
    );

    const encryptedAESBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedAES)));
    socket.emit("send_aes_key_encrypted", {
      from_user: username,
      to_user: toUser,
      encrypted_aes_key: encryptedAESBase64
    });

    appendSystemMessage("🔐 AES key generated and sent. Waiting for response...");
  } else {
    alert("User not found or offline.");
  }
};

socket.on("receive_aes_key_encrypted", async (data) => {
  const encryptedBase64 = data.encrypted_aes_key;
  const privateKeyPem = sessionStorage.getItem("privateKey");

  if (!privateKeyPem) {
    alert("🔐 Private key missing. Please log in again.");
    location.href = "index.html";
    return;
  }

  const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
  const importedPrivateKey = await window.crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKeyPem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );

  const rawKey = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    importedPrivateKey,
    encryptedBytes
  );

  aesKey = await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  console.log("🔑 AES key exchanged successfully!");
  appendSystemMessage("✅ Secure connection established. You may now chat.");

  document.getElementById("messageInput").disabled = false;
  document.getElementById("sendButton").disabled = false;
});

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----.*-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
  return buffer;
}

document.getElementById("sendButton").onclick = async () => {
  const input = document.getElementById("messageInput");
  const plainText = input.value;
  if (!plainText || !aesKey || !room || !toUser) return;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(plainText)
  );

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  const encryptedBase64 = btoa(String.fromCharCode(...combined));

  socket.emit("send_message", {
    from_user: username,
    to_user: toUser,
    message: encryptedBase64,
    room
  });

  input.value = "";
};

socket.on("receive_message", async (data) => {
  if (!aesKey) return;

  const combined = Uint8Array.from(atob(data.message), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const encryptedData = combined.slice(12);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      encryptedData
    );

    const message = new TextDecoder().decode(decrypted);
    const div = document.createElement("div");
    div.innerHTML = `<strong>${escapeHTML(data.username)}</strong> [${getTimestamp()}]: ${escapeHTML(message)}`;
    document.getElementById("chatBox").appendChild(div);
  } catch (e) {
    console.error("Decryption failed:", e);
  }
});

function appendSystemMessage(msg) {
  const div = document.createElement("div");
  div.innerHTML = `<em>[${getTimestamp()}] ${escapeHTML(msg)}</em>`;
  div.style.color = "gray";
  document.getElementById("chatBox").appendChild(div);
}
