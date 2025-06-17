const BASE_URL = "https://securechatapp-ys8y.onrender.com";
const socket = io(BASE_URL);



async function fetchPublicKey(username) {
  const response = await fetch(`${BASE_URL}/get_public_key?username=${username}`);
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
    alert("❌ Couldn't fetch public key");
    return null;
  }
}



const username = sessionStorage.getItem("username");
if (!username) {
  alert("You are not logged in.");
  window.location.href = "index.html";
} else {
  document.getElementById("userNameDisplay").textContent = username;
}

// Register user on connect
socket.emit("register_user", { username });

let currentRoom = null;
let chattingWith = null;

// Handle incoming chat request
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
  }
});

// Handle approval result
socket.on("chat_request_approved", (data) => {
  if (data.approved) {
    const roomName = generateRoomName(username, data.by_user);
    currentRoom = roomName;
    chattingWith = data.by_user;
    socket.emit("join", { room: roomName, username });
  } else {
    alert(`${data.by_user} rejected your chat request.`);
  }
});

socket.on("chat_approved", (data) => {
  const msg = document.createElement("div");
  msg.textContent = `Chat started with ${chattingWith}`;
  document.getElementById("chatBox").appendChild(msg);
});


socket.on("receive_message", async (data) => {
  try {
    const encryptedBase64 = data.message;
    const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

    const privateKeyPem = sessionStorage.getItem("privateKey");
    const b64 = privateKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const binaryDer = atob(b64);
    const buffer = new Uint8Array([...binaryDer].map(ch => ch.charCodeAt(0))).buffer;

    const privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      buffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedBytes
    );

    const decryptedMessage = new TextDecoder().decode(decryptedBuffer);

    const msg = document.createElement("div");
    msg.textContent = `${data.username}: ${decryptedMessage}`;
    document.getElementById("chatBox").appendChild(msg);
  } catch (e) {
    console.error("❌ Decryption failed", e);
    const msg = document.createElement("div");
    msg.textContent = `${data.username}: 🔒 (Unable to decrypt message)`;
    document.getElementById("chatBox").appendChild(msg);
  }
});


function searchUser() {
  const searchUser = document.getElementById("searchUser").value;
  if (!searchUser.trim()) return;

  fetch(`${BASE_URL}/search_user?query=${searchUser}`)
    .then(res => res.json())
    .then(data => {
      if (data.success && data.users.length > 0) {
        socket.emit("send_chat_request", {
          from_user: username,
          to_user: searchUser
        });
        document.getElementById("searchMessage").textContent = "📨 Request sent!";
      } else {
        document.getElementById("searchMessage").textContent = "❌ User not found.";
      }
    });
}
async function sendMessage() {
  const message = document.getElementById("messageInput").value;
  if (!message.trim() || !currentRoom || !chattingWith) return;

  // 1. Get public key of recipient
  const recipientPublicKey = await fetchPublicKey(chattingWith);
  if (!recipientPublicKey) return;

  // 2. Encrypt message with recipient's public key
  const encoder = new TextEncoder();
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPublicKey,
    encoder.encode(message)
  );

  const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));

  // 3. Show encrypted message in your chat box (as "You:")
  const msg = document.createElement("div");
  msg.textContent = `You (encrypted): ${message}`;
  document.getElementById("chatBox").appendChild(msg);

  // 4. Emit encrypted message
  socket.emit("send_message", {
    from_user: username,
    to_user: chattingWith,
    message: encryptedBase64,
    room: currentRoom
  });

  document.getElementById("messageInput").value = "";
}

function generateRoomName(user1, user2) {
  return [user1, user2].sort().join("_");
}
