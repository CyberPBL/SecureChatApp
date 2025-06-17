const BASE_URL = "https://securechatapp-ys8y.onrender.com";
const socket = io(BASE_URL);

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

socket.on("receive_message", (data) => {
  const msg = document.createElement("div");
  msg.textContent = `${data.username}: ${data.message}`;
  document.getElementById("chatBox").appendChild(msg);
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

function sendMessage() {
  const message = document.getElementById("messageInput").value;
  if (!message.trim() || !currentRoom) return;

  const msg = document.createElement("div");
  msg.textContent = `You: ${message}`;
  document.getElementById("chatBox").appendChild(msg);

  socket.emit("send_message", {
    from_user: username,
    to_user: chattingWith,
    message,
    room: currentRoom
  });

  document.getElementById("messageInput").value = "";
}

function generateRoomName(user1, user2) {
  return [user1, user2].sort().join("_");
}
