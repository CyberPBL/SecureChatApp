const BASE_URL = "http://localhost:8000"; // same as backend
const socket = io(BASE_URL);
const username = sessionStorage.getItem("username");

if (!username) {
  alert("You are not logged in.");
  window.location.href = "index.html";
}

document.getElementById("userNameDisplay").textContent = username;

// Register user for socket events
socket.emit("register_user", { username });

function searchUser() {
  const searchUser = document.getElementById("searchUser").value;
  fetch(`${BASE_URL}/search_user?query=${searchUser}`)
    .then(res => res.json())
    .then(data => {
      if (data.success && data.users.length > 0) {
        socket.emit("send_chat_request", {
          from_user: username,
          to_user: searchUser
        });
        alert("Request sent!");
      } else {
        document.getElementById("searchMessage").textContent = "User not found.";
      }
    });
}

function sendMessage() {
  const message = document.getElementById("messageInput").value;
  if (!message.trim()) return;

  const msgDiv = document.createElement("div");
  msgDiv.textContent = "You: " + message;
  document.getElementById("chatMessages").appendChild(msgDiv);

  // Simulate sending
  document.getElementById("messageInput").value = "";
}
