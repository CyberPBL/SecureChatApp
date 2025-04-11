// Load username from localStorage
const username = localStorage.getItem("username");

if (!username) {
  alert("No user found. Redirecting to login...");
  window.location.href = "index.html";
}

// Update welcome text
document.getElementById("welcomeText").textContent = `Welcome, ${username}!`;

function sendMessage() {
  const input = document.getElementById("messageInput");
  const message = input.value.trim();
  if (message === "") return;

  fetch("http://127.0.0.1:5000/send-message", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ username: username, message: message })
  })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        input.value = "";
        loadMessages();  // Refresh messages
      } else {
        alert("Message failed.");
      }
    });
}

function loadMessages() {
  fetch("http://127.0.0.1:5000/get-messages")
    .then(res => res.json())
    .then(data => {
      const chatBox = document.getElementById("chatBox");
      chatBox.innerHTML = "";

      data.forEach(msg => {
        const div = document.createElement("div");
        div.className = "message";
        div.textContent = `${msg.user}: ${msg.text}`;
        chatBox.appendChild(div);
      });

      chatBox.scrollTop = chatBox.scrollHeight;  // Auto-scroll
    });
}

// Load messages when page opens
loadMessages();
setInterval(loadMessages, 2000); // Refresh messages every 2 seconds
