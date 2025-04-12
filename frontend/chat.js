const username = new URLSearchParams(window.location.search).get("username");
document.getElementById("welcomeText").innerText = "Logged in as: " + username;

let currentChatWith = null;

function loadInbox() {
  fetch(`http://127.0.0.1:5000/get-inbox?username=${username}`)
    .then(res => res.json())
    .then(data => {
      const inboxDiv = document.getElementById("inbox");
      inboxDiv.innerHTML = "<h3>Inbox</h3>";

      data.inbox.forEach(item => {
        const div = document.createElement("div");
        div.innerHTML = `
          <p><b>${item.from}</b> sent you a request.</p>
          <button onclick="acceptRequest('${item.from}')">Accept</button>
          <button onclick="rejectRequest('${item.from}')">Reject</button>
        `;
        inboxDiv.appendChild(div);
      });
    });
}

function acceptRequest(fromUser) {
  fetch("http://127.0.0.1:5000/accept-request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ to: username, from: fromUser })
  })
    .then(res => res.json())
    .then(data => {
      alert(data.message);
      loadInbox();
      startChatWith(fromUser);
    });
}

function rejectRequest(fromUser) {
  fetch("http://127.0.0.1:5000/reject-request", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ to: username, from: fromUser })
  })
    .then(res => res.json())
    .then(data => {
      alert(data.message);
      loadInbox();
    });
}

function startChatWith(friend) {
  currentChatWith = friend;
  document.getElementById("chatBox").innerHTML = `Chat started with <b>${friend}</b><br>`;
  pollMessages(); // Start polling
}

function sendMessage() {
  const msg = document.getElementById("messageInput").value;
  if (!msg || !currentChatWith) return;

  fetch("http://127.0.0.1:5000/send-message", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from: username, to: currentChatWith, message: msg })
  }).then(res => {
    document.getElementById("messageInput").value = "";
  });
}

function pollMessages() {
  setInterval(() => {
    if (!currentChatWith) return;

    fetch(`http://127.0.0.1:5000/get-messages?user1=${username}&user2=${currentChatWith}`)
      .then(res => res.json())
      .then(data => {
        const chatBox = document.getElementById("chatBox");
        chatBox.innerHTML = "";
        data.messages.forEach(msg => {
          const line = document.createElement("p");
          line.textContent = `${msg.sender}: ${msg.text}`;
          chatBox.appendChild(line);
        });
      });
  }, 1000); // Refresh every second
}

function searchUser() {
  const searchValue = document.getElementById("searchInput").value.trim();
  if (searchValue === "") {
    document.getElementById("searchMessage").textContent = "Please enter a username.";
    return;
  }

  if (searchValue === username) {
    document.getElementById("searchMessage").textContent = "You cannot send a request to yourself.";
    return;
  }

  fetch("http://127.0.0.1:5000/request-chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from: username, to: searchValue })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        document.getElementById("searchMessage").textContent = `Request sent to ${searchValue}`;
      } else {
        document.getElementById("searchMessage").textContent = `Error: ${data.message}`;
      }
    })
    .catch(err => {
      document.getElementById("searchMessage").textContent = "Something went wrong.";
      console.error(err);
    });
}

// Initialize
loadInbox();
