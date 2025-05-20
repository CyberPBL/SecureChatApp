document.addEventListener("DOMContentLoaded", function () {
  const username = sessionStorage.getItem("username");

  if (!username) {
    sessionStorage.clear();
    alert("Not logged in. Redirecting...");
    window.location.href = "index.html";
    return;
  }

  let currentChatUser = null;
  const BACKEND_URL = "https://securechatapp-ys8y.onrender.com";
  const socket = io(BACKEND_URL);

  socket.on("connect", () => {
    console.log("✅ Connected to Socket.IO");
    socket.emit("register_user", { username });
  });

  // Receive message
  socket.on("receive_message", (data) => {
    if (data.username && data.message) {
      const chatBox = document.getElementById("chatBox");
      if (chatBox) {
        chatBox.innerHTML += `<div><b>${data.username}:</b> ${data.message}</div>`;
        chatBox.scrollTop = chatBox.scrollHeight;

        // Optional: Auto delete after 10 seconds
        setTimeout(() => {
          if (chatBox.lastChild) chatBox.lastChild.remove();
        }, 10000);
      }
    }
  });

  // Incoming chat request handler
  socket.on("chat_request", (data) => {
    const inbox = document.getElementById("inboxRequests");
    if (inbox) {
      inbox.innerHTML +=
        `<div>
          <b>${data.from_user}</b> wants to chat. 
          <button onclick="acceptChat('${data.from_user}')">Accept</button>
        </div>`;
    }
  });

  // When chat is approved
  socket.on("chat_request_approved", (data) => {
    if (!data.approved) {
      alert("Chat request was declined.");
      return;
    }
    currentChatUser = data.by_user;
    const chatArea = document.getElementById("chatArea");
    const chatBox = document.getElementById("chatBox");
    if (chatArea && chatBox) {
      chatArea.style.display = "block";
      chatBox.innerHTML = `<i>Chat with ${currentChatUser} started...</i><br>`;
    }
    const room = [username, currentChatUser].sort().join('_');
    socket.emit("join", { username, room });
  });

  // Search for user and send chat request
  window.searchUser = function () {
    const query = document.getElementById("searchUser").value.trim();
    if (!query) {
      alert("Enter a username to search.");
      return;
    }

    fetch(`${BACKEND_URL}/search_user?query=${encodeURIComponent(query)}`)
      .then((res) => res.json())
      .then((data) => {
        const resultDiv = document.getElementById("searchResult");
        resultDiv.innerHTML = "";
        if (data.success && data.users.length > 0) {
          data.users.forEach((user) => {
            if (user.username !== username) {
              const btn = document.createElement("button");
              btn.textContent = `Chat with ${user.username}`;
              btn.onclick = () => {
                socket.emit("send_chat_request", {
                  from_user: username,
                  to_user: user.username,
                });
                alert(`Chat request sent to ${user.username}`);
              };
              resultDiv.appendChild(btn);
            } else {
              resultDiv.innerHTML = "<i>Cannot chat with yourself.</i>";
            }
          });
        } else {
          resultDiv.innerHTML = "<i>No users found.</i>";
        }
      })
      .catch(() => {
        alert("Error searching users.");
      });
  };

  // Accept chat request
  window.acceptChat = function (fromUser) {
    socket.emit("approve_chat_request", {
      from_user: fromUser,
      to_user: username,
      approved: true,
    });
    // Remove from inbox after accepting
    const inbox = document.getElementById("inboxRequests");
    if (inbox) {
      inbox.innerHTML = "";
    }
  };

  // Send message button
  document.getElementById("sendMsgBtn").addEventListener("click", () => {
    const input = document.getElementById("msgInput");
    const msg = input.value.trim();
    if (!msg) return;

    if (!currentChatUser) {
      alert("No chat user selected.");
      return;
    }

    const room = [username, currentChatUser].sort().join('_');
    socket.emit("send_message", {
      from_user: username,
      to_user: currentChatUser,
      message: msg,
      room,
    });

    const chatBox = document.getElementById("chatBox");
    if (chatBox) {
      chatBox.innerHTML += `<div><b>You:</b> ${msg}</div>`;
      chatBox.scrollTop = chatBox.scrollHeight;
    }
    input.value = "";
  });
});
