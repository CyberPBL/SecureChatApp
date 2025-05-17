let username = localStorage.getItem("username"); // Assuming user has logged in
let currentReceiver = ''; // Track the current user to chat with

// Update the welcome message
document.getElementById("welcomeText").innerText = `Welcome, ${username}!`;

// Function to send a chat request to another user
function searchUser() {
    const searchUsername = document.getElementById("searchInput").value;
    if (!searchUsername) {
        alert("Please enter a username to search.");
        return;
    }

    document.getElementById("searchButton").disabled = true;

    fetch("http://localhost:5000/request-chat", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            from: username,
            to: searchUsername
        })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("searchButton").disabled = false;

        if (data.success) {
            document.getElementById("searchMessage").innerText = `Request sent to ${searchUsername}.`;
        } else {
            document.getElementById("searchMessage").innerText = `Error: ${data.message}`;
        }
    })
    .catch(error => {
        document.getElementById("searchButton").disabled = false;
        console.error("Error:", error);
        document.getElementById("searchMessage").innerText = "An error occurred while sending the request.";
    });
}

// ✅ FIXED Function to get and display chat requests in the inbox
function getInbox() {
    fetch("http://localhost:5000/get-inbox", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username: username })
    })
    .then(response => response.json())
    .then(data => {
        const inboxDiv = document.getElementById("inbox");
        inboxDiv.innerHTML = "<h3>Inbox</h3>";

        if (!data.inbox || data.inbox.length === 0) {
            inboxDiv.innerHTML += "<p>No new requests.</p>";
        } else {
            data.inbox.forEach(entry => {
                const requester = entry.from;
                const requestDiv = document.createElement("div");
                requestDiv.innerHTML = `
                    <p>${requester} wants to chat.</p>
                    <button onclick="acceptRequest('${requester}')">Accept</button>
                    <button onclick="rejectRequest('${requester}')">Reject</button>
                `;
                inboxDiv.appendChild(requestDiv);
            });
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Failed to load inbox.");
    });
}

// Function to accept a chat request
function acceptRequest(fromUser) {
    fetch("http://localhost:5000/accept-request", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            to: username,
            from: fromUser
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            currentReceiver = fromUser;
            alert(`You are now chatting with ${fromUser}`);
            getChatHistory(fromUser);
        } else {
            alert("Failed to accept the request.");
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("An error occurred while accepting the chat request.");
    });
}

// Function to reject a chat request
function rejectRequest(fromUser) {
    fetch("http://localhost:5000/reject-request", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            to: username,
            from: fromUser
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`You rejected the chat request from ${fromUser}`);
            getInbox();
        } else {
            alert("Failed to reject the request.");
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("An error occurred while rejecting the chat request.");
    });
}

// ✅ FIXED getChatHistory to access correct data
function getChatHistory(user) {
    fetch("http://localhost:5000/get-messages", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            user1: username,
            user2: user
        })
    })
    .then(response => response.json())
    .then(data => {
        const chatBox = document.getElementById("chatBox");
        chatBox.innerHTML = "";

        if (!data.messages || data.messages.length === 0) {
            chatBox.innerHTML = "<p>No chat history found.</p>";
        } else {
            data.messages.forEach(message => {
                const messageDiv = document.createElement("div");
                messageDiv.innerHTML = `<strong>${message.sender}:</strong> ${message.message}`;
                chatBox.appendChild(messageDiv);
            });
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Failed to load chat history.");
    });
}
