// chat.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com"; // Ensure this matches your backend URL
const socket = io(BASE_URL);

// Retrieve user info and private key from sessionStorage
let currentUser = sessionStorage.getItem("username");
let privateKeyPem = sessionStorage.getItem("privateKey");
let publicKeyPem = sessionStorage.getItem("publicKey");

let currentChatPartner = null;
let currentChatRoom = null;
let friendPublicKeys = {};
let ownPublicKeyObject = null;

// DOM Elements
const userNameDisplay = document.getElementById("userNameDisplay");
const chatBox = document.getElementById("chatBox");
const messageInput = document.getElementById("messageInput");
const sendButton = document.getElementById("sendButton");
const searchMessage = document.getElementById("searchMessage");
const friendsContainer = document.getElementById("friendsContainer");
const noFriendsMessage = document.getElementById("noFriendsMessage");
const currentChatPartnerDisplay = document.getElementById("currentChatPartner");

// --- Malicious Content Patterns and Checker Function ---
const suspiciousPatterns = [
  /https?:\/\/(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|is\.gd|shorte\.st|adf\.ly|rebrand\.ly|cutt\.ly|buff\.ly|lnkd\.in|bl\.ink|trib\.al|snip\.ly|shorturl\.at|shrtco\.de|short\.cm|v\.gd|zi\.mu)/i,
  /https?:\/\/.*\.(tk|ml|ga|cf|gq|xyz|top|club|pw|info)(\/|$)/i,
  /https?:\/\/(?:000webhostapp\.com|weebly\.com|wixsite\.com|github\.io|firebaseapp\.com|pages\.dev)/i,
  /https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/i,
  /<script.?>.?<\/script>/i,
  /onerror\s*=/i,
  /javascript:/i,
  /data:text\/html/i,
  /(login|verify|reset|account|bank|payment|alert).*(free|urgent|click|now|immediately)/i,
  /https?:\/\/.*(paypal|google|facebook|instagram|microsoft|whatsapp)\.[^\.]+?\.(tk|ml|ga|cf|gq|xyz|top)/i,
  /%[0-9a-f]{2}/i,
  /[\u200B-\u200F\u202A-\u202E]/,
  // NEW: Pattern for common executable/archive file extensions
  /\.(apk|exe|zip|rar|bat|sh|jar|msi|vbs|cmd)(\/|\?|$)/i,
];

function isMaliciousContent(message) {
    for (let pattern of suspiciousPatterns) {
        if (pattern.test(message)) {
            return true;
        }
    }
    return false;
}
// --- END Malicious Content Detection ---

// --- Initialization on page load ---
document.addEventListener("DOMContentLoaded", async () => {
    if (!currentUser || !privateKeyPem || !publicKeyPem) {
        alert("You are not logged in or missing cryptographic keys. Please log in first.");
        window.location.href = "index.html";
        return;
    }
    userNameDisplay.textContent = currentUser;

    try {
        ownPublicKeyObject = await importPublicKey(publicKeyPem);
        console.log("✅ Successfully imported own public key.");
    } catch (e) {
        console.error("❌ Error importing own public key:", e);
        appendMessage("System", "Failed to load your public key. You may not be able to send messages for history.", 'error');
    }

    socket.emit("register_user", { username: currentUser });
    console.log(`Sending 'register_user' for: ${currentUser}`);

    await fetchFriends();
});

// --- Utility Functions for UI and Cryptography ---

function appendMessage(sender, message, type) {
    const messageElement = document.createElement("div");
    messageElement.classList.add("chat-message", type);

    if (type === 'sent') {
        messageElement.textContent = `You: ${message}`;
    } else if (type === 'received') {
        messageElement.textContent = `${sender}: ${message}`;
    } else {
        messageElement.textContent = message;
    }

    chatBox.appendChild(messageElement);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function displaySearchMessage(message, isError = false) {
    searchMessage.textContent = message;
    searchMessage.style.color = isError ? "red" : "green";
    setTimeout(() => {
        searchMessage.textContent = "";
    }, 5000);
}

async function importPublicKey(pem) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
                            .replace(/\s/g, '');
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );
}

async function importPrivateKey(pem) {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
                            .replace(/\s/g, '');
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["decrypt"]
    );
}

async function encryptMessage(message, publicKey) {
    const encoded = new TextEncoder().encode(message);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        encoded
    );
    return btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
}

async function decryptMessage(encryptedBase64, privateKey) {
    const encryptedBuffer = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedBuffer
        );
        return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
        console.error("Decryption failed:", e);
        return "[Could not decrypt message]";
    }
}

// --- Socket.IO Event Handlers ---

socket.on('connect', () => {
    console.log("✅ Socket.IO connected with ID:", socket.id);
    if (currentUser) {
        socket.emit("register_user", { username: currentUser });
    }
});

socket.on('registered', (data) => {
    console.log("Backend registration confirmation:", data.message);
    if (data.onlineUsers) {
        console.log("Online users:", data.onlineUsers);
        socket.onlineUsers = data.onlineUsers;
        updateFriendOnlineStatus(socket.onlineUsers);
    }
});

socket.on('error', (data) => {
    console.error("Backend error:", data.message);
    appendMessage("System", `Error: ${data.message}`, 'error');
    displaySearchMessage(`Error: ${data.message}`, true);
});

socket.on('user_found', (data) => {
    if (data.foundUser) {
        displaySearchMessage(`User '${data.foundUser}' found. Sending friend request...`);
        socket.emit('send_friend_request', { sender: currentUser, receiver: data.foundUser });
    } else {
        displaySearchMessage(`User '${data.searchedUser}' not found.`, true);
    }
});

socket.on('friend_request_sent', (data) => {
    displaySearchMessage(`Friend request sent to ${data.receiver}.`);
});

socket.on('friend_request_received', (data) => {
    const existingRequest = document.getElementById(`request-${data.sender}`);
    if (existingRequest) {
        console.log(`Friend request from ${data.sender} already displayed.`);
        return;
    }

    appendMessage("System", `Friend request from ${data.sender}.`, 'info');
    const friendsListUl = friendsContainer.querySelector('ul');
    const friendRequestElement = document.createElement("li");
    friendRequestElement.id = `request-${data.sender}`;
    friendRequestElement.classList.add("friend-item", "request");
    friendRequestElement.innerHTML = `
        <span>${data.sender} (Pending Request)</span>
        <div class="friend-actions">
            <button onclick="acceptFriendRequest('${data.sender}')" style="background-color: #28a745; width: auto; margin: 0 5px;">Accept</button>
            <button onclick="rejectFriendRequest('${data.sender}')" style="background-color: #dc3545; width: auto; margin: 0 5px;">Reject</button>
        </div>
    `;
    friendsListUl.prepend(friendRequestElement);
    noFriendsMessage.style.display = 'none';
});

socket.on('friend_request_accepted', (data) => {
    appendMessage("System", `${data.requester} accepted your friend request!`, 'info');
    displaySearchMessage(`${data.requester} is now your friend!`, false);
    fetchFriends();
});

socket.on('friend_request_rejected', (data) => {
    appendMessage("System", `${data.rejecter} rejected your friend request.`, 'info');
    displaySearchMessage(`${data.rejecter} rejected your friend request.`, true);
    const requestElement = document.getElementById(`request-${data.rejecter}`);
    if (requestElement) {
        requestElement.remove();
    }
    if (friendsContainer.querySelector('ul').children.length === 0) {
        noFriendsMessage.style.display = 'block';
    }
});

socket.on('friend_list_updated', async () => {
    console.log("Friend list updated by backend, re-fetching friends.");
    await fetchFriends();
});

socket.on('chat_approved', async (data) => {
    console.log(`Chat approved with: ${data.partner} in room: ${data.room}`);
    currentChatPartner = data.partner;
    currentChatRoom = data.room;
    currentChatPartnerDisplay.textContent = `(Chatting with: ${currentChatPartner})`;

    messageInput.removeAttribute("disabled");
    sendButton.removeAttribute("disabled");
    messageInput.focus();

    chatBox.innerHTML = '';
    appendMessage("System", `You are now chatting with ${currentChatPartner}.`, 'info');

    if (data.history && data.history.length > 0) {
        appendMessage("System", "Loading chat history...", 'info');
        const privateKey = await importPrivateKey(privateKeyPem);

        for (const msg of data.history) {
            let decryptedMessage;
            try {
                decryptedMessage = await decryptMessage(msg.message, privateKey);
            } catch (e) {
                decryptedMessage = "[Could not decrypt message]";
                console.error("Failed to decrypt history message:", e);
            }

            if (msg.sender === currentUser) {
                appendMessage("You", decryptedMessage, 'sent');
            } else {
                appendMessage(msg.sender, decryptedMessage, 'received');
            }
        }
    } else {
        appendMessage("System", "No chat history found for this conversation.", 'info');
    }

    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
        item.classList.remove('active-chat');
        item.classList.remove('new-message-indicator');
    });
    const selectedFriendElement = document.querySelector(`.friend-item[data-username="${currentChatPartner}"]`);
    if (selectedFriendElement) {
        selectedFriendElement.classList.add('active-chat');
    }
});

socket.on('receive_message', async (data) => {
    console.log("Received encrypted message:", data);
    if (data.room === currentChatRoom && data.sender === currentChatPartner) {
        try {
            const privateKey = await importPrivateKey(privateKeyPem);
            const decryptedMessage = await decryptMessage(data.message, privateKey);
            appendMessage(data.sender, decryptedMessage, 'received');
        } catch (error) {
            console.error("Error decrypting received message:", error);
            appendMessage(data.sender, "[Encrypted Message - Decryption Error]", 'error');
        }
    } else {
        appendMessage("System", `New message from ${data.sender}. Select them to view.`, 'info');
        const friendItem = document.querySelector(`.friend-item[data-username="${data.sender}"]`);
        if (friendItem && !friendItem.classList.contains('active-chat')) {
            friendItem.classList.add('new-message-indicator');
        }
    }
});

socket.on('online_users', (onlineUsers) => {
    console.log("Updated online users:", onlineUsers);
    socket.onlineUsers = onlineUsers;
    updateFriendOnlineStatus(onlineUsers);
});

socket.on('user_disconnected', (data) => {
    console.log(`${data.username} disconnected.`);
    const friendItem = document.querySelector(`.friend-item[data-username="${data.username}"]`);
    if (friendItem) {
        friendItem.classList.remove('online');
        friendItem.classList.add('offline'); // Corrected from 'item.classList.add'
    }
});

// NEW Socket.IO Events for blocked messages
socket.on('message_blocked', (data) => {
    appendMessage("System", `🚫 Your message was blocked by the system: ${data.reason.replace(/_/g, ' ')}.`, 'error');
    console.warn(`Message blocked: ${data.reason}`);
});

socket.on('message_from_friend_blocked', (data) => {
    appendMessage("System", `🚫 A message from ${data.sender} was blocked by the system due to suspicious content.`, 'info');
    console.warn(`Message from ${data.sender} blocked by system: ${data.reason}`);
});
// END NEW Socket.IO Events

// NEW Socket.IO Events for unfriend
socket.on('unfriended_success', (data) => {
    appendMessage("System", `You have unfriended ${data.unfriendedUser}.`, 'info');
    if (currentChatPartner === data.unfriendedUser) {
        currentChatPartner = null;
        currentChatRoom = null;
        currentChatPartnerDisplay.textContent = "(Not chatting)";
        chatBox.innerHTML = ''; // Clear chat history
        messageInput.setAttribute("disabled", "true");
        sendButton.setAttribute("disabled", "true");
        appendMessage("System", "Chat session ended. Friend removed.", 'info');
    }
    fetchFriends(); // Re-fetch friends list to update UI
});

socket.on('you_were_unfriended', (data) => {
    appendMessage("System", `😭 You were unfriended by ${data.unfriender}.`, 'info');
    if (currentChatPartner === data.unfriender) {
        currentChatPartner = null;
        currentChatRoom = null;
        currentChatPartnerDisplay.textContent = "(Not chatting)";
        chatBox.innerHTML = ''; // Clear chat history
        messageInput.setAttribute("disabled", "true");
        sendButton.setAttribute("disabled", "true");
        appendMessage("System", "Chat session ended. This user is no longer your friend.", 'info');
    }
    fetchFriends(); // Re-fetch friends list to update UI
});
// END NEW Socket.IO Events for unfriend


// --- Friends List Management ---

async function fetchFriends() {
    try {
        const res = await fetch(`${BASE_URL}/friends?username=${currentUser}`);
        const data = await res.json();

        const friendsListUl = friendsContainer.querySelector('ul');
        friendsListUl.innerHTML = ''; // Clear existing list before re-populating

        let hasFriendsOrRequests = false;

        if (data.friends && data.friends.length > 0) {
            data.friends.forEach(friend => {
                addFriendToList(friend.username, friend.status, friend.publicKey);
            });
            hasFriendsOrRequests = true;
            updateFriendOnlineStatus(socket.onlineUsers || []);
        }

        if (data.pendingRequests && data.pendingRequests.length > 0) {
            data.pendingRequests.forEach(sender => {
                // Ensure request is not already displayed, or update if it is
                if (!document.getElementById(`request-${sender}`)) {
                    const friendRequestElement = document.createElement("li");
                    friendRequestElement.id = `request-${sender}`;
                    friendRequestElement.classList.add("friend-item", "request");
                    friendRequestElement.innerHTML = `
                        <span>${sender} (Pending Request)</span>
                        <div class="friend-actions">
                            <button onclick="acceptFriendRequest('${sender}')" style="background-color: #28a745; width: auto; margin: 0 5px;">Accept</button>
                            <button onclick="rejectFriendRequest('${sender}')" style="background-color: #dc3545; width: auto; margin: 0 5px;">Reject</button>
                        </div>
                    `;
                    friendsListUl.prepend(friendRequestElement);
                }
            });
            hasFriendsOrRequests = true;
        }

        if (hasFriendsOrRequests) {
            noFriendsMessage.style.display = 'none';
        } else {
            noFriendsMessage.style.display = 'block';
        }

    } catch (error) {
        console.error("Error fetching friends:", error);
        appendMessage("System", "Failed to load friends.", 'error');
    }
}

function addFriendToList(friendUsername, status = 'offline', publicKeyPemString) {
    const friendsListUl = friendsContainer.querySelector('ul');
    let friendItem = document.querySelector(`.friend-item[data-username="${friendUsername}"]`);

    if (!friendItem) {
        friendItem = document.createElement("li");
        friendItem.classList.add("friend-item");
        friendItem.setAttribute("data-username", friendUsername);
        friendItem.innerHTML = `
            <span>${friendUsername}</span>
            <div class="friend-actions">
                <button class="chat-btn" onclick="selectFriend('${friendUsername}')">Chat</button>
                <button class="unfriend-btn" onclick="unfriendUser('${friendUsername}')">Unfriend</button>
            </div>
        `;
        friendsListUl.appendChild(friendItem);
    } else {
        // If friend item already exists, ensure unfriend button is present
        // This handles cases where a pending request turns into a friend
        if (!friendItem.querySelector('.unfriend-btn')) {
            const friendActionsDiv = document.createElement('div');
            friendActionsDiv.classList.add('friend-actions');
            friendActionsDiv.innerHTML = `
                <button class="chat-btn" onclick="selectFriend('${friendUsername}')">Chat</button>
                <button class="unfriend-btn" onclick="unfriendUser('${friendUsername}')">Unfriend</button>
            `;
            friendItem.innerHTML = `<span>${friendUsername}</span>`; // Clear existing content
            friendItem.appendChild(friendActionsDiv);
        }
    }


    friendItem.classList.remove('online', 'offline', 'request');
    friendItem.classList.add(status);

    if (publicKeyPemString && !friendPublicKeys[friendUsername]) {
        importPublicKey(publicKeyPemString)
            .then(publicKeyObj => {
                friendPublicKeys[friendUsername] = publicKeyObj;
                console.log(`Cached public key for ${friendUsername}`);
            })
            .catch(error => console.error(`Error importing public key for ${friendUsername}:`, error));
    }
}

function updateFriendOnlineStatus(onlineUsers) {
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
        const username = item.getAttribute('data-username');
        if (username) {
            if (onlineUsers.includes(username)) {
                item.classList.add('online');
                item.classList.remove('offline');
            } else {
                item.classList.add('offline');
                item.classList.remove('online');
            }
        }
    });
}

function selectFriend(friendUsername) {
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
        item.classList.remove('active-chat');
        item.classList.remove('new-message-indicator');
    });
    const selectedFriendElement = document.querySelector(`.friend-item[data-username="${friendUsername}"]`);
    if (selectedFriendElement) {
        selectedFriendElement.classList.add('active-chat');
    }

    console.log(`Selected friend: ${friendUsername}`);
    socket.emit('request_chat', { sender: currentUser, receiver: friendUsername });
}

// --- User Interaction Functions ---

async function searchUser() {
    const searchUsername = document.getElementById("searchUser").value.trim();
    if (!searchUsername) {
        displaySearchMessage("Please enter a username to search.", true);
        return;
    }
    if (searchUsername === currentUser) {
        displaySearchMessage("You cannot search for yourself.", true);
        return;
    }
    const friendsListUl = friendsContainer.querySelector('ul');
    const existingFriend = friendsListUl.querySelector(`li[data-username="${searchUsername}"], li#request-${searchUsername}`);
    if (existingFriend) {
        if (existingFriend.classList.contains('request')) {
            displaySearchMessage(`A pending request with ${searchUsername} already exists.`, false);
        } else {
            displaySearchMessage(`${searchUsername} is already your friend. Select them to chat.`, false);
        }
        return;
    }

    console.log(`Searching for user: ${searchUsername}`);
    socket.emit('search_user', { username: searchUsername });
}

function acceptFriendRequest(senderUsername) {
    console.log(`Accepting request from: ${senderUsername}`);
    socket.emit('accept_friend_request', { acceptor: currentUser, requester: senderUsername });
    const requestElement = document.getElementById(`request-${senderUsername}`);
    if (requestElement) {
        requestElement.remove();
    }
    fetchFriends(); // Re-fetch friends to ensure the accepted friend appears as a regular friend
}

function rejectFriendRequest(senderUsername) {
    console.log(`Rejecting request from: ${senderUsername}`);
    socket.emit('reject_friend_request', { rejecter: currentUser, requester: senderUsername });
    const requestElement = document.getElementById(`request-${senderUsername}`);
    if (requestElement) {
        requestElement.remove();
    }
    if (friendsContainer.querySelector('ul').children.length === 0) {
        noFriendsMessage.style.display = 'block';
    }
}

// NEW: Unfriend Function
function unfriendUser(unfriendedUsername) {
    if (confirm(`Are you sure you want to unfriend ${unfriendedUsername}? This will remove them from your friends list and end the current chat.`)) {
        socket.emit('unfriend_user', { unfriender: currentUser, unfriended: unfriendedUsername });
    }
}
// END NEW: Unfriend Function

async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message) {
        return;
    }

    if (!currentChatPartner || !currentChatRoom) {
        appendMessage("System", "Please select a friend to chat with.", 'error');
        return;
    }

    // Frontend malicious content check
    if (isMaliciousContent(message)) {
        appendMessage("System", "🚫 Your message contains suspicious content and cannot be sent.", 'error');
        console.warn("Message blocked locally: Contains suspicious content.");
        messageInput.value = ""; // Clear input
        return; // Prevent sending
    }

    if (!friendPublicKeys[currentChatPartner]) {
        appendMessage("System", `Public key for ${currentChatPartner} not found. Cannot encrypt message.`, 'error');
        console.error(`Public key missing for ${currentChatPartner}`);
        return;
    }

    if (!ownPublicKeyObject) {
        appendMessage("System", "Your own public key is not loaded. Cannot encrypt message for history.", 'error');
        console.error("Own public key object is null.");
        return;
    }

    try {
        const encryptedMessageForReceiver = await encryptMessage(message, friendPublicKeys[currentChatPartner]);
        console.log("Encrypted for receiver (first 50 chars):", encryptedMessageForReceiver.substring(0, 50) + '...');

        const encryptedMessageForSelf = await encryptMessage(message, ownPublicKeyObject);
        console.log("Encrypted for self (first 50 chars):", encryptedMessageForSelf.substring(0, 50) + '...');

        // Emit the message to the server, including the original unencrypted content for backend scanning
        socket.emit('send_message', {
            sender: currentUser,
            receiver: currentChatPartner,
            room: currentChatRoom,
            messageForReceiver: encryptedMessageForReceiver,
            messageForSelf: encryptedMessageForSelf,
            originalMessageContent: message // IMPORTANT: Send unencrypted content for backend scan
        });

        appendMessage("You", message, 'sent');
        messageInput.value = "";
    } catch (error) {
        console.error("Error sending message:", error);
        appendMessage("System", "Failed to send message due to encryption error.", 'error');
    }
}

messageInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
