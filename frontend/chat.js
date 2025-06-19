// chat.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com";
const socket = io(BASE_URL);

// Retrieve user info and private key from sessionStorage
let currentUser = sessionStorage.getItem("username");
let privateKeyPem = sessionStorage.getItem("privateKey"); // PEM string of the private key

let currentChatPartner = null; // Stores the username of the actively chatting friend
let currentChatRoom = null;    // Stores the current chat room ID (e.g., "user1_user2")
let friendPublicKeys = {};     // Cache for friend public keys {username: CryptoKeyObject}

// DOM Elements
const userNameDisplay = document.getElementById("userNameDisplay");
const chatBox = document.getElementById("chatBox");
const messageInput = document.getElementById("messageInput");
const sendButton = document.getElementById("sendButton");
const searchMessage = document.getElementById("searchMessage");
const friendsContainer = document.getElementById("friendsContainer");
const noFriendsMessage = document.getElementById("noFriendsMessage");
const currentChatPartnerDisplay = document.getElementById("currentChatPartner");

// --- Initialization on page load ---
document.addEventListener("DOMContentLoaded", async () => {
    // Check if user is logged in
    if (!currentUser || !privateKeyPem) {
        alert("You are not logged in. Please log in first.");
        window.location.href = "index.html"; // Redirect to login page
        return;
    }
    userNameDisplay.textContent = currentUser;

    // Register the user with Socket.IO upon entering the chat page
    socket.emit("register_user", { username: currentUser });
    console.log(`Sending 'register_user' for: ${currentUser}`);

    // Fetch and display friends initially
    await fetchFriends();
});

// --- Utility Functions for UI and Cryptography ---

/**
 * Appends a message to the chat box.
 * @param {string} sender The sender's username.
 * @param {string} message The message content.
 * @param {string} type 'sent', 'received', 'info', or 'error'.
 */
function appendMessage(sender, message, type) {
    const messageElement = document.createElement("div");
    messageElement.classList.add("chat-message", type);

    if (type === 'sent') {
        messageElement.textContent = `You: ${message}`;
    } else if (type === 'received') {
        messageElement.textContent = `${sender}: ${message}`;
    } else { // info or error messages from the system
        messageElement.textContent = message;
    }

    chatBox.appendChild(messageElement);
    chatBox.scrollTop = chatBox.scrollHeight; // Scroll to bottom
}

/**
 * Displays a message in the searchMessage element.
 * @param {string} message The message to display.
 * @param {boolean} isError True if it's an error message (red text), false otherwise (green text).
 */
function displaySearchMessage(message, isError = false) {
    searchMessage.textContent = message;
    searchMessage.style.color = isError ? "red" : "green";
    setTimeout(() => {
        searchMessage.textContent = "";
    }, 5000);
}

/**
 * Imports a PEM formatted public key string into a CryptoKey object.
 * @param {string} pem The PEM formatted public key string.
 * @returns {Promise<CryptoKey>} The CryptoKey object.
 */
async function importPublicKey(pem) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
                           .replace(/\s/g, ''); // Remove all whitespace
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "spki", // SubjectPublicKeyInfo format
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true, // extractable
        ["encrypt"]
    );
}

/**
 * Imports a PEM formatted private key string into a CryptoKey object.
 * @param {string} pem The PEM formatted private key string.
 * @returns {Promise<CryptoKey>} The CryptoKey object.
 */
async function importPrivateKey(pem) {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
                           .replace(/\s/g, ''); // Remove all whitespace
    const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "pkcs8", // PKCS #8 format
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true, // extractable
        ["decrypt"]
    );
}

/**
 * Encrypts a message using a public key.
 * @param {string} message The plain text message to encrypt.
 * @param {CryptoKey} publicKey The public key (CryptoKey object) to use for encryption.
 * @returns {Promise<string>} The base64 encoded encrypted message.
 */
async function encryptMessage(message, publicKey) {
    const encoded = new TextEncoder().encode(message); // Encode message to Uint8Array
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        encoded
    );
    // Convert ArrayBuffer to base64 string for transmission
    return btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
}

/**
 * Decrypts a base64 encoded encrypted message using a private key.
 * @param {string} encryptedBase64 The base64 encoded encrypted message.
 * @param {CryptoKey} privateKey The private key (CryptoKey object) to use for decryption.
 * @returns {Promise<string>} The decrypted plain text message.
 */
async function decryptMessage(encryptedBase64, privateKey) {
    const encryptedBuffer = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedBuffer
        );
        return new TextDecoder().decode(decryptedBuffer); // Decode decrypted buffer to string
    } catch (e) {
        console.error("Decryption failed:", e);
        return "[Could not decrypt message]"; // Indicate decryption failure
    }
}

// --- Socket.IO Event Handlers ---

socket.on('connect', () => {
    console.log("✅ Socket.IO connected with ID:", socket.id);
    if (currentUser) {
        // Re-register user on reconnect if they are already logged in
        socket.emit("register_user", { username: currentUser });
    }
});

socket.on('registered', (data) => {
    console.log("Backend registration confirmation:", data.message);
    if (data.onlineUsers) {
        console.log("Online users:", data.onlineUsers);
        // Store online users on the socket object for easier access
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
    // Check if the request is already displayed to prevent duplicates
    const existingRequest = document.getElementById(`request-${data.sender}`);
    if (existingRequest) {
        console.log(`Friend request from ${data.sender} already displayed.`);
        return;
    }

    appendMessage("System", `Friend request from ${data.sender}.`, 'info');
    const friendsListUl = friendsContainer.querySelector('ul');
    const friendRequestElement = document.createElement("li");
    friendRequestElement.id = `request-${data.sender}`; // Unique ID for easy removal
    friendRequestElement.classList.add("friend-item", "request"); // Add 'request' class for styling
    friendRequestElement.innerHTML = `
        <span>${data.sender} (Pending Request)</span>
        <div>
            <button onclick="acceptFriendRequest('${data.sender}')" style="background-color: #28a745; width: auto; margin: 0 5px;">Accept</button>
            <button onclick="rejectFriendRequest('${data.sender}')" style="background-color: #dc3545; width: auto; margin: 0 5px;">Reject</button>
        </div>
    `;
    friendsListUl.prepend(friendRequestElement); // Add to top of friend list
    noFriendsMessage.style.display = 'none'; // Hide "no friends" message if requests exist
});

socket.on('friend_request_accepted', (data) => {
    appendMessage("System", `${data.requester} accepted your friend request!`, 'info');
    displaySearchMessage(`${data.requester} is now your friend!`, false);
    fetchFriends(); // Refresh friends list to show the new friend
});

socket.on('friend_request_rejected', (data) => {
    appendMessage("System", `${data.rejecter} rejected your friend request.`, 'info');
    displaySearchMessage(`${data.rejecter} rejected your friend request.`, true);
    // Remove the request element from the UI if it exists
    const requestElement = document.getElementById(`request-${data.rejecter}`);
    if (requestElement) {
        requestElement.remove();
    }
    // If no friends or requests are left, show the "no friends" message
    if (friendsContainer.querySelector('ul').children.length === 0) {
        noFriendsMessage.style.display = 'block';
    }
});

socket.on('friend_list_updated', async () => {
    console.log("Friend list updated by backend, re-fetching friends.");
    await fetchFriends(); // Re-fetch friends when backend signals an update
});

socket.on('chat_approved', async (data) => {
    console.log(`Chat approved with: ${data.partner} in room: ${data.room}`);
    currentChatPartner = data.partner;
    currentChatRoom = data.room;
    currentChatPartnerDisplay.textContent = `(Chatting with: ${currentChatPartner})`;

    // Enable message input and send button
    messageInput.removeAttribute("disabled");
    sendButton.removeAttribute("disabled");
    messageInput.focus(); // Set focus to the input field

    // Clear previous chat messages from other conversations
    chatBox.innerHTML = '';
    appendMessage("System", `You are now chatting with ${currentChatPartner}.`, 'info');

    // Display chat history if available
    if (data.history && data.history.length > 0) {
        appendMessage("System", "Loading chat history...", 'info');
        const privateKey = await importPrivateKey(privateKeyPem); // Get user's private key for decryption

        for (const msg of data.history) {
            let decryptedMessage;
            try {
                // Decrypt each message from history
                decryptedMessage = await decryptMessage(msg.message, privateKey);
            } catch (e) {
                decryptedMessage = "[Decryption Failed for history message]";
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

    // Ensure the selected friend in the list is highlighted
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
        item.classList.remove('active-chat'); // Remove active class from all
        item.classList.remove('new-message-indicator'); // Remove new message indicator
    });
    const selectedFriendElement = document.querySelector(`.friend-item[data-username="${currentChatPartner}"]`);
    if (selectedFriendElement) {
        selectedFriendElement.classList.add('active-chat'); // Add active class to current partner
    }
});

socket.on('receive_message', async (data) => {
    console.log("Received encrypted message:", data);
    // Only display message if it's for the currently active chat room and partner
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
        // If message is for a different chat, provide a notification
        appendMessage("System", `New message from ${data.sender}. Select them to view.`, 'info');
        // Add a visual indicator to the friend in the list
        const friendItem = document.querySelector(`.friend-item[data-username="${data.sender}"]`);
        if (friendItem && !friendItem.classList.contains('active-chat')) {
            friendItem.classList.add('new-message-indicator'); // Add a class for visual notification
        }
    }
});

socket.on('online_users', (onlineUsers) => {
    console.log("Updated online users:", onlineUsers);
    socket.onlineUsers = onlineUsers; // Keep the online user list updated
    updateFriendOnlineStatus(onlineUsers);
});

socket.on('user_disconnected', (data) => {
    console.log(`${data.username} disconnected.`);
    const friendItem = document.querySelector(`.friend-item[data-username="${data.username}"]`);
    if (friendItem) {
        friendItem.classList.remove('online');
        friendItem.classList.add('offline');
    }
});

// --- Friends List Management ---

async function fetchFriends() {
    try {
        const res = await fetch(`${BASE_URL}/friends?username=${currentUser}`);
        const data = await res.json();

        const friendsListUl = friendsContainer.querySelector('ul');
        friendsListUl.innerHTML = ''; // Clear existing friends and requests

        let hasFriendsOrRequests = false;

        // Add approved friends
        if (data.friends && data.friends.length > 0) {
            data.friends.forEach(friend => {
                // friend.status will be provided by backend (e.g., 'online', 'offline')
                addFriendToList(friend.username, friend.status, friend.publicKey);
            });
            hasFriendsOrRequests = true;
            // Update online status based on current known online users
            updateFriendOnlineStatus(socket.onlineUsers || []);
        }

        // Add pending requests
        if (data.pendingRequests && data.pendingRequests.length > 0) {
            data.pendingRequests.forEach(sender => {
                // Check if already displayed (unlikely with innerHTML = '')
                if (!document.getElementById(`request-${sender}`)) {
                    const friendRequestElement = document.createElement("li");
                    friendRequestElement.id = `request-${sender}`; // Unique ID
                    friendRequestElement.classList.add("friend-item", "request"); // Styling for requests
                    friendRequestElement.innerHTML = `
                        <span>${sender} (Pending Request)</span>
                        <div>
                            <button onclick="acceptFriendRequest('${sender}')" style="background-color: #28a745; width: auto; margin: 0 5px;">Accept</button>
                            <button onclick="rejectFriendRequest('${sender}')" style="background-color: #dc3545; width: auto; margin: 0 5px;">Reject</button>
                        </div>
                    `;
                    friendsListUl.prepend(friendRequestElement); // Prepend to show requests at the top
                }
            });
            hasFriendsOrRequests = true;
        }

        // Show/hide "no friends" message based on content
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

/**
 * Adds a friend to the UI list and caches their public key.
 * @param {string} friendUsername The username of the friend.
 * @param {string} status The online/offline status.
 * @param {string} publicKeyPemString The PEM string of the friend's public key.
 */
function addFriendToList(friendUsername, status = 'offline', publicKeyPemString) {
    const friendsListUl = friendsContainer.querySelector('ul');
    let friendItem = document.querySelector(`.friend-item[data-username="${friendUsername}"]`);

    if (!friendItem) { // Create new item only if it doesn't already exist
        friendItem = document.createElement("li");
        friendItem.classList.add("friend-item");
        friendItem.setAttribute("data-username", friendUsername); // Custom attribute to store username
        friendItem.innerHTML = `<span>${friendUsername}</span>`;
        // Attach click listener to select the friend and start chat
        friendItem.addEventListener('click', () => selectFriend(friendUsername));
        friendsListUl.appendChild(friendItem);
    }

    // Update status classes
    friendItem.classList.remove('online', 'offline', 'request'); // Clear previous status
    friendItem.classList.add(status);

    // Cache public key if provided and not already cached
    if (publicKeyPemString && !friendPublicKeys[friendUsername]) {
        importPublicKey(publicKeyPemString)
            .then(publicKeyObj => {
                friendPublicKeys[friendUsername] = publicKeyObj;
                console.log(`Cached public key for ${friendUsername}`);
            })
            .catch(error => console.error(`Error importing public key for ${friendUsername}:`, error));
    }
}

/**
 * Updates the online/offline status of friends in the UI.
 * @param {Array<string>} onlineUsers An array of usernames who are currently online.
 */
function updateFriendOnlineStatus(onlineUsers) {
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
        const username = item.getAttribute('data-username');
        if (username) { // Ensure it's an actual friend item (not a request which lacks data-username)
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

/**
 * Handles the selection of a friend from the friends list to initiate a chat.
 * @param {string} friendUsername The username of the friend to chat with.
 */
function selectFriend(friendUsername) {
    // Visually highlight the selected friend in the list
    const friendItems = document.querySelectorAll('.friend-item');
    friendItems.forEach(item => {
        item.classList.remove('active-chat');
        item.classList.remove('new-message-indicator'); // Clear new message indicator on selection
    });
    const selectedFriendElement = document.querySelector(`.friend-item[data-username="${friendUsername}"]`);
    if (selectedFriendElement) {
        selectedFriendElement.classList.add('active-chat');
    }

    console.log(`Selected friend: ${friendUsername}`);
    // Emit 'request_chat' to the backend to get/create a chat room
    socket.emit('request_chat', { sender: currentUser, receiver: friendUsername });
}

// --- User Interaction Functions ---

/**
 * Initiates a search for a user or sends a friend request.
 */
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
    // Check if already a friend or has pending request
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

/**
 * Accepts a pending friend request.
 * @param {string} senderUsername The username of the person who sent the request.
 */
function acceptFriendRequest(senderUsername) {
    console.log(`Accepting request from: ${senderUsername}`);
    socket.emit('accept_friend_request', { acceptor: currentUser, requester: senderUsername });
    // Immediately remove the request element from the UI
    const requestElement = document.getElementById(`request-${senderUsername}`);
    if (requestElement) {
        requestElement.remove();
    }
    // Re-fetch friends to ensure the list is accurate and includes the new friend
    fetchFriends();
}

/**
 * Rejects a pending friend request.
 * @param {string} senderUsername The username of the person who sent the request.
 */
function rejectFriendRequest(senderUsername) {
    console.log(`Rejecting request from: ${senderUsername}`);
    socket.emit('reject_friend_request', { rejecter: currentUser, requester: senderUsername });
    // Immediately remove the request element from the UI
    const requestElement = document.getElementById(`request-${senderUsername}`);
    if (requestElement) {
        requestElement.remove();
    }
    // Check if the "no friends" message should be displayed after rejection
    if (friendsContainer.querySelector('ul').children.length === 0) {
        noFriendsMessage.style.display = 'block';
    }
}

/**
 * Sends a message to the currently active chat partner.
 */
async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message) {
        // Do nothing if message is empty
        return;
    }

    if (!currentChatPartner || !currentChatRoom) {
        appendMessage("System", "Please select a friend to chat with.", 'error');
        return;
    }

    // Ensure we have the public key for the current chat partner
    if (!friendPublicKeys[currentChatPartner]) {
        appendMessage("System", `Public key for ${currentChatPartner} not found. Cannot encrypt message.`, 'error');
        console.error(`Public key missing for ${currentChatPartner}`);
        return;
    }

    try {
        // 1. Encrypt message for the recipient using their public key
        const encryptedMessageForReceiver = await encryptMessage(message, friendPublicKeys[currentChatPartner]);
        console.log("Encrypted for receiver (first 50 chars):", encryptedMessageForReceiver.substring(0, 50) + '...');

        // 2. Encrypt message for self (for chat history storage on the backend)
        // We need the user's own public key to encrypt for self.
        // It's assumed the privateKeyPem in sessionStorage corresponds to the current user.
        // We can derive the public key from the private key object if needed, or simply re-import our own public key.
        // For simplicity here, we'll re-derive public key from our private key's object.
        const privateKeyObj = await importPrivateKey(privateKeyPem);
        const publicKeyForSelfBuffer = await window.crypto.subtle.exportKey("spki", privateKeyObj.publicKey);
        const publicKeyForSelf = await importPublicKey(btoa(String.fromCharCode(...new Uint8Array(publicKeyForSelfBuffer))));
        const encryptedMessageForSelf = await encryptMessage(message, publicKeyForSelf);
        console.log("Encrypted for self (first 50 chars):", encryptedMessageForSelf.substring(0, 50) + '...');


        // Emit the message to the server
        socket.emit('send_message', {
            sender: currentUser,
            receiver: currentChatPartner,
            room: currentChatRoom,
            messageForReceiver: encryptedMessageForReceiver,
            messageForSelf: encryptedMessageForSelf // Store encrypted for self for history
        });

        // Display the sent message in the UI immediately
        appendMessage("You", message, 'sent');
        messageInput.value = ""; // Clear input after sending
    } catch (error) {
        console.error("Error sending message:", error);
        appendMessage("System", "Failed to send message due to encryption error.", 'error');
    }
}

// Event listener for Enter key to send message from the input field
messageInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
