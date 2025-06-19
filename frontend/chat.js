// chat.js

const BASE_URL = "https://securechatapp-ys8y.onrender.com";
const socket = io(BASE_URL);

let currentUser = sessionStorage.getItem("username");
let privateKeyPem = sessionStorage.getItem("privateKey");
let currentChatPartner = null; // Stores the username of the actively chatting friend
let currentChatRoom = null;    // Stores the current chat room ID
let friendPublicKeys = {};     // Cache for friend public keys {username: publicKeyObject}

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
    if (!currentUser || !privateKeyPem) {
        alert("You are not logged in. Please log in first.");
        window.location.href = "index.html"; // Redirect to login page
        return;
    }
    userNameDisplay.textContent = currentUser;

    // Connect to Socket.IO and register the user
    socket.emit("register_user", { username: currentUser });
    console.log(`Sending 'register_user' for: ${currentUser}`);

    // Fetch and display friends
    await fetchFriends();
});

// --- Utility Functions ---

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
    } else { // info or error
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
 * Imports a PEM formatted public key into a CryptoKey object.
 * @param {string} pem The PEM formatted public key.
 * @returns {Promise<CryptoKey>} The CryptoKey object.
 */
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

/**
 * Imports a PEM formatted private key into a CryptoKey object.
 * @param {string} pem The PEM formatted private key.
 * @returns {Promise<CryptoKey>} The CryptoKey object.
 */
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

/**
 * Encrypts a message using a public key.
 * @param {string} message The message to encrypt.
 * @param {CryptoKey} publicKey The public key to use for encryption.
 * @returns {Promise<string>} The base64 encoded encrypted message.
 */
async function encryptMessage(message, publicKey) {
    const encoded = new TextEncoder().encode(message);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        encoded
    );
    return btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
}

/**
 * Decrypts a message using a private key.
 * @param {string} encryptedBase64 The base64 encoded encrypted message.
 * @param {CryptoKey} privateKey The private key to use for decryption.
 * @returns {Promise<string>} The decrypted message.
 */
async function decryptMessage(encryptedBase664, privateKey) {
    const encryptedBuffer = Uint8Array.from(atob(encryptedBase664), c => c.charCodeAt(0));
    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedBuffer
        );
        return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
        console.error("Decryption failed:", e);
        return "[Could not decrypt message]"; // Indicate decryption failure
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
        updateFriendOnlineStatus(data.onlineUsers);
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
    // Check if the request is already displayed
    const existingRequest = document.getElementById(`request-${data.sender}`);
    if (existingRequest) {
        console.log(`Friend request from ${data.sender} already displayed.`);
        return;
    }

    appendMessage("System", `Friend request from ${data.sender}.`, 'info');
    const friendRequestElement = document.createElement("li");
    friendRequestElement.id = `request-${data.sender}`;
    friendRequestElement.classList.add("friend-item", "request"); // Add request class for styling
    friendRequestElement.innerHTML = `
        <span>${data.sender} (Pending Request)</span>
        <div>
            <button onclick="acceptFriendRequest('${data.sender}')" style="background-color: #28a745; width: auto; margin: 0 5px;">Accept</button>
            <button onclick="rejectFriendRequest('${data.sender}')" style="background-color: #dc3545; width: auto; margin: 0 5px;">Reject</button>
        </div>
    `;
    friendsContainer.querySelector('ul').prepend(friendRequestElement); // Add to top of friend list
    noFriendsMessage.style.display = 'none'; // Hide "no friends" message
});

socket.on('friend_request_accepted', (data) => {
    appendMessage("System", `${data.requester} accepted your friend request!`, 'info');
    displaySearchMessage(`${data.requester} is now your friend!`, false);
    fetchFriends(); // Refresh friends list
});

socket.on('friend_request_rejected', (data) => {
    appendMessage("System", `${data.rejecter} rejected your friend request.`, 'info');
    displaySearchMessage(`${data.rejecter} rejected your friend request.`, true);
    // Remove the request element if it exists in the list
    const requestElement = document.getElementById(`request-${data.rejecter}`);
    if (requestElement) {
        requestElement.remove();
    }
});

socket.on('friend_list_updated', async () => {
    console.log("Friend list updated, re-fetching friends.");
    await fetchFriends();
});

socket.on('chat_approved', async (data) => {
    console.log(`Chat approved with: ${data.partner} in room: ${data.room}`);
    currentChatPartner = data.partner;
    currentChatRoom = data.room;
    currentChatPartnerDisplay.textContent = `(Chatting with: ${currentChatPartner})`;

    // Enable message input and send button
    messageInput.removeAttribute("disabled");
    sendButton.removeAttribute("disabled");
    messageInput.focus();

    // Clear previous chat messages
    chatBox.innerHTML = '';
    appendMessage("System", `You are now chatting with ${currentChatPartner}.`, 'info');

    // Display chat history if available
    if (data.history && data.history.length > 0) {
        appendMessage("System", "Loading chat history...", 'info');
        const privateKey = await importPrivateKey(privateKeyPem);
        for (const msg of data.history) {
            let decryptedMessage;
            try {
                decryptedMessage = await decryptMessage(msg.message, privateKey);
            } catch (e) {
                decryptedMessage = "[Decryption Failed]";
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
        console.log(`Received message for a different room or sender. Room: ${data.room}, Sender: ${data.sender}`);
        // Optionally, add a notification for messages from other chats
        appendMessage("System", `New message from ${data.sender}. Select them to view.`, 'info');
        // You might want to update the UI to highlight the friend who sent a new message
        const friendItem = document.querySelector(`.friend-item[data-username="${data.sender}"]`);
        if (friendItem && !friendItem.classList.contains('active-chat')) {
            friendItem.classList.add('new-message-indicator'); // Add a class for visual notification
        }
    }
});

socket.on('online_users', (onlineUsers) => {
    console.log("Updated online users:", onlineUsers);
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

// --- Chat Functions ---

async function fetchFriends() {
    try {
        const res = await fetch(`${BASE_URL}/friends?username=${currentUser}`);
        const data = await res.json();

        const friendsListUl = friendsContainer.querySelector('ul');
        friendsListUl.innerHTML = ''; // Clear existing friends

        if (data.friends && data.friends.length > 0) {
            noFriendsMessage.style.display = 'none';
            data.friends.forEach(friend => {
                addFriendToList(friend.username, friend.status, friend.publicKey);
            });
            updateFriendOnlineStatus(socket.onlineUsers || []); // Update initial status
        } else {
            noFriendsMessage.style.display = 'block';
        }

        // Handle pending requests separately if necessary (or integrate into friends list)
        if (data.pendingRequests && data.pendingRequests.length > 0) {
            data.pendingRequests.forEach(sender => {
                // Check if already displayed to prevent duplicates on re-fetch
                if (!document.getElementById(`request-${sender}`)) {
                    const friendRequestElement = document.createElement("li");
                    friendRequestElement.id = `request-${sender}`;
                    friendRequestElement.classList.add("friend-item", "request");
                    friendRequestElement.innerHTML = `
                        <span>${sender} (Pending Request)</span>
                        <div>
                            <button onclick="acceptFriendRequest('${sender}')" style="background-color: #28a745; width: auto; margin: 0 5px;">Accept</button>
                            <button onclick="rejectFriendRequest('${sender}')" style="background-color: #dc3545; width: auto; margin: 0 5px;">Reject</button>
                        </div>
                    `;
                    friendsListUl.prepend(friendRequestElement);
                    noFriendsMessage.style.display = 'none';
                }
            });
        }
    } catch (error) {
        console.error("Error fetching friends:", error);
        appendMessage("System", "Failed to load friends.", 'error');
    }
}

function addFriendToList(friendUsername, status = 'offline', publicKeyPemString) {
    const friendsListUl = friendsContainer.querySelector('ul');
    let friendItem = document.querySelector(`.friend-item[data-username="${friendUsername}"]`);

    if (!friendItem) { // Only create if it doesn't exist
        friendItem = document.createElement("li");
        friendItem.classList.add("friend-item");
        friendItem.setAttribute("data-username", friendUsername);
        friendItem.innerHTML = `<span>${friendUsername}</span>`;
        friendItem.addEventListener('click', () => selectFriend(friendUsername));
        friendsListUl.appendChild(friendItem);
    }

    // Update status classes
    friendItem.classList.remove('online', 'offline', 'request'); // Remove all status classes first
    friendItem.classList.add(status);

    // Cache public key (if provided)
    if (publicKeyPemString) {
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
        if (username) { // Ensure it's a friend item, not a request item
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
    // Remove 'active-chat' class from previously selected friend
    const activeFriend = document.querySelector('.friend-item.active-chat');
    if (activeFriend) {
        activeFriend.classList.remove('active-chat');
    }

    // Add 'active-chat' class to the newly selected friend
    const selectedFriendElement = document.querySelector(`.friend-item[data-username="${friendUsername}"]`);
    if (selectedFriendElement) {
        selectedFriendElement.classList.add('active-chat');
        selectedFriendElement.classList.remove('new-message-indicator'); // Clear new message indicator
    }

    console.log(`Selected friend: ${friendUsername}`);
    // Request to initiate chat (backend will handle room creation/retrieval)
    socket.emit('request_chat', { sender: currentUser, receiver: friendUsername });
}

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
    console.log(`Searching for user: ${searchUsername}`);
    socket.emit('search_user', { username: searchUsername });
}

function acceptFriendRequest(senderUsername) {
    console.log(`Accepting request from: ${senderUsername}`);
    socket.emit('accept_friend_request', { acceptor: currentUser, requester: senderUsername });
    // Remove the request element from the UI immediately
    const requestElement = document.getElementById(`request-${senderUsername}`);
    if (requestElement) {
        requestElement.remove();
    }
    fetchFriends(); // Re-fetch friends to update the list with the new friend
}

function rejectFriendRequest(senderUsername) {
    console.log(`Rejecting request from: ${senderUsername}`);
    socket.emit('reject_friend_request', { rejecter: currentUser, requester: senderUsername });
    // Remove the request element from the UI immediately
    const requestElement = document.getElementById(`request-${senderUsername}`);
    if (requestElement) {
        requestElement.remove();
    }
    if (friendsContainer.querySelector('ul').children.length === 0) {
        noFriendsMessage.style.display = 'block';
    }
}

async function sendMessage() {
    const message = messageInput.value.trim();
    if (!message || !currentChatPartner || !currentChatRoom) {
        appendMessage("System", "Please select a friend to chat with and type a message.", 'error');
        return;
    }

    if (!friendPublicKeys[currentChatPartner]) {
        appendMessage("System", `Public key for ${currentChatPartner} not found. Cannot encrypt message.`, 'error');
        console.error(`Public key missing for ${currentChatPartner}`);
        return;
    }

    try {
        // Encrypt message for the recipient
        const encryptedMessageForReceiver = await encryptMessage(message, friendPublicKeys[currentChatPartner]);
        console.log("Encrypted for receiver (first 50 chars):", encryptedMessageForReceiver.substring(0, 50) + '...');

        // Encrypt message for self (for chat history storage)
        const privateKeyObj = await importPrivateKey(privateKeyPem);
        const publicKeyFromPrivate = await window.crypto.subtle.exportKey("spki", privateKeyObj.publicKey); // Re-export public key from private
        const publicKeySelf = await importPublicKey(btoa(String.fromCharCode(...new Uint8Array(publicKeyFromPrivate)))); // Import it as a CryptoKey
        const encryptedMessageForSelf = await encryptMessage(message, publicKeySelf);
        console.log("Encrypted for self (first 50 chars):", encryptedMessageForSelf.substring(0, 50) + '...');

        socket.emit('send_message', {
            sender: currentUser,
            receiver: currentChatPartner,
            room: currentChatRoom,
            messageForReceiver: encryptedMessageForReceiver,
            messageForSelf: encryptedMessageForSelf // Store encrypted for self for history
        });

        appendMessage("You", message, 'sent');
        messageInput.value = ""; // Clear input after sending
    } catch (error) {
        console.error("Error sending message:", error);
        appendMessage("System", "Failed to send message due to encryption error.", 'error');
    }
}

// Event listener for Enter key to send message
messageInput.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        sendMessage();
    }
});
