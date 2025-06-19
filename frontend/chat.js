// chat.js

const socket = io(); // Connects to the current host by default
const backendUrl = "http://localhost:8000"; // Or your deployed backend URL
// const backendUrl = "https://your-deployed-backend.onrender.com"; // Example for deployed backend

let loggedInUsername = localStorage.getItem('loggedInUsername');
let ownKeyPair = null; // Will store the CryptoKey objects from script.js
let currentChatPartner = null;
let currentRoomId = null;
let currentChatAesKey = null; // AES key for the current active chat
const friendPublicKeys = {}; // Cache: { username: CryptoKeyObject }
const chatAesKeys = {}; // Cache for AES keys: { roomId: CryptoKeyObject }

document.addEventListener('DOMContentLoaded', async () => {
    if (!loggedInUsername) {
        alert("Not logged in. Redirecting to login page.");
        window.location.href = 'index.html';
        return;
    }

    document.getElementById('loggedInUser').textContent = loggedInUsername;

    // Load own keys from localStorage via the utility in script.js
    const privateKeyPem = localStorage.getItem('privateKey');
    const publicKeyPem = localStorage.getItem('publicKey');

    if (!privateKeyPem || !publicKeyPem) {
        console.error("❌ Critical: Own keys not found in localStorage. Redirecting to login.");
        alert("Your cryptographic keys are missing. Please log in again to regenerate.");
        window.location.href = 'index.html';
        return;
    }

    try {
        ownKeyPair = await window.CryptoUtils.importKeyPairFromPem(publicKeyPem, privateKeyPem);
        console.log("✅ Chat page: Successfully imported own key pair.");
        AuthKeys.OwnKeyPair = ownKeyPair; // Update global in AuthKeys if it wasn't already set

        // After successful key import, register the user with Socket.IO
        socket.emit('register_user', { username: loggedInUsername });
        fetchFriendsList();

    } catch (e) {
        console.error("❌ Chat page: Error importing own keys:", e);
        alert("Failed to load your cryptographic keys. Please try logging in again.");
        window.location.href = 'index.html';
    }

    // Event Listeners for UI
    document.getElementById('searchUserForm').addEventListener('submit', handleSearchUser);
    document.getElementById('sendRequestBtn').addEventListener('click', handleSendFriendRequest);
    document.getElementById('messageForm').addEventListener('submit', handleSendMessage);
    document.getElementById('friendsList').addEventListener('click', handleFriendListClick);
    document.getElementById('pendingRequestsList').addEventListener('click', handlePendingRequestClick);
});


// --- Socket.IO Event Handlers ---

socket.on('connect', () => {
    console.log('🔗 Connected to Socket.IO backend.');
});

socket.on('registered', (data) => {
    console.log('Socket.IO registration:', data.message);
    updateOnlineUsersDisplay(data.onlineUsers);
});

socket.on('online_users', (onlineUsers) => {
    console.log('Online users updated:', onlineUsers);
    updateOnlineUsersDisplay(onlineUsers);
});

socket.on('user_found', (data) => {
    const searchResultDiv = document.getElementById('searchResult');
    if (data.foundUser) {
        searchResultDiv.innerHTML = `Found: ${data.foundUser} <button id="sendRequestBtn" data-username="${data.foundUser}">Send Friend Request</button>`;
        // Store public key of found user
        friendPublicKeys[data.foundUser] = data.publicKey; // Store PEM string for now
        console.log(`Cached public key PEM for ${data.foundUser}`);
    } else {
        searchResultDiv.textContent = `User '${data.searchedUser}' not found.`;
    }
});

socket.on('friend_request_sent', (data) => {
    alert(`Friend request sent to ${data.receiver}.`);
    fetchFriendsList(); // Refresh lists
});

socket.on('friend_request_received', (data) => {
    alert(`You received a friend request from ${data.sender}!`);
    fetchFriendsList(); // Refresh lists
});

socket.on('friend_request_accepted', (data) => {
    alert(`Friend request from ${data.requester} accepted!`);
    fetchFriendsList(); // Refresh lists
});

socket.on('friend_request_rejected', (data) => {
    alert(`Friend request from ${data.rejecter} rejected.`);
    fetchFriendsList(); // Refresh lists
});

socket.on('friend_list_updated', () => {
    console.log("Friend list updated event received, refetching.");
    fetchFriendsList(); // Re-fetch friends and pending requests
});

socket.on('chat_approved', async (data) => {
    console.log('Chat approved data:', data);
    currentChatPartner = data.partner;
    currentRoomId = data.room;
    document.getElementById('chattingWith').textContent = `Chatting with: ${currentChatPartner}`;
    document.getElementById('messageInput').disabled = false;
    document.getElementById('sendMessageBtn').disabled = false;
    document.getElementById('chatHistory').innerHTML = ''; // Clear previous history

    // Determine if this is a new chat (no existing AES key in cache)
    if (!chatAesKeys[currentRoomId]) {
        console.log("No existing AES key for this chat. Establishing new key.");
        // This is simplified: in a real app, you'd have a key exchange mechanism.
        // For demonstration, let's assume one user generates and shares it.
        // If 'data.history' is empty or doesn't contain a key exchange message
        // one of the users (e.g., the initiator) should generate and send the AES key.
        // For simplicity, we'll generate one here if not present in history.

        let symmetricKeyReceived = false;
        for(const msg of data.history) {
            // Check for a specific 'key_exchange' type message
            // This is just a placeholder logic, a proper protocol is needed.
            if (msg.type === 'aes_key_exchange' && msg.sender !== loggedInUsername) {
                try {
                    const decryptedAesKeyRaw = await window.CryptoUtils.rsaDecrypt(msg.message, ownKeyPair.privateKey);
                    currentChatAesKey = await window.CryptoUtils.importAesKeyRaw(decryptedAesKeyRaw);
                    chatAesKeys[currentRoomId] = currentChatAesKey;
                    console.log("✅ Received and decrypted AES key from partner.");
                    symmetricKeyReceived = true;
                    break;
                } catch (e) {
                    console.error("❌ Failed to decrypt received AES key:", e);
                    // This is a critical error, cannot proceed with chat
                    alert("Failed to establish secure chat: could not decrypt symmetric key.");
                    return;
                }
            }
        }

        if (!symmetricKeyReceived) {
            console.log("Generating new AES key for this chat...");
            currentChatAesKey = await window.CryptoUtils.generateAesKey();
            chatAesKeys[currentRoomId] = currentChatAesKey;
            console.log("✅ Generated new AES key for chat.");

            // Export raw AES key to base64 for encryption
            const rawAesKeyB64 = await window.CryptoUtils.exportAesKeyRaw(currentChatAesKey);

            // Get partner's public key (already cached or fetched)
            const partnerPublicKeyPem = friendPublicKeys[currentChatPartner];
            if (!partnerPublicKeyPem) {
                console.error("❌ Partner's public key not available for AES key encryption.");
                alert("Cannot start chat: Partner's public key is missing.");
                return;
            }
            const partnerPublicKey = await window.CryptoUtils.importKeyPairFromPem(partnerPublicKeyPem, null).then(kp => kp.publicKey);

            // Encrypt the raw AES key with the partner's public key
            const encryptedAesKeyForPartner = await window.CryptoUtils.rsaEncrypt(rawAesKeyB64, partnerPublicKey);

            // Send this encrypted key as a special message type
            socket.emit('send_message', {
                sender: loggedInUsername,
                receiver: currentChatPartner,
                room: currentRoomId,
                messageForReceiver: encryptedAesKeyForPartner, // Encrypted AES key
                messageForSelf: "[AES Key Exchange Initiated]", // A placeholder for sender's history
                originalMessageContent: "[AES Key Exchange]", // For backend scan
                type: 'aes_key_exchange' // Custom type for key exchange message
            });
            console.log("Sent encrypted AES key to partner.");
        }
    } else {
        console.log("Using existing AES key for this chat.");
        currentChatAesKey = chatAesKeys[currentRoomId];
    }

    // Process chat history only after AES key is established
    if (currentChatAesKey) {
        console.log("Displaying chat history...");
        for (const msg of data.history) {
            // Skip key exchange messages from history display if they're not actual chat messages
            if (msg.type === 'aes_key_exchange') {
                 // You might want to display a notification that key exchange happened
                console.log(`Skipping key exchange message in history display.`);
                continue;
            }
            let decryptedMessage = await window.CryptoUtils.aesDecrypt(msg.message, currentChatAesKey);

            // If it's a message you sent, the stored 'message' field is what you need
            // If it's a message from someone else, and you've stored 'messageForReceiver' differently,
            // you'd need to handle that. But given backend stores 'messageForSelf', this should work for both.
            if (msg.sender !== loggedInUsername && msg.messageForReceiver) { // This part is tricky. Backend stores 'message' as self-encrypted.
                // Re-fetch history for the active room after the partner is joined
                // The backend stores the "messageForSelf" as "message" for the sender.
                // So when history is loaded, a message from the other person needs to be decrypted.
                // If backend only stores one 'message' field, it must be the 'messageForSelf' from the sender.
                // For the receiver, the backend just broadcasts 'messageForReceiver'.
                // So, if the history message `msg.message` is meant for *you* (the receiver in the past),
                // it should have been encrypted with your public key, then by the shared AES key.
                // This means the `msg.message` in history *must* be the AES-encrypted message.
                // If it was encrypted with RSA initially for the recipient, that's not stored in common history.
                // Let's assume the `msg.message` in history is the AES encrypted one.
                // If it was from `loggedInUsername`, it's `messageForSelf`. If from partner, it's `messageForReceiver`.
                // BUT backend saves `messageForSelf` from the sender into 'messages' field for history.
                // THIS IS A MAJOR SOURCE OF ERROR. Backend should save two encrypted versions, or a way to distinguish.
                // For simplicity, let's assume 'message' in history is AES-encrypted.
                // The `send_message` in app.py updates with `message: message_for_self` - this means history will *always* show sender's own encrypted view.
                // The `receive_message` emits `message: message_for_receiver`. This is only for LIVE messages.
                // To fix history: Backend needs to store 'messageForSender' and 'messageForReceiver' for EACH message, or ensure they are the same after AES.
                // **Corrected Assumption:** The backend stores `message_for_self` for all messages in the `messages` array of the chat room.
                // This means, for messages you sent, `msg.message` is what you originally stored.
                // For messages your *friend* sent, `msg.message` is what *they* stored (their `messageForSelf`).
                // This implies that the AES key *must* be derived symmetrically, or exchanged so both parties
                // encrypt with the same key. The current AES logic already does this if key exchange works.
                // So, the `msg.message` in history should be decryptable by the shared AES key.
            }
            addMessageToChat(msg.sender, decryptedMessage, msg.timestamp);
        }
    } else {
        console.error("❌ AES key not established for chat. Cannot display history.");
    }
});

socket.on('receive_message', async (data) => {
    console.log('Received message:', data);
    // Ensure the message is for the currently active chat
    if (data.room === currentRoomId && currentChatAesKey) {
        let decryptedMessage = await window.CryptoUtils.aesDecrypt(data.message, currentChatAesKey);
        addMessageToChat(data.sender, decryptedMessage, data.timestamp);
    } else if (data.room !== currentRoomId) {
        console.log(`Received message for inactive chat room ${data.room}.`);
        // You might want to show a notification for messages from other chats
    } else {
        console.error("❌ Received message but no active AES key for current chat.");
    }
});

socket.on('message_blocked', (data) => {
    alert(`Your message was blocked: ${data.reason}.`);
    console.warn("Message blocked by server:", data);
});

socket.on('message_from_friend_blocked', (data) => {
    alert(`A message from ${data.sender} was blocked by the server due to malicious content detection.`);
    console.warn("Friend's message blocked by server:", data);
});

socket.on('error', (data) => {
    console.error('Socket.IO Error:', data.message);
    alert('Server Error: ' + data.message);
});

socket.on('disconnect', () => {
    console.log('🔗 Disconnected from Socket.IO backend.');
    // Handle re-connection or show disconnected status
});


// --- UI and Data Fetching Functions ---

async function fetchFriendsList() {
    try {
        const response = await fetch(`${backendUrl}/friends?username=${loggedInUsername}`);
        const data = await response.json();
        console.log("Friends list fetched:", data);

        if (data.success) {
            const friendsListDiv = document.getElementById('friendsList');
            friendsListDiv.innerHTML = '<h3>Your Friends</h3>';
            if (data.friends && data.friends.length > 0) {
                data.friends.forEach(friend => {
                    const friendDiv = document.createElement('div');
                    friendDiv.className = 'friend-item';
                    friendDiv.innerHTML = `
                        <span>${friend.username}</span>
                        <span class="status ${friend.status}">● ${friend.status}</span>
                        <button class="chat-button" data-username="${friend.username}">Chat</button>
                    `;
                    friendsListDiv.appendChild(friendDiv);
                    // Cache friend's public key (PEM string)
                    friendPublicKeys[friend.username] = friend.publicKey;
                });
            } else {
                friendsListDiv.innerHTML += '<p>No friends yet. Search for users!</p>';
            }

            const pendingRequestsListDiv = document.getElementById('pendingRequestsList');
            pendingRequestsListDiv.innerHTML = '<h3>Pending Requests</h3>';
            if (data.pendingRequests && data.pendingRequests.length > 0) {
                data.pendingRequests.forEach(requester => {
                    const requestDiv = document.createElement('div');
                    requestDiv.className = 'pending-request-item';
                    requestDiv.innerHTML = `
                        <span>${requester}</span>
                        <button class="accept-request" data-requester="${requester}">Accept</button>
                        <button class="reject-request" data-requester="${requester}">Reject</button>
                    `;
                    pendingRequestsListDiv.appendChild(requestDiv);
                });
            } else {
                pendingRequestsListDiv.innerHTML += '<p>No pending requests.</p>';
            }
        } else {
            console.error('Failed to fetch friends:', data.message);
            alert('Failed to load friends list: ' + data.message);
        }
    } catch (error) {
        console.error('Network error fetching friends:', error);
        alert('Network error while fetching friends list.');
    }
}

function updateOnlineUsersDisplay(onlineUsers) {
    const onlineUsersDiv = document.getElementById('onlineUsers');
    onlineUsersDiv.innerHTML = '<h3>Online Users</h3>';
    if (onlineUsers && onlineUsers.length > 0) {
        onlineUsers.forEach(user => {
            if (user !== loggedInUsername) { // Don't list yourself as online friend
                const userDiv = document.createElement('div');
                userDiv.textContent = user;
                onlineUsersDiv.appendChild(userDiv);
            }
        });
    } else {
        onlineUsersDiv.innerHTML += '<p>No other users online.</p>';
    }
    // Also update status in friends list if it's already displayed
    document.querySelectorAll('.friend-item').forEach(item => {
        const username = item.querySelector('span').textContent;
        const statusSpan = item.querySelector('.status');
        if (statusSpan) {
            if (onlineUsers.includes(username)) {
                statusSpan.textContent = '● online';
                statusSpan.className = 'status online';
            } else {
                statusSpan.textContent = '● offline';
                statusSpan.className = 'status offline';
            }
        }
    });
}

function addMessageToChat(sender, message, timestamp) {
    const chatHistory = document.getElementById('chatHistory');
    const messageDiv = document.createElement('div');
    messageDiv.className = sender === loggedInUsername ? 'message-sent' : 'message-received';

    const date = new Date(timestamp); // Parse ISO string
    const timeString = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const dateString = date.toLocaleDateString();

    messageDiv.innerHTML = `
        <strong>${sender}:</strong> ${message}
        <span class="timestamp">${dateString} ${timeString}</span>
    `;
    chatHistory.appendChild(messageDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight; // Scroll to bottom
}

// --- Event Handlers for Buttons/Forms ---

async function handleSearchUser(e) {
    e.preventDefault();
    const searchUsername = document.getElementById('searchUserInput').value.trim();
    if (searchUsername && searchUsername !== loggedInUsername) {
        socket.emit('search_user', { username: searchUsername });
    } else {
        document.getElementById('searchResult').textContent = 'Please enter a valid username (not your own).';
    }
}

function handleSendFriendRequest(e) {
    const receiver = e.target.dataset.username;
    if (receiver) {
        socket.emit('send_friend_request', { sender: loggedInUsername, receiver: receiver });
        document.getElementById('searchResult').textContent = ''; // Clear search result
        document.getElementById('searchUserInput').value = ''; // Clear search input
    }
}

function handleFriendListClick(e) {
    if (e.target.classList.contains('chat-button')) {
        const partnerUsername = e.target.dataset.username;
        if (partnerUsername) {
            console.log(`Requesting chat with ${partnerUsername}`);
            socket.emit('request_chat', { sender: loggedInUsername, receiver: partnerUsername });
        }
    }
}

function handlePendingRequestClick(e) {
    const requester = e.target.dataset.requester;
    if (!requester) return;

    if (e.target.classList.contains('accept-request')) {
        socket.emit('accept_friend_request', { acceptor: loggedInUsername, requester: requester });
    } else if (e.target.classList.contains('reject-request')) {
        socket.emit('reject_friend_request', { rejecter: loggedInUsername, requester: requester });
    }
}

async function handleSendMessage(e) {
    e.preventDefault();
    const messageInput = document.getElementById('messageInput');
    const originalMessageContent = messageInput.value.trim();

    if (!originalMessageContent || !currentChatPartner || !currentRoomId || !currentChatAesKey) {
        alert("Cannot send empty message, or chat not active.");
        return;
    }

    try {
        // Encrypt message with the shared AES key
        const encryptedMessageForSelf = await window.CryptoUtils.aesEncrypt(originalMessageContent, currentChatAesKey);
        const encryptedMessageForReceiver = encryptedMessageForSelf; // For symmetric AES, it's the same

        socket.emit('send_message', {
            sender: loggedInUsername,
            receiver: currentChatPartner,
            room: currentRoomId,
            messageForReceiver: encryptedMessageForReceiver,
            messageForSelf: encryptedMessageForSelf,
            originalMessageContent: originalMessageContent // Send unencrypted for backend malicious content check
        });

        messageInput.value = ''; // Clear input field
    } catch (error) {
        console.error("❌ Error sending message:", error);
        alert("Failed to send message due to encryption error.");
    }
}

// Function to leave a chat (e.g., when selecting a new friend, or on disconnect)
function leaveCurrentChat() {
    if (currentRoomId) {
        socket.emit('leave_room', currentRoomId);
        currentChatPartner = null;
        currentRoomId = null;
        currentChatAesKey = null; // Clear AES key on leaving chat
        document.getElementById('chattingWith').textContent = 'Chat Box';
        document.getElementById('chatHistory').innerHTML = '';
        document.getElementById('messageInput').disabled = true;
        document.getElementById('sendMessageBtn').disabled = true;
    }
}

// Consider calling leaveCurrentChat if a new chat is initiated, or when user navigates away.
// For simplicity, this example just switches chat.
document.getElementById('friendsList').addEventListener('click', (e) => {
    if (e.target.classList.contains('chat-button')) {
        leaveCurrentChat(); // Leave old chat before starting new one
        // ... then trigger handleFriendListClick logic
        handleFriendListClick(e);
    }
});
