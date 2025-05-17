// Backend URL deployed on Render
const API_BASE_URL = "https://securechatapp-ys8y.onrender.com";

// Function to hash the pin before sending it
async function hashPin(pin) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pin);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Check if the user is already logged in from session storage
window.onload = function() {
  const username = sessionStorage.getItem("username");
  if (username) {
    alert(`Welcome back, ${username}!`);
    window.location.href = "chat.html";  // Redirect to chat page
  }
};

function startChat() {
  const username = document.getElementById('username').value.trim();
  const pin = document.getElementById('pin').value.trim();

  if (username === "" || pin === "") {
    alert("Please fill in both fields.");
    return;
  }

  const usernameRegex = /^[a-zA-Z0-9_]+$/;
  if (!usernameRegex.test(username)) {
    alert("Username can only contain letters, numbers, and underscores.");
    return;
  }

  hashPin(pin).then(hashedPin => {
    // Check if the user already exists in the backend
    fetch(`${API_BASE_URL}/check-user`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    })
    .then(response => response.json())
    .then(result => {
      if (result.exists) {
        // User exists → try logging in
        loginUser(username, hashedPin);
      } else {
        // User does not exist → register first
        registerUser(username, hashedPin);
      }
    })
    .catch(err => {
      console.error("Error checking user existence:", err);
      alert("Error checking username. Try again.");
    });
  }).catch(err => {
    console.error("Pin hashing error:", err);
    alert("Error hashing pin.");
  });
}

// Function to log in
function loginUser(username, hashedPin) {
  fetch(`${API_BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, pin: hashedPin })
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Pop-up message for returning users
      alert("Welcome back, " + username + "!");
      sessionStorage.setItem("username", username);  // Save username in sessionStorage
      window.location.href = "chat.html";  // Redirect to chat page
    } else {
      alert("Login Failed: " + data.message);
    }
  })
  .catch(error => {
    console.error("Login error:", error);
    alert("Could not log in.");
  });
}

// Function to register
function registerUser(username, hashedPin) {
  fetch(`${API_BASE_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, pin: hashedPin })
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Pop-up message for new users
      alert("Registration successful! Welcome, " + username + "!");
      sessionStorage.setItem("username", username);  // Save username in sessionStorage
      window.location.href = "chat.html";  // Redirect to chat page
    } else {
      alert("Registration Failed: " + data.message);
    }
  })
  .catch(error => {
    console.error("Registration error:", error);
    alert("Could not register.");
  });
}
