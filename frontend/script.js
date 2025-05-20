const API_BASE_URL = "https://securechatapp-ys8y.onrender.com/"; // Replace with your backend URL

// Function to hash the pin before sending it
async function hashPin(pin) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pin);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Check if user is already logged in via sessionStorage
window.onload = function () {
  const username = sessionStorage.getItem("username");
  if (username) {
    alert(`Welcome back, ${username}!`);
    window.location.href = "chat.html"; // Redirect to chat page
  }
};

// Main function triggered by Start Chat button
async function startChat() {
  const username = document.getElementById('username').value.trim();
  const pin = document.getElementById('pin').value.trim();

  if (!username || !pin) {
    alert("Please fill in both fields.");
    return;
  }

  const usernameRegex = /^[a-zA-Z0-9_]+$/;
  if (!usernameRegex.test(username)) {
    alert("Username can only contain letters, numbers, and underscores.");
    return;
  }

  const button = document.querySelector('button');
  button.disabled = true;
  button.textContent = "Processing...";

  try {
    const hashedPin = await hashPin(pin);

    console.log("Sending to /check-user:", username);

    const checkUserRes = await fetch(`${API_BASE_URL}/check-user`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });

    const checkUserData = await checkUserRes.json();

    console.log("Response from /check-user:", checkUserData);

    if (checkUserData.exists) {
      await loginUser(username, hashedPin);
    } else {
      await registerUser(username, hashedPin);
    }
  } catch (error) {
    console.error("Error during startChat:", error);
    alert("An error occurred. Please try again.");
  } finally {
    button.disabled = false;
    button.textContent = "Start Chat";
  }
}

// Login function
async function loginUser(username, hashedPin) {
  try {
    const response = await fetch(`${API_BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, pin: hashedPin })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      alert(`Welcome back, ${username}!`);
      sessionStorage.setItem("username", username);
      window.location.href = "chat.html";
    } else {
      alert("Login Failed: " + (data.message || "Unknown error"));
    }
  } catch (error) {
    console.error("Login error:", error);
    alert("Could not log in.");
  }
}

// Registration function
async function registerUser(username, hashedPin) {
  try {
    const response = await fetch(`${API_BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, pin: hashedPin })
    });

    const data = await response.json();

    if (response.ok && data.success) {
      alert(`Registration successful! Welcome, ${username}!`);
      sessionStorage.setItem("username", username);
      window.location.href = "chat.html";
    } else {
      alert("Registration Failed: " + (data.message || "Unknown error"));
    }
  } catch (error) {
    console.error("Registration error:", error);
    alert("Could not register.");
  }
}
