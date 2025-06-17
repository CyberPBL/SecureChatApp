const BASE_URL = "https://securechatapp-ys8y.onrender.com"; // Or your backend URL

function registerUser() {
  const username = document.getElementById("anonymousId").value;
  const pin = document.getElementById("securePin").value;

  fetch(`${BASE_URL}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, pin })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        alert("✅ Registered successfully");
      } else {
        alert("❌ " + data.message);
      }
    });
}

function loginUser() {
  const username = document.getElementById("anonymousId").value;
  const pin = document.getElementById("securePin").value;

  fetch(`${BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, pin })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        sessionStorage.setItem("username", username);
        window.location.href = "chat.html";
      } else {
        document.getElementById("authMessage").textContent = "Login failed: " + data.message;
      }
    });
}
