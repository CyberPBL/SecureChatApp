function startChat() {
  const username = document.getElementById('username').value;
  const pin = document.getElementById('pin').value;

  if (username.trim() === "" || pin.trim() === "") {
    alert("Please fill in both fields.");
    return;
  }

  fetch("http://127.0.0.1:5000/start-chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ username, pin })
  })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        alert(data.message);
        localStorage.setItem("username", username);
        window.location.href = "chat.html";
      } else {
        alert("Failed: " + data.message);
      }
    })
    .catch(error => {
      console.error("Error:", error);
      alert("Something went wrong while contacting backend.");
    });
}
