// ✅ 1. Declare constants at the top
const BASE_URL = "https://securechat-frontend-9qs2.onrender.com";
console.log("Connecting to backend:", BASE_URL);

// ✅ 2. Utility: Display authentication messages
function displayAuthMessage(message, isError = false) {
  const authMessageElement = document.getElementById("authMessage");
  if (!authMessageElement) return; // Prevent error if element not found
  authMessageElement.textContent = message;
  authMessageElement.style.color = isError ? "red" : "green";
  setTimeout(() => {
    authMessageElement.textContent = "";
  }, 5000);
}

// ✅ 3. Check for private key on load
window.addEventListener("DOMContentLoaded", () => {
  const username = sessionStorage.getItem("username");
  const privateKey = sessionStorage.getItem("privateKey");
  if (username && !privateKey) {
    displayAuthMessage("⚠️ Warning: You are logged in but your private key is missing. Re-register or import it manually.", true);
  }
});

// ✅ 4. Connect to backend via Socket.IO
const socket = io(BASE_URL);

socket.on("connect", () => {
  const username = sessionStorage.getItem("username")?.trim();
  if (username) {
    socket.emit("register_user", { username });
    console.log(`✅ Socket connected and registered as ${username}`);
  }
});

socket.on("registered", (data) => {
  console.log("🔔 Backend confirmation:", data.message);
});

socket.on("error", (data) => {
  console.error("❌ Backend error:", data.message);
  displayAuthMessage("Error: " + data.message, true);
});

// ✅ 5. Define registerUser and loginUser below this point
// registerUser()
// loginUser()
