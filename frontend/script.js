const BASE_URL = "https://securechatapp-ys8y.onrender.com";
console.log("Connecting to backend:", BASE_URL);


async function registerUser() {
  const username = document.getElementById("anonymousId").value;
  const pin = document.getElementById("securePin").value;

  // Generate RSA key pair using SubtleCrypto
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
// Export public key to PEM format (for sending to server) 
const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

console.log("✅ Public Key PEM:\n", publicKeyPem); // <--- ✅ Add this line here

console.log("Registering user:", { username, pin, publicKeyPem });

// Export private key to PEM and store in sessionStorage
const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));
const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----`;

sessionStorage.setItem("privateKey", privateKeyPem); // Store locally
sessionStorage.setItem("username", username);

// Send public key to backend
fetch(`${BASE_URL}/register`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    username,
    pin,
    publicKey: publicKeyPem
  })
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
