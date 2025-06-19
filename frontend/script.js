// --- USER REGISTRATION ---
async function registerUser() {
  const username = document.getElementById("anonymousId").value.trim();
  const pin = document.getElementById("securePin").value;

  if (!username || !pin) {
    displayAuthMessage("Username and PIN are required.", true);
    return;
  }

  try {
    // Generate RSA key pair
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

    // Export public key (PEM format)
    const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;

    // Export private key (PEM format)
    const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyBuffer)));
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----`;

    // Save to sessionStorage
    sessionStorage.setItem("privateKey", privateKeyPem);
    sessionStorage.setItem("username", username);

    const res = await fetch(`${BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, pin, publicKey: publicKeyPem })
    });

    let data;
    try {
      data = await res.json();
    } catch (e) {
      const raw = await res.text();
      console.error("❌ Invalid JSON from /register:", raw);
      displayAuthMessage("❌ Server error during registration", true);
      return;
    }

    if (res.status === 409) {
      displayAuthMessage("⚠️ Username already registered. Please login instead.", true);
      return;
    }

    if (data.success) {
      displayAuthMessage("✅ Registered successfully");
      loginUser(username, pin); // Auto-login
    } else {
      displayAuthMessage("❌ " + data.message, true);
    }
  } catch (error) {
    console.error("Registration failed:", error);
    displayAuthMessage("❌ Error: " + error.message, true);
  }
}

// --- USER LOGIN ---
async function loginUser(username = null, pin = null) {
  const currentUsername = (username || document.getElementById("anonymousId").value).trim();
  const currentPin = (pin || document.getElementById("securePin").value);

  if (!currentUsername || !currentPin) {
    displayAuthMessage("Username and PIN are required.", true);
    return;
  }

  try {
    const res = await fetch(`${BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: currentUsername, pin: currentPin })
    });

    let data;
    try {
      data = await res.json();
    } catch (e) {
      const raw = await res.text();
      console.error("❌ Invalid JSON from /login:", raw);
      displayAuthMessage("❌ Server error during login", true);
      return;
    }

    if (data.success) {
      sessionStorage.setItem("username", currentUsername);
      displayAuthMessage("✅ Login successful. Redirecting...");
      window.location.href = "chat.html";
    } else {
      displayAuthMessage("❌ Login failed: " + data.message, true);
    }
  } catch (error) {
    console.error("Login error:", error);
    displayAuthMessage("❌ Login error: " + error.message, true);
  }
}
