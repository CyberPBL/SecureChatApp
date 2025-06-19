// script.js

const backendUrl = "http://localhost:8000"; // Or your deployed backend URL
// const backendUrl = "https://your-deployed-backend.onrender.com"; // Example for deployed backend

let ownKeyPair = null; // To store the CryptoKey objects for the current session

document.addEventListener('DOMContentLoaded', async () => {
    // Check if keys already exist in localStorage
    const privateKeyPem = localStorage.getItem('privateKey');
    const publicKeyPem = localStorage.getItem('publicKey');

    if (privateKeyPem && publicKeyPem) {
        console.log("✅ Keys found in localStorage. Attempting to import.");
        try {
            const importedKeys = await importKeyPairFromPem(publicKeyPem, privateKeyPem);
            ownKeyPair = importedKeys;
            console.log("✅ Successfully imported existing key pair.");
        } catch (e) {
            console.error("❌ Error importing existing keys from localStorage:", e);
            // If import fails, clear them to force new generation
            localStorage.removeItem('privateKey');
            localStorage.removeItem('publicKey');
            console.log("Cleared corrupted keys. Will generate new ones.");
            await generateAndStoreNewKeys();
        }
    } else {
        console.log("No keys found in localStorage. Generating new pair...");
        await generateAndStoreNewKeys();
    }

    // Event listener for registration form submission
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('registerUsername').value.trim();
            const pin = document.getElementById('registerPin').value;

            if (!ownKeyPair) {
                alert("Cryptographic keys not ready. Please refresh and try again.");
                return;
            }

            try {
                // Export public key to PEM string for sending to backend
                const publicKeyPemString = await exportKeyToPem(ownKeyPair.publicKey, 'public');

                const response = await fetch(`${backendUrl}/register`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        pin: pin,
                        publicKey: publicKeyPemString
                    })
                });

                const data = await response.json();
                const messageDiv = document.getElementById('message');
                if (data.success) {
                    messageDiv.textContent = data.message + " You can now log in.";
                    messageDiv.style.color = 'green';
                    // Clear form or redirect to login
                    document.getElementById('registerForm').reset();
                } else {
                    messageDiv.textContent = data.message;
                    messageDiv.style.color = 'red';
                }
            } catch (error) {
                console.error('Error during registration:', error);
                document.getElementById('message').textContent = 'Network error or server unavailable.';
                document.getElementById('message').style.color = 'red';
            }
        });
    }

    // Event listener for login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value.trim();
            const pin = document.getElementById('loginPin').value;

            try {
                const response = await fetch(`${backendUrl}/login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        pin: pin
                    })
                });

                const data = await response.json();
                const messageDiv = document.getElementById('message');
                if (data.success) {
                    messageDiv.textContent = data.message;
                    messageDiv.style.color = 'green';
                    localStorage.setItem('loggedInUsername', username); // Store username for chat page
                    window.location.href = 'chat.html'; // Redirect to chat page
                } else {
                    messageDiv.textContent = data.message;
                    messageDiv.style.color = 'red';
                }
            } catch (error) {
                console.error('Error during login:', error);
                document.getElementById('message').textContent = 'Network error or server unavailable.';
                document.getElementById('message').style.color = 'red';
            }
        });
    }
});

/**
 * Generates a new RSA key pair and stores it in localStorage.
 * Updates the global ownKeyPair variable.
 */
async function generateAndStoreNewKeys() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: "SHA-256", // CRITICAL: Matches Python backend
            },
            true, // extractable: Set to true to export keys to PEM
            ["encrypt", "decrypt"] // Usage for RSA
        );
        ownKeyPair = keyPair;

        const publicKeyPemString = await exportKeyToPem(keyPair.publicKey, 'public');
        const privateKeyPemString = await exportKeyToPem(keyPair.privateKey, 'private');

        localStorage.setItem('publicKey', publicKeyPemString);
        localStorage.setItem('privateKey', privateKeyPemString);

        console.log("✅ New RSA key pair generated and stored in localStorage.");
        console.log("Public Key (first 50 chars):", publicKeyPemString.substring(0, 50) + "...");
        console.log("Private Key (first 50 chars):", privateKeyPemString.substring(0, 50) + "...");

    } catch (e) {
        console.error("❌ Error generating or storing new keys:", e);
        alert("Failed to generate cryptographic keys. Please check console.");
        ownKeyPair = null; // Ensure ownKeyPair is null if generation fails
    }
}

/**
 * Imports an RSA key pair from PEM strings.
 * @param {string} publicKeyPem
 * @param {string} privateKeyPem
 * @returns {Promise<CryptoKeyPair>}
 */
async function importKeyPairFromPem(publicKeyPem, privateKeyPem) {
    const publicKeyBuffer = Uint8Array.from(atob(publicKeyPem.replace(/-----(BEGIN|END) PUBLIC KEY-----|\n/g, '')), c => c.charCodeAt(0));
    const privateKeyBuffer = Uint8Array.from(atob(privateKeyPem.replace(/-----(BEGIN|END) PRIVATE KEY-----|\n/g, '')), c => c.charCodeAt(0));

    const publicKey = await window.crypto.subtle.importKey(
        "spki", // SubjectPublicKeyInfo format for public keys
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" }, // CRITICAL: Match backend hash
        true, // extractable
        ["encrypt"]
    );

    const privateKey = await window.crypto.subtle.importKey(
        "pkcs8", // PKCS#8 format for private keys
        privateKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" }, // CRITICAL: Match backend hash
        true, // extractable
        ["decrypt"]
    );

    return { publicKey, privateKey };
}

/**
 * Exports a CryptoKey to PEM string format.
 * @param {CryptoKey} key
 * @param {'public'|'private'} type
 * @returns {Promise<string>} PEM string
 */
async function exportKeyToPem(key, type) {
    const exported = await window.crypto.subtle.exportKey(
        type === 'public' ? "spki" : "pkcs8",
        key
    );
    const base64String = btoa(String.fromCharCode(...new Uint8Array(exported)));
    const pemHeader = type === 'public' ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
    const pemFooter = type === 'public' ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";
    return `${pemHeader}\n${base64String.match(/.{1,64}/g).join('\n')}\n${pemFooter}`; // Wrap at 64 chars
}

// Global utility functions for encryption/decryption (can be moved to a separate `cryptoUtils.js` if preferred)
/**
 * Encrypts data using RSA-OAEP with a public key.
 * @param {string} plaintext - The message to encrypt.
 * @param {CryptoKey} publicKey - The RSA public key (CryptoKey object).
 * @returns {Promise<string>} Base64 encoded ciphertext.
 */
async function rsaEncrypt(plaintext, publicKey) {
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        encoded
    );
    return btoa(String.fromCharCode(...new Uint8Array(ciphertextBuffer)));
}

/**
 * Decrypts data using RSA-OAEP with a private key.
 * @param {string} base64Ciphertext - Base64 encoded ciphertext.
 * @param {CryptoKey} privateKey - The RSA private key (CryptoKey object).
 * @returns {Promise<string>} Decrypted plaintext.
 */
async function rsaDecrypt(base64Ciphertext, privateKey) {
    try {
        const decoded = Uint8Array.from(atob(base64Ciphertext), c => c.charCodeAt(0));
        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            privateKey,
            decoded
        );
        return new TextDecoder().decode(plaintextBuffer);
    } catch (e) {
        console.error("❌ RSA Decryption failed:", e);
        throw new Error("RSA Decryption failed"); // Re-throw to be caught by caller
    }
}

/**
 * Generates a random AES key (256-bit for AES-CBC).
 * @returns {Promise<CryptoKey>}
 */
async function generateAesKey() {
    return window.crypto.subtle.generateKey(
        {
            name: "AES-CBC",
            length: 256, // 256-bit key
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypts a message using AES-CBC.
 * @param {string} plaintext - The message to encrypt.
 * @param {CryptoKey} aesKey - The AES key (CryptoKey object).
 * @returns {Promise<string>} Base64 encoded IV + ciphertext.
 */
async function aesEncrypt(plaintext, aesKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(16)); // 16-byte IV
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-CBC",
            iv: iv,
        },
        aesKey,
        encoded
    );
    const combined = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertextBuffer), iv.length);
    return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypts a message using AES-CBC.
 * @param {string} base64CiphertextWithIv - Base64 encoded IV + ciphertext.
 * @param {CryptoKey} aesKey - The AES key (CryptoKey object).
 * @returns {Promise<string>} Decrypted plaintext.
 */
async function aesDecrypt(base64CiphertextWithIv, aesKey) {
    try {
        const decoded = Uint8Array.from(atob(base64CiphertextWithIv), c => c.charCodeAt(0));
        const iv = decoded.slice(0, 16);
        const ciphertext = decoded.slice(16);

        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: iv,
            },
            aesKey,
            ciphertext
        );
        return new TextDecoder().decode(plaintextBuffer);
    } catch (e) {
        console.error("❌ AES Decryption failed:", e);
        return "[Could not decrypt message]"; // Return a specific error string for UI
    }
}

// Global utility for exporting raw AES key for storage/transport
async function exportAesKeyRaw(aesKey) {
    const exported = await window.crypto.subtle.exportKey("raw", aesKey);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

// Global utility for importing raw AES key
async function importAesKeyRaw(base64RawKey) {
    const decoded = Uint8Array.from(atob(base64RawKey), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
        "raw",
        decoded,
        { name: "AES-CBC" },
        true,
        ["encrypt", "decrypt"]
    );
}

// Attach these utility functions to the window object or an exports object
// so they can be accessed from chat.js
window.CryptoUtils = {
    rsaEncrypt,
    rsaDecrypt,
    generateAesKey,
    aesEncrypt,
    aesDecrypt,
    exportKeyToPem, // Keep this for registration
    importKeyPairFromPem, // Keep this for initial load
    exportAesKeyRaw,
    importAesKeyRaw
};

// Also export ownKeyPair and the ability to set it after import for chat.js
window.AuthKeys = {
    get OwnKeyPair() { return ownKeyPair; },
    set OwnKeyPair(kp) { ownKeyPair = kp; }
};
