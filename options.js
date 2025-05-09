// Utility: convert ArrayBuffer to Base64 string for storage
function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Initialize options page
document.addEventListener('DOMContentLoaded', () => {
  // Check if an encrypted key is already stored
  browser.storage.local.get("encryptedKey").then(data => {
      if (data.encryptedKey) {
          document.getElementById("status").textContent = "API key is stored securely. Enter a new key and PIN to update.";
      }
  }).catch(err => {
      console.error("Storage load error:", err);
      document.getElementById("status").textContent = "Error loading stored key.";
  });

  // Handle Save button click
  document.getElementById("save").addEventListener("click", async () => {
      const apiKeyInput = document.getElementById("apiKey");
      const pinInput = document.getElementById("pin");
      const statusEl = document.getElementById("status");
      const apiKey = apiKeyInput.value.trim();
      const pin = pinInput.value.trim();

      // Basic validation for API key and PIN
      if (!apiKey || !pin) {
          statusEl.textContent = "Please enter both API key and PIN.";
          return;
      }
      if (!/^[a-zA-Z0-9]{20,}$/.test(apiKey)) {
          statusEl.textContent = "Invalid API key format.";
          return;
      }
      if (pin.length < 4) {
          statusEl.textContent = "PIN must be at least 4 characters.";
          return;
      }

      try {
          // Creates random salt 16 bytes
          const salt = crypto.getRandomValues(new Uint8Array(16));

          // Creates a random IV with 12 bytes
          const iv   = crypto.getRandomValues(new Uint8Array(12));

          // String to binary
          const enc = new TextEncoder();

          // Takes the user entered PIN and makes it a crypto key
          const baseKey = await crypto.subtle.importKey(
              "raw",                // raw binary of the PIN
              enc.encode(pin),      // PIN string -> PIN binary
              { name: "PBKDF2" },   // We use PBKDF2 from the library
              false,                // Do not allow exporting
              ["deriveKey"]         // Can generate another key with this key
          );

          // Create a secure AES-GCM key using the PIN which uses PBKDF2
          const aesKey = await crypto.subtle.deriveKey(
              {
                  name: "PBKDF2",       // Using PBKDF2
                  salt: salt,           // Adding salt prevents 
                                        // rainbow table attacks
                  iterations: 100000,
                  hash: "SHA-256"
              },
              baseKey,
              { name: "AES-GCM", length: 256 },
              false,
              ["encrypt", "decrypt"]
          );
          // Encrypt the API key using the derived AES-GCM key
          const ciphertext = await crypto.subtle.encrypt(
              { name: "AES-GCM", iv: iv },
              aesKey,
              enc.encode(apiKey)
          );
          // Encode binary data to base64 for storage
          const encryptedKeyB64 = arrayBufferToBase64(ciphertext);
          const saltB64 = arrayBufferToBase64(salt.buffer);
          const ivB64   = arrayBufferToBase64(iv.buffer);
          // Store the encrypted key and parameters
          await browser.storage.local.set({
              encryptedKey: encryptedKeyB64,
              salt: saltB64,
              iv: ivB64
          });
          // Remove any old plaintext key entry (cleanup from previous versions)
          browser.storage.local.remove("userApiKey");
          // Clear in-memory decrypted key, forcing PIN re-entry next time if needed
          await browser.runtime.sendMessage({ action: "clearDecryptedKey" });
          // Success feedback
          statusEl.textContent = "API key saved securely.";
          apiKeyInput.value = "";
          pinInput.value = "";
      } catch (e) {
          console.error("Encryption error:", e);
          statusEl.textContent = "Failed to save API key. " + (e.message || "");
      }
  });
});
