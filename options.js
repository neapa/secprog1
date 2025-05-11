// Options.js operates the options.html API setup page in which the user inputs 
// the AbuseIPDB api key and PIN for encryption and authentication.

// 1. The user opens the extension setting page: options.html
// 2. User inputs their AbuseIPDB API key and PIN

// 3. We make the PIN into a strong key using PBKDF2
// 4. This key is used with AES-GCM to encrypt the API key.
// 5. Everything is saved in local browser storage in encrypted form.
// 6. We clean all plain text API and PIN secrets that were handled.

// Utility function that converts binary to base64 so it can be saved
function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer); // Turns the binary to array of bytes
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]); // Every byte is converted to a character
    }
    return btoa(binary); // returns the full base64 text
}

// When the API setup page options.html is loaded:
document.addEventListener('DOMContentLoaded', () => {

  // Checks if the user already inputted an API key
  browser.storage.local.get("encryptedKey").then(data => {
      if (data.encryptedKey) {
        // If it exists we have this text under the input field:
          document.getElementById("status").textContent = "API key is stored securely. Enter a new key and PIN to update.";
      }
  }).catch(err => {
    // Shows error if could not load from storage the key
      console.error("Storage load error:", err);
      document.getElementById("status").textContent = "Error loading stored key.";
  });

  // When user clicks the Save button on the options.html page.
  document.getElementById("save").addEventListener("click", async () => {

    // We get the information from the user inputs: Api key and pin
      const apiKeyInput = document.getElementById("apiKey");
      const pinInput = document.getElementById("pin");
      const statusEl = document.getElementById("status");
      const apiKey = apiKeyInput.value.trim(); // Spaces removed to mitigate user errors.
      const pin = pinInput.value.trim(); // Spaces removed to mitigate user errors.

      // This makes sure both input boxes are filled always.
      if (!apiKey || !pin) {
          statusEl.textContent = "Please enter both API key and PIN.";
          return;
      }

      // API validation: is at least 20 letter/number combination without symbols.
      if (!/^[a-zA-Z0-9]{20,}$/.test(apiKey)) {
          statusEl.textContent = "Invalid API key format.";
          return;
      }

      // Pin validation
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

          // Takes the user entered PIN and makes it a base key which is used to create the real enc key.
          const baseKey = await crypto.subtle.importKey(
              "raw",                // This tells browser that this is just raw binary data.
              enc.encode(pin),      // Conversion of PIN string -> PIN binary
              { name: "PBKDF2" },   // We use PBKDF2 from the library
              false,                // Do not allow exporting
              ["deriveKey"]         // Can generate another key with this key
          );

          // Create a secure AES-GCM key using the PIN which uses PBKDF2
          const aesKey = await crypto.subtle.deriveKey(
              {
                  name: "PBKDF2",       // Using PBKDF2
                  salt: salt,           // Adding salt prevents from attacks rainbow table attacks
                  iterations: 100000,   // Repeats hash calculation 100k times to make it more random.
                  hash: "SHA-256"       // Secure hashing used
              },
              baseKey,                          // Starting from the PIN base key.
              { name: "AES-GCM", length: 256 }, // We make AES key for encryption
              false,                            // Do not allow exporting
              ["encrypt", "decrypt"]            // This key is used for enc/dec
          );
          // Encrypt the API key using the newly made aesKey (AES-GCM key)
          const ciphertext = await crypto.subtle.encrypt(
              { name: "AES-GCM", iv: iv },  // Telling browser we use AES-GCM and IV (random data)
              aesKey,                       // Using the newly made AES-GCM key
              enc.encode(apiKey)            // Conversion API key to binary + encryption
          );

          // Conversion of enc data, salt and IV to base64 in order to put them to storage.
          const encryptedKeyB64 = arrayBufferToBase64(ciphertext);
          const saltB64 = arrayBufferToBase64(salt.buffer);
          const ivB64   = arrayBufferToBase64(iv.buffer);

          // Encrypted key, salt and IV is saved to browser's local storage.
          await browser.storage.local.set({
              encryptedKey: encryptedKeyB64,
              salt: saltB64,
              iv: ivB64
          });

          // Cleans up the plaintext api key from memory.
          browser.storage.local.remove("userApiKey");

          // Cleans the memory of decrypted api key which requires user to input PIN again.
          await browser.runtime.sendMessage({ action: "clearDecryptedKey" });

          // If everything went well. Show this on page:
          statusEl.textContent = "API key saved securely.";
          apiKeyInput.value = "";
          pinInput.value = "";

      } catch (e) {
            // If there was error in encryption.
          console.error("Encryption error:", e);
          statusEl.textContent = "Failed to save API key. " + (e.message || "");
      }
  });
});
