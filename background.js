// Background.js is the main algorithm of the extension:

// 1. We check the ipv4/ipv6 is valid using regex.
// 2. When user highlights text on website and right clicks, extension is visible on the right click menu.
// 3. If the highlighted text is valid it will open spur.us/context/<ip address> and still empty AbuseIPDB popup window.
// 4. IP Address is also stored in local storage for later use.

// 5. Listens when popup.js wants to unlock the API key with salt + iv from storage.
// 6. The decryption is built from the user input PIN, local storage salt and using the PBKDF2 algorithm.

// 7. Listens when popup.js want to get AbuseIPDB info for IP. Then performs the API fetching from AbuseIPDB
// 8. Listens when options.js wants the API key to be cleared.

// ChatGPT 4o created regex patterns for ipv4:
const ipv4Pattern = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
// ChatGPT 4o created regex patterns for ipv6:
const ipv6Pattern = /^(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,2}|:)|(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,3}|:)|(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,5}|:)|(?:[0-9A-Fa-f]{1,4}:){1}(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,6}|:)|(?::(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,7}|:)))(?:%\S+)?$/;

// Tests if the IP address maches the regex
function isValidIP(address) {
    return ipv4Pattern.test(address) || ipv6Pattern.test(address);
}

// In-memory decrypted API key is only stored during session once user has authenticated.
let decryptedAPIKey = null;

// When IP address is highlighted on website this opens the right-click menu:
browser.runtime.onInstalled.addListener(() => {
    browser.contextMenus.create({
        id: "lookup-ip",                // Menu ID can be really anything
        title: "Spur us + AbuseIPDB",   // This is the name of the extension in the menu
        contexts: ["selection"]         // Some text needs to be highlighted
    });
});

// ... inside background.js contextMenus.onClicked listener:
browser.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "lookup-ip" && info.selectionText) {
        const ip = info.selectionText.trim();

        if (isValidIP(ip)) {
            const spurUrl = "https://spur.us/context/" + ip;

            // Save IP for popup.js
            await browser.storage.local.set({ selectedIP: ip });

            // Get current tab info
            const [currentTab] = await browser.tabs.query({ active: true, currentWindow: true });

            // Open spur.us tab next to current tab
            const spurTab = await browser.tabs.create({
                url: spurUrl,
                index: currentTab.index,
                active: true // You want it visible right away
            });

            // Open the popup window but return to original tab after short delay
            const popupWidth = 500;
            const popupHeight = 500;
            const margin = 115;

            const win = await browser.windows.getCurrent();
            const top = win.top + margin;
            const left = win.left + win.width - popupWidth - margin;

            const popupWindow = await browser.windows.create({
                url: "popup.html",
                type: "popup",
                width: popupWidth,
                height: popupHeight,
                top: top,
                left: left,
                focused: false // Only works in Chrome
            });

          
        } else {
            // Invalid IP notification
            if (browser.notifications) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: browser.runtime.getURL("icon_128x128.png"),
                    title: "Spur us + AbuseIPDB",
                    message: "Highlighted text is not a valid IP address."
                });
            }
        }
    }
});

// Converts binary data into base64 so it is possible to store it as a string and used in encryption/decryption.
function arrayBufferToBase64(buffer) {
    let binary = "";

    // Turns it into array of bytes.
    const bytes = new Uint8Array(buffer); 
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary); // returns base64 encoded binary sring
}

// Converts base64 text back to binary data
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Listens for actions from popup.js and options.js
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    
    // Popup.js asks for decrypted API key
    if (msg.action === "getDecryptedKey") {
        sendResponse({ key: decryptedAPIKey });

    // Options.js asks to clear the key. This means that a new key was saved and we clear the old key from memory.
    } else if (msg.action === "clearDecryptedKey") {
        decryptedAPIKey = null;
        sendResponse({ status: "ok" });

    // If popup.js asks to unlock the encrypted API key
    } else if (msg.action === "unlockKey") {

        // Gets the encrypted key, its salt and iv from browser storage.
        browser.storage.local.get(["encryptedKey", "salt", "iv"]).then(async (data) => {

            // Checks if some of the values are missing and throws error.
            if (!data.encryptedKey || !data.salt || !data.iv) {
                sendResponse({ success: false });
                return;
            }
            try {

                // This function turns string -> bytes
                const enc = new TextEncoder();

                // Makes a basic key out of the PIN with PBKDF2
                const baseKey = await crypto.subtle.importKey(
                    "raw",                  // raw bytes are given. Not a key
                    enc.encode(msg.pin),    // PIN is converted into bytes
                    { name: "PBKDF2" },     // We are using PBKDF2
                    false,                  // This key cannot be extracted
                    ["deriveKey"]           // We can make new keys with it
                );

                // Makes 256 AES key from the PIN.
                const aesKey = await crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",                         // Using PBKDF2 again
                        salt: base64ToArrayBuffer(data.salt),   // Adds salt which is random data adding uniqueness
                        iterations: 100000,                     // Running the hash math 100k to make it harder to brute force
                        hash: "SHA-256"                         // Using secure 
                    },
                    baseKey,                                    // We use the base key made with the PIN
                    { name: "AES-GCM", length: 256 },           // We use AES-GCM algorithm with 256 bits as its secure.
                    false,                                      // This key cannot be extracted
                    ["decrypt"]                                 // This key can be used to decrypt
                );

                // Decrypt the encrypted API key from the memory 
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: base64ToArrayBuffer(data.iv) }, // We get the IV which is also like random data
                    aesKey,                                                // Using the key for decrypting (aesKey)
                    base64ToArrayBuffer(data.encryptedKey)                 // encrypted key from base64 transferred to binary
                );

                // Then decrypted key is in binary which needs to be decoded to string (Final result)
                decryptedAPIKey = new TextDecoder().decode(decryptedBuffer);
                sendResponse({ success: true });

            // If encryption fails, shows error in console.
            } catch (e) {
                console.error("Failed to decrypt API key:", e);

                // API key is cleared from memory as a precaution.
                decryptedAPIKey = null;

                // Telling popup.js the decryption failed.
                sendResponse({ success: false });
            }
        });
        return true; // The listening of popup.js is active until the decryption is finished.

    // Popup.js asks for AbuseIPDB info
    } else if (msg.action === "lookupIP") {
        // Checking if there is no decrypted API key and sending error back.
        if (!decryptedAPIKey) {
            sendResponse({ error: "API key not unlocked" });
            return false;
        }
        // Fetches from the AbuseIPDB api the information
        const ip = msg.ip; // IP address is got from popup.js
        fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
            method: "GET",                      // GET message means we are asking something from the api
            headers: {
                "Accept": "application/json",   // Response is given in json format
                "Key": decryptedAPIKey          // Key is provided with the fetch
            }
        }).then(async (response) => {

            // if the response is not HTTP 200 OK
            if (!response.ok) {
                // sending error message to explain the error.
                let errMessage = `HTTP ${response.status}`;

                // This fetches the detailed error from the API 
                try {
                    const errData = await response.json();
                    if (errData?.errors?.length) {
                        errMessage = errData.errors[0].detail || errMessage;
                    } else if (errData?.message) {
                        errMessage = errData.message;
                    }
                } catch (e) {
                    // If detailed error is not found, we just use the initial message.
                }
                throw new Error(errMessage);
            }
            return response.json();
        }).then(data => {
            // Data is sent to popup.js after it is fetched
            sendResponse({ data: data });

        // Error catching
        }).catch(error => {
            console.error("Lookup error:", error);
            sendResponse({ error: error.message });
        });
        return true; // Because of this the system knows we are listening and responsive.
    }
});
