// Validate IPv4 and IPv6 addresses using regex (supports full IPv6 notation range)
const ipv4Pattern = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const ipv6Pattern = /^(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,2}|:)|(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,3}|:)|(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,5}|:)|(?:[0-9A-Fa-f]{1,4}:){1}(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,6}|:)|(?::(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,7}|:)))(?:%\S+)?$/;
function isValidIP(address) {
    return ipv4Pattern.test(address) || ipv6Pattern.test(address);
}

// In-memory decrypted API key (only stored during session after PIN unlock)
let decryptedAPIKey = null;

// Create context menu on extension installation/upgrade
browser.runtime.onInstalled.addListener(() => {
    browser.contextMenus.create({
        id: "lookup-ip",
        title: "Spur us + AbuseIPDB",
        contexts: ["selection"]
    });
});

// Handle context menu click events
browser.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "lookup-ip" && info.selectionText) {
        const ip = info.selectionText.trim();
        if (isValidIP(ip)) {
            const spurUrl = "https://spur.us/context/" + ip;
            // Store selected IP and open popup + background Spur tab
            browser.storage.local.set({ selectedIP: ip }).then(() => {
                // Open Spur.us context page in a new background tab
                browser.tabs.create({ url: spurUrl, active: true });
                // Open the extension popup window to display AbuseIPDB info
                browser.windows.getCurrent().then(win => {
                    const popupWidth = 500;
                    const popupHeight = 500;
                    const margin = 115;
                  
                    const top = win.top + margin;
                    const left = win.left + win.width - popupWidth - margin;
                  
                    browser.windows.create({
                      url: "popup.html",
                      type: "popup",
                      width: popupWidth,
                      height: popupHeight,
                      top: top,
                      left: left
                    });
                  });
                  
            });
        } else {
            // Notify user if the selected text is not a valid IP address
            if (browser.notifications) {
                browser.notifications.create({
                    type: "basic",
                    iconUrl: browser.runtime.getURL("icon_128x128.png"),
                    title: "IP Lookup",
                    message: "Selected text is not a valid IP address."
                });
            }
        }
    }
});

// Utility functions for Base64 conversions (used in encryption/decryption)
function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Listen for runtime messages from popup and options scripts
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "getDecryptedKey") {
        // Popup asks if API key is already unlocked this session
        sendResponse({ key: decryptedAPIKey });
    } else if (msg.action === "clearDecryptedKey") {
        // Options page saved a new key – clear any old decrypted key from memory
        decryptedAPIKey = null;
        sendResponse({ status: "ok" });
    } else if (msg.action === "unlockKey") {
        // Attempt to derive key with provided PIN and decrypt stored API key
        browser.storage.local.get(["encryptedKey", "salt", "iv"]).then(async (data) => {
            if (!data.encryptedKey || !data.salt || !data.iv) {
                sendResponse({ success: false });
                return;
            }
            try {
                const enc = new TextEncoder();
                // Derive 256-bit AES-GCM key from PIN using PBKDF2 (100k iterations, SHA-256)
                const baseKey = await crypto.subtle.importKey(
                    "raw",
                    enc.encode(msg.pin),
                    { name: "PBKDF2" },
                    false,
                    ["deriveKey"]
                );
                const aesKey = await crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",
                        salt: base64ToArrayBuffer(data.salt),
                        iterations: 100000,
                        hash: "SHA-256"
                    },
                    baseKey,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["decrypt"]
                );
                // Decrypt the stored API key using derived AES key
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: base64ToArrayBuffer(data.iv) },
                    aesKey,
                    base64ToArrayBuffer(data.encryptedKey)
                );
                decryptedAPIKey = new TextDecoder().decode(decryptedBuffer);
                sendResponse({ success: true });
            } catch (e) {
                console.error("Failed to decrypt API key:", e);
                decryptedAPIKey = null;
                sendResponse({ success: false });
            }
        });
        return true; // Keep the message channel open for async response
    } else if (msg.action === "lookupIP") {
        // Perform the AbuseIPDB lookup using the decrypted API key
        if (!decryptedAPIKey) {
            sendResponse({ error: "API key not unlocked" });
            return false;
        }
        const ip = msg.ip;
        fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
            method: "GET",
            headers: {
                "Accept": "application/json",
                "Key": decryptedAPIKey
            }
        }).then(async (response) => {
            if (!response.ok) {
                // Construct a useful error message from the response if available
                let errMessage = `HTTP ${response.status}`;
                try {
                    const errData = await response.json();
                    if (errData?.errors?.length) {
                        errMessage = errData.errors[0].detail || errMessage;
                    } else if (errData?.message) {
                        errMessage = errData.message;
                    }
                } catch (e) {
                    // ignore JSON parse errors
                }
                throw new Error(errMessage);
            }
            return response.json();
        }).then(data => {
            sendResponse({ data: data });
        }).catch(error => {
            console.error("Lookup error:", error);
            sendResponse({ error: error.message });
        });
        return true; // Respond asynchronously after fetch completes
    }
});
