// Popup.js is responsible for showing the AbuseIPDB information inside the popup window background.js opens.

// 1. Escapes HTML that is fetched from AbuseIPDB
// 2. TODO: remove? Validates IP Addresses
// 3. Of course links the variables to work properly with popup.html html elements.

// 4. Listens when background.js has opened the popup window and will then check if the API key is decrypted.
// 5. Asks for PIN if the API key is not decrypted.
// 6. Gets the decrypted API key from local memory OR asks with unlockKey for background.js to unlock the key.

// 7. Performs the AbuseIPDB fetching using the API key and escapes its contents.

// This function escapes symbols from html which we fetch from AbuseIPDB
function escapeHtml(text) {
    return text.replace(/[&<>"']/g, match => {
        const escapeMap = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "\"": "&quot;",
            "'": "&#039;"
        };
        return escapeMap[match] || match;
    });
}

// TODO: is ip validation needed if it is done in background.js? 
// Regex patterns for IP validation. These are same as in background.js
const ipv4Pattern = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const ipv6Pattern = /^(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,2}|:)|(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,3}|:)|(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,5}|:)|(?:[0-9A-Fa-f]{1,4}:){1}(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,6}|:)|(?::(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,7}|:)))(?:%\S+)?$/;

function isValidIP(ip) {
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}

// We make variables for the HTML elements that will be shown in the popup window so it works consistentl with popup.html.
const resultDiv  = document.getElementById("result");
const pinModal   = document.getElementById("pinModal");
const pinInput   = document.getElementById("pinInput");
const pinSubmit  = document.getElementById("pinSubmit");
const pinErrorMsg = document.getElementById("pinError");

// Listening when the popup window is loaded in background.js
document.addEventListener("DOMContentLoaded", () => {

    // Asks for encrypted key
    browser.storage.local.get("encryptedKey").then(data => {

        // If user did not save API key we show this to user on the popup window.
        if (!data.encryptedKey) {
            resultDiv.innerText = "API key not set. Please go to Options to save your API key.";
            checkBtn.disabled = true; // TODO: This could be erased? This is check button which is not needed.
            return;
        }

        // Asking if the background.js has already decrypted the key.
        browser.runtime.sendMessage({ action: "getDecryptedKey" }).then(response => {
            if (response && response.key) {
                // No PIN is needed if there is still decrypted key.
                initializeLookupUI();
            } else {
                // No decrypted key means that we need to ask for PIN in a popup:
                pinModal.style.display = "flex";
                pinInput.focus();
            }
        });
    });
    // Takes the highlighted IP Address from the local storage and stores it.
    // TODO: Try to change this if clause off i dont think we need it?
    browser.storage.local.get("selectedIP").then(data => {
        if (data.selectedIP) {
            ipInput.value = data.selectedIP;
            browser.storage.local.remove("selectedIP");
        }
    });
});

// This initalizes the UI and is the main function of fetching from AbuseIPDB.
function initializeLookupUI() {
    browser.storage.local.get("selectedIP").then(data => {
        const ip = data.selectedIP;
        if (ip) {
            fetchIPData(ip);
        } else {
            resultDiv.innerText = "No IP address found.";
        }
    });
}

// This listens users clicks on PIN input prompt.
pinSubmit.addEventListener("click", () => {
    const pin = pinInput.value;
    if (!pin) return;              // If field is empty, don't do anything.
    pinErrorMsg.textContent = "";  // clears any previous errors

    // Asks background.js to decrypt the API key with the PIN
    browser.runtime.sendMessage({ action: "unlockKey", pin: pin }).then(response => {
        if (response && response.success) {

            // PIN is correct so API key is now unlocked
            pinModal.style.display = "none";
            pinInput.value = "";
            initializeLookupUI();
        } else {
            pinErrorMsg.textContent = "Incorrect PIN. Please try again.";
        }
    });
});


// This function makes the main AbuseIPDB data fetching.
function fetchIPData(ip) {
    resultDiv.textContent = "Loading...";

    // Asks from background.js to call for AbuseIPDB's API.
    browser.runtime.sendMessage({ action: "lookupIP", ip: ip }).then(response => {
        if (!response) {
            resultDiv.textContent = "No response from background.";
            return;
        }
        if (response.error) {
            // Show error message e.g invalid API key or problem within AbuseIPDB API connection.
            resultDiv.textContent = "Error: " + escapeHtml(response.error);
        } else if (response.data) {
            const data = response.data;
            if (!data.data) {
                resultDiv.textContent = "No data available for this IP.";
                return;
            }
            const info = data.data;
            // The main output of the popup window: The AbuseIPDB IP Address information:
            let outputHtml = "";
            outputHtml += `<p><strong>IP Address:</strong> ${escapeHtml(info.ipAddress)}</p>`;                           // IP Address
            outputHtml += `<p><strong>Country:</strong> ${escapeHtml(info.countryCode || "")}</p>`;                      // Country
            outputHtml += `<p><strong>Abuse Confidence Score:</strong> ${info.abuseConfidenceScore}%</p>`;               // Abuse Confidence
            outputHtml += `<p><strong>Total Reports:</strong> ${info.totalReports}</p>`;                                 // Total reports
            // These information might not be available, so it is checked first:
            if (info.isp) {
                outputHtml += `<p><strong>ISP:</strong> ${escapeHtml(info.isp)}</p>`;                                    // ISP
            }
            if (info.domain) {
                outputHtml += `<p><strong>Domain:</strong> ${escapeHtml(info.domain)}</p>`;                              // Domain
            }
            if (info.hostnames && info.hostnames.length > 0) {
                outputHtml += `<p><strong>Hostnames:</strong> ${info.hostnames.map(h => escapeHtml(h)).join(", ")}</p>`; // Hostnames
            }
            if (info.usageType) {
                outputHtml += `<p><strong>Usage Type:</strong> ${escapeHtml(info.usageType)}</p>`;                       // Usage type
            }
            if (info.asn) {
                outputHtml += `<p><strong>ASN:</strong> ${escapeHtml(info.asn.toString())}</p>`;                         // ASN
            }
            if (info.lastReportedAt) {
                outputHtml += `<p><strong>Last Reported:</strong> ${escapeHtml(info.lastReportedAt)}</p>`;               // Last reported
            }
            resultDiv.innerHTML = outputHtml;
        } else {
            resultDiv.textContent = "Unexpected response format.";
        }
    });
}
