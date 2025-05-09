// Escape HTML special characters in output (prevent injection in result display)
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

// Regex patterns for IP validation (same as in background.js)
const ipv4Pattern = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const ipv6Pattern = /^(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[0-9A-Fa-f]{1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,2}|:)|(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,3}|:)|(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,4}|:)|(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,5}|:)|(?:[0-9A-Fa-f]{1,4}:){1}(?:(?::[0-9A-Fa-f]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,6}|:)|(?::(?:(?::[0-9A-Fa-f]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[0-9A-Fa-f]{1,4}){1,7}|:)))(?:%\S+)?$/;
function isValidIP(ip) {
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}

// Grab references to UI elements
const resultDiv  = document.getElementById("result");
const pinModal   = document.getElementById("pinModal");
const pinInput   = document.getElementById("pinInput");
const pinSubmit  = document.getElementById("pinSubmit");
const pinErrorMsg = document.getElementById("pinError");

// When popup loads, check if API key is stored and/or already unlocked
document.addEventListener("DOMContentLoaded", () => {
    browser.storage.local.get("encryptedKey").then(data => {
        if (!data.encryptedKey) {
            // API key not configured
            resultDiv.innerText = "API key not set. Please go to Options to save your API key.";
            checkBtn.disabled = true;
            return;
        }
        // API key is set; check if already unlocked in this session
        browser.runtime.sendMessage({ action: "getDecryptedKey" }).then(response => {
            if (response && response.key) {
                // Key is already unlocked – no PIN needed
                initializeLookupUI();
            } else {
                // Not unlocked yet – show PIN modal
                pinModal.style.display = "flex";
                pinInput.focus();
            }
        });
    });
    // If the popup was opened via context menu, load the selected IP
    browser.storage.local.get("selectedIP").then(data => {
        if (data.selectedIP) {
            ipInput.value = data.selectedIP;
            browser.storage.local.remove("selectedIP");
        }
    });
});

// Enable the lookup UI after PIN unlock
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


// PIN submission handler
pinSubmit.addEventListener("click", () => {
    const pin = pinInput.value;
    if (!pin) return;
    pinErrorMsg.textContent = "";  // clear any previous error
    browser.runtime.sendMessage({ action: "unlockKey", pin: pin }).then(response => {
        if (response && response.success) {
            // PIN correct, API key unlocked
            pinModal.style.display = "none";
            pinInput.value = "";
            initializeLookupUI();
        } else {
            // Wrong PIN – show error
            pinErrorMsg.textContent = "Incorrect PIN. Please try again.";
        }
    });
});


// Perform the AbuseIPDB lookup via background script
function fetchIPData(ip) {
    resultDiv.textContent = "Loading...";
    browser.runtime.sendMessage({ action: "lookupIP", ip: ip }).then(response => {
        if (!response) {
            resultDiv.textContent = "No response from background.";
            return;
        }
        if (response.error) {
            // Show error message (e.g., invalid API key or network error)
            resultDiv.textContent = "Error: " + escapeHtml(response.error);
        } else if (response.data) {
            const data = response.data;
            if (!data.data) {
                resultDiv.textContent = "No data available for this IP.";
                return;
            }
            const info = data.data;
            // Build HTML output with key fields
            let outputHtml = "";
            outputHtml += `<p><strong>IP Address:</strong> ${escapeHtml(info.ipAddress)}</p>`;
            outputHtml += `<p><strong>Country:</strong> ${escapeHtml(info.countryCode || "")}</p>`;
            outputHtml += `<p><strong>Abuse Confidence Score:</strong> ${info.abuseConfidenceScore}%</p>`;
            outputHtml += `<p><strong>Total Reports:</strong> ${info.totalReports}</p>`;
            if (info.isp) {
                outputHtml += `<p><strong>ISP:</strong> ${escapeHtml(info.isp)}</p>`;
            }
            if (info.domain) {
                outputHtml += `<p><strong>Domain:</strong> ${escapeHtml(info.domain)}</p>`;
            }
            if (info.hostnames && info.hostnames.length > 0) {
                outputHtml += `<p><strong>Hostnames:</strong> ${info.hostnames.map(h => escapeHtml(h)).join(", ")}</p>`;
            }
            if (info.usageType) {
                outputHtml += `<p><strong>Usage Type:</strong> ${escapeHtml(info.usageType)}</p>`;
            }
            if (info.asn) {
                outputHtml += `<p><strong>ASN:</strong> ${escapeHtml(info.asn.toString())}</p>`;
            }
            if (info.lastReportedAt) {
                outputHtml += `<p><strong>Last Reported:</strong> ${escapeHtml(info.lastReportedAt)}</p>`;
            }
            resultDiv.innerHTML = outputHtml;
        } else {
            resultDiv.textContent = "Unexpected response format.";
        }
    });
}
