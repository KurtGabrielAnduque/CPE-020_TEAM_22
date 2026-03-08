console.log("Phishing Guard Advanced Engine Active");

// ─── CONFIGURATION ───────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = ['.zip', '.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.work'];

const TARGET_BRANDS = [
    { name: "paypal", domain: "paypal.com" },
    { name: "google", domain: "google.com" },
    { name: "apple", domain: "apple.com" },
    { name: "facebook", domain: "facebook.com" },
    { name: "microsoft", domain: "microsoft.com" },
    { name: "netflix", domain: "netflix.com" },
    { name: "amazon", domain: "amazon.com" },
    { name: "example", domain: "example.net" }
];

// Known legitimate domains that should never be blocked
const SAFELIST = new Set([
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "www.paypal.com",
    "signin.aws.amazon.com",
    "www.facebook.com",
    "www.netflix.com",
]);

// Score thresholds
const SCORE_BLOCK    = 4;  // Block immediately, no ML check needed
const SCORE_MEDIUM   = 3;  // Uncertain — send to Django for ML verdict
const DJANGO_API_URL = "http://127.0.0.1:8000/analyze/"; // Your future Django endpoint

// ─── ALLOWLIST (session-persistent) ──────────────────────────────────────────

async function isAllowlisted(url) {
    return new Promise((resolve) => {
        chrome.storage.session.get("allowlist", (data) => {
            const allowlist = data.allowlist || [];
            resolve(allowlist.includes(url));
        });
    });
}

async function addToAllowlist(url) {
    return new Promise((resolve) => {
        chrome.storage.session.get("allowlist", (data) => {
            const allowlist = data.allowlist || [];
            if (!allowlist.includes(url)) allowlist.push(url);
            chrome.storage.session.set({ allowlist }, resolve);
        });
    });
}

// ─── MESSAGE LISTENER ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "ALLOW_SITE") {
        addToAllowlist(request.url).then(() => {
            console.log("User explicitly allowed:", request.url);
            sendResponse({ success: true });
        });
        return true; // Keep channel open for async response
    }
});

// ─── HEURISTIC SCORING ────────────────────────────────────────────────────────

function calculateRiskScore(urlStr) {
    let score = 0;
    let reasons = [];

    try {
        const urlObj = new URL(urlStr);
        const hostname = urlObj.hostname.toLowerCase();
        const wholeUrl = urlStr.toLowerCase();

        // Check 1: Suspicious TLD
        const tld = "." + hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.includes(tld)) {
            score += 2;
            reasons.push("Suspicious TLD: " + tld);
        }

        // Check 2: Punycode (homograph attack)
        if (hostname.includes("xn--")) {
            score += 2;

            // lets try to decode the punycode to show the user the potential homograph
            try {
                const unicodeHostname = new URL(urlStr).hostname
                    .split('.')
                    .map(part => part.startsWith('xn--') 
                        ? decodeURIComponent(escape(punycode.toUnicode(part))) 
                        : part)
                    .join('.');
                reasons.push(`Punycode detected — displays as: ${unicodeHostname}`);
            } catch (e) {
                reasons.push("Punycode detected");
            }
        }

        // Check 3: Excessive subdomains
        const dotCount = hostname.split('.').length - 1;
        if (dotCount >= 4) {
            score += 1;
            reasons.push("Excessive subdomains: " + dotCount);
        }

        // Check 4: Brand mismatch — requires corroboration
        TARGET_BRANDS.forEach(brand => {
            if (hostname.includes(brand.name) && !hostname.endsWith(brand.domain)) {
                score += 3;
                reasons.push(`Brand mismatch: "${brand.name}" on ${hostname}`);
            }
        });

        // Check 5: IP address as hostname
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
            score += 2;
            reasons.push("IP address used as hostname");
        }

        // Check 6: Suspicious keywords — only count if combined with other signals
        const hasKeyword = ["login", "signin", "verify", "wallet", "secure", "update", "confirm"].some(k => wholeUrl.includes(k));
        if (hasKeyword && score > 0) {
            score += 1;
            reasons.push("Suspicious keyword in URL");
        }

        // Check 7: Excessive hyphens (common in phishing domains)
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount >= 3) {
            score += 1;
            reasons.push("Excessive hyphens: " + hyphenCount);
        }

        // Check 8: URL length (very long URLs are suspicious)
        if (urlStr.length > 100) {
            score += 1;
            reasons.push("Unusually long URL: " + urlStr.length + " chars");
        }

    } catch (e) {
        console.error("Heuristic analysis failed:", e);
    }

    return { score, reasons };
}


chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    
    // 1. Only run when the URL changes (and exists)
    if (changeInfo.url) {
        
        // 2. Prevent loops: Don't check your own Extension pages or blank tabs
        if (changeInfo.url.startsWith("chrome://") || 
            changeInfo.url.includes("chrome-extension://") ||
            changeInfo.url.includes("goaway.html")) {
            return;
        }

        console.log("Analyzing:", changeInfo.url);

        // 3. Run your Logic
        const score = calculateRiskScore(changeInfo.url);

        if (score > 0) {
            console.log(`[Risk Analysis] Score: ${score} | URL: ${changeInfo.url}`);
        }

        // 4. Action: REDIRECT (Instead of "cancel")
        if (score >= 3) {
            console.log("BLOCKING MALICIOUS SITE");
            
            const warningPage = chrome.runtime.getURL("goaway.html");
            const finalUrl = warningPage + "?url=" + encodeURIComponent(changeInfo.url);

            // Immediate Redirect (The MV3 alternative to blocking)
            chrome.tabs.update(tabId, { url: finalUrl });
        }
        return;
    }

    // Score too low — allow
    console.log("Low risk, allowing:", url);
});
