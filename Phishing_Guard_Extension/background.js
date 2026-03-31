    console.log("Phishing Guard Advanced Engine Active");

    // ─── CONFIGURATION ───────────────────────────────────────────────────────────

    const SUSPICIOUS_TLDS = [".html", ".id", ".is", ".ua", ".ro", ".fr", ".zip", ".si", ".at", ".il", ".store", ".exe", ".eu", ".in", ".au", ".gif", ".be", ".fi", ".sk", ".info", ".es", ".tk", ".ru", ".rar", ".de", ".pl", ".cz", ".txt", ".ch", ".nl", ".mk", ".work", ".top", ".cl", ".link", ".men", ".date", ".gq", ".ln", ".reveiw", '.io', '.dev', '.click'];

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
    const SCORE_BLOCK    = 5;  // Block immediately, no ML check needed
    const SCORE_MEDIUM   = 3;  // Uncertain — send to Django for ML verdict
    const DJANGO_API_URL = "http://127.0.0.1:8000/analyze/"; // Your future Django endpoint

    // ─── ALLOWLIST (session-persistent) ──────────────────────────────────────────

    async function isAllowlisted(url) {
        return new Promise((resolve) => {
            // Check session allowlist first
            chrome.storage.session.get("allowlist", (sessionData) => {
                const sessionList = sessionData.allowlist || [];
                if (sessionList.includes(url)) return resolve(true);

                // Also check proceedList from local storage
                chrome.storage.local.get("proceedList", (localData) => {
                    const proceedList = localData.proceedList || [];
                    resolve(proceedList.includes(url));
                });
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

    chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
        if (request.action === "ALLOW_SITE") {
            addToAllowlist(request.url).then(() => {
                console.log("Externally allowlisted:", request.url);
                sendResponse({ success: true });
            });
            return true;
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
                score += 2;
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

    // ─── DJANGO ML CHECK (MEDIUM SCORE LAYER) ────────────────────────────────────

    async function checkWithDjango(url) {
        try {
            const response = await fetch(DJANGO_API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });

            if (!response.ok) throw new Error("Django API error: " + response.status);

            const data = await response.json();
            // Expected response from Django: { is_phishing: true/false, confidence: 0.0-1.0 }
            console.log("Django ML verdict:", data);
            return data;

        } catch (e) {
            // If backend is unreachable, fail safe — don't block
            console.warn("Django ML check failed, failing safe:", e.message);
            return { is_phishing: false, confidence: 0 };
        }
    }

// ─── REDIRECT TO WARNING PAGE ─────────────────────────────────────────────────
// Layer 1: Blocked by heuristics → extension page (no backend needed)
function blockSiteLocal(tabId, targetUrl) {
    const warningPage = chrome.runtime.getURL("goaway.html");
    const finalUrl    = warningPage + "?url=" + encodeURIComponent(targetUrl);
    chrome.tabs.update(tabId, { url: finalUrl });
}

// Layer 2: Blocked by ML backend → Django warning page
function blockSiteDjango(tabId, targetUrl) {
    const finalUrl = `http://127.0.0.1:8000/goaway/?url=${encodeURIComponent(targetUrl)}`;
    chrome.tabs.update(tabId, { url: finalUrl });
}
function blockSite(tabId, targetUrl) {
    const warningPage = chrome.runtime.getURL("goaway.html");
    const finalUrl = warningPage + "?url=" + encodeURIComponent(targetUrl);
    chrome.tabs.update(tabId, { url: finalUrl });
}

    // ─── MAIN LISTENER ────────────────────────────────────────────────────────────

    chrome.webNavigation.onErrorOccurred.addListener((details) => {
        if (details.error === "net::ERR_BLOCKED_BY_CLIENT") {
            console.log("Blocked by PhishTank ruleset:", details.url);
            blockSite(details.tabId, details.url);
        }
    });

    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
        if (!changeInfo.url) return;

        const url = changeInfo.url;

        // Ignore internal pages
        if (url.startsWith("chrome://") || url.includes("chrome-extension://") || url.includes("goaway.html") || url.startsWith("http://127.0.0.1:8000")) return;

        // Check session allowlist
        if (await isAllowlisted(url)) {
            console.log("Allowlisted, skipping:", url);
            return;
        }

        // Check safelist
        try {
            const hostname = new URL(url).hostname.toLowerCase();
            if (SAFELIST.has(hostname)) {
                console.log("Safelisted domain, skipping:", hostname);
                return;
            }
        } catch (_) { return; }

        // Run heuristics
        const { score, reasons } = calculateRiskScore(url);



        // Layer 1: High score — block immediately
        if (score >= SCORE_BLOCK) {
            console.log(`Score: ${score}`);
            console.log("HIGH SCORE — Blocking immediately:", url);
            blockSiteLocal(tabId, url);  // ← extension goaway.html
            return;
        }

        // Layer 2: Medium score — consult Django ML backend
        if (score >= 2) {
            console.log(`Score: ${score}`);
            console.log("MEDIUM SCORE — Sending to Django:", url);
            const verdict = await checkWithDjango(url);

            if (verdict.is_phishing) {
                console.log(`ML CONFIRMED — Blocking (confidence: ${verdict.confidence}):`, url);
                blockSiteDjango(tabId, url);  // ← Django goaway page
            } else {
                console.log(`ML CLEARED — Allowing (confidence: ${verdict.confidence}):`, url);
            }
            return;
        }

        // Score too low — allow
        console.log("Low risk, allowing:", url);
    });

