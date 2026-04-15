document.addEventListener("DOMContentLoaded", () => {

    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get("url");

    const unsafeDisplay = document.getElementById("unsafe-url-display");
    const techUrl = document.getElementById("tech-url");
    const threatTypeDisplay = document.getElementById("threat-type");
    const threatType = params.get("type");

    // ── Populate the URL displays ──────────────────────────────────────
    if (targetUrl) {
        const decoded = decodeURIComponent(targetUrl);
        
        if (unsafeDisplay) unsafeDisplay.textContent = decoded;
        if (techUrl) techUrl.textContent = decoded;

        // NEW: Inject the threat type
        if (threatTypeDisplay) {
            // Replaces underscores with spaces so "BLACKLIST_MATCH" becomes "BLACKLIST MATCH"
            threatTypeDisplay.textContent = threatType ? threatType.replace("_", " ") : "UNKNOWN THREAT";
        }
        
    } else {
        if (unsafeDisplay) unsafeDisplay.textContent = "unknown";
        if (techUrl) techUrl.textContent = "unknown";
        if (threatTypeDisplay) threatTypeDisplay.textContent = "UNKNOWN THREAT";
    }
    // ──────────────────────────────────────────────────────────────────

    document.getElementById("btn-safe").addEventListener("click", goBack);
    document.getElementById("btn-exit").addEventListener("click", goBack);

    document.getElementById("btn-details").addEventListener("click", () => {
        document.getElementById("details").classList.toggle("hidden");
    });

    document.getElementById("btn-lockdown").addEventListener("click", () => {
        document.getElementById("primary-warning").classList.add("hidden");
        document.getElementById("lockdown-screen").classList.remove("hidden");
    });

    document.getElementById("btn-proceed").addEventListener("click", () => {
        if (!targetUrl) return;
        showNotice("SECURITY DISABLED. PROCEEDING...");

        const decodedUrl = decodeURIComponent(targetUrl);

        chrome.runtime.sendMessage({ action: "ALLOW_SITE", url: decodedUrl }, () => {
            setTimeout(() => {
                location.href = decodedUrl;
            }, 1500);
        });
    });

    function goBack() {
        showNotice("Returning to safety...");
        
        // Disable buttons to prevent spam clicks
        document.getElementById("btn-safe").disabled = true;
        document.getElementById("btn-exit").disabled = true;

        setTimeout(() => {
            // Check if there is enough history to jump over the malware site
            if (window.history.length > 2) {
                // Go back TWO pages to skip the blocked URL
                window.history.go(-2); 
            } else {
                // If there isn't enough history (e.g., they opened link in a new tab),
                // close the tab to protect them.
                window.close(); 
                
                // Fallback if the browser refuses to close the tab
                setTimeout(() => {
                    location.replace("https://www.google.com"); 
                }, 300);
            }
        }, 800);
    }
    function showNotice(text) {
        const notice = document.getElementById("notification");
        notice.textContent = text;
        notice.style.display = "block";
    }
});