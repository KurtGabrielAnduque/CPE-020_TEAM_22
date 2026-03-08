document.addEventListener("DOMContentLoaded", () => {

    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get("url");

    const unsafeDisplay = document.getElementById("unsafe-url-display");
    const techUrl = document.getElementById("tech-url");

    // ── Populate the URL displays ──────────────────────────────────────
    if (targetUrl) {
        const decoded = decodeURIComponent(targetUrl);
        unsafeDisplay.textContent = decoded;
        techUrl.textContent = decoded;
    } else {
        unsafeDisplay.textContent = "unknown";
        techUrl.textContent = "unknown";
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
        setTimeout(() => {
            location.replace("https://www.google.com");
        }, 800);
    }

    function showNotice(text) {
        const notice = document.getElementById("notification");
        notice.textContent = text;
        notice.style.display = "block";
    }
});