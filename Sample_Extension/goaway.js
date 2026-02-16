document.addEventListener("DOMContentLoaded", () => {

    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get("url");

    const unsafeDisplay = document.getElementById("unsafe-url-display");
    const techUrl = document.getElementById("tech-url");


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
        setTimeout(() => {
            location.href = decodeURIComponent(targetUrl);
        }, 1500);
    });

    function goBack() {
        showNotice("Returning to safety...");
        setTimeout(() => {
            if (history.length > 1) history.back();
            else location.href = "https://www.google.com";
        }, 800);
    }

    function showNotice(text) {
        const notice = document.getElementById("notification");
        notice.textContent = text;
        notice.style.display = "block";
    }
});
