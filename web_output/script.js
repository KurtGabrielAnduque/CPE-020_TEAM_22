    function goBack() {
            const notice = document.getElementById('notification');
            notice.style.opacity = '1';
            setTimeout(() => {
                window.location.href = "https://www.google.com";
            }, 1200);
        }

        function toggleDetails() {
            document.getElementById('details').classList.toggle('show-details');
        }

        function triggerLockdown() {
            const primary = document.getElementById('primary-warning');
            primary.style.opacity = '0';
            primary.style.transform = 'scale(0.85)';
            setTimeout(() => {
                primary.style.display = 'none';
                const lockdown = document.getElementById('lockdown-screen');
                lockdown.style.display = 'flex';
            }, 400);
        }

        function finalProceed() {
            const notice = document.getElementById('notification');
            notice.innerText = "SECURITY DISABLED. PROCEEDING...";
            notice.style.backgroundColor = "#000";
            notice.style.color = "#fff";
            notice.style.opacity = '1';
    }