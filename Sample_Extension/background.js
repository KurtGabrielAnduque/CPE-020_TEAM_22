console.log("Phishing Guard Advanced Engine Active");


const SUSPICIOUS_TLDS = ['.zip', '.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.work'];
const TARGET_BRANDS = [
    { name: "paypal", domain: "paypal.com" },
    { name: "google", domain: "google.com" },
    { name: "apple", domain: "apple.com" },
    { name: "facebook", domain: "facebook.com" },
    { name: "microsoft", domain: "microsoft.com" },
    { name: "netflix", domain: "netflix.com" },
    { name: "amazon", domain: "amazon.com" }
];


function calculateRiskScore(urlStr) {
    let score = 0;
    
    try {
        const urlObj = new URL(urlStr);
        const hostname = urlObj.hostname.toLowerCase();
        const pathname = urlObj.pathname.toLowerCase();
        const wholeUrl = urlStr.toLowerCase();

        
        const tld = "." + hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.includes(tld)) {
            console.log(`Log: Suspicious TLD detected (${tld})`);
            score += 2;
        }

        
        if (hostname.includes("xn--")) {
            console.log("Log: Punycode (homograph attack) detected");
            score += 2;
        }

        
        const dotCount = hostname.split('.').length - 1;
        if (dotCount >= 4) { 
            console.log("Log: Excessive subdomain depth");
            score += 1;
        }

        
        TARGET_BRANDS.forEach(brand => {
            if (hostname.includes(brand.name)) {
                
                if (!hostname.endsWith(brand.domain)) {
                    console.log(`Log: Brand mismatch detected! claiming ${brand.name} but on ${hostname}`);
                    score += 3; 
                }
            }
        });

        
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
             console.log("Log: Raw IP address used");
             score += 2;
        }

        
        if (wholeUrl.includes("login") || wholeUrl.includes("signin") || wholeUrl.includes("verify") || wholeUrl.includes("wallet")) {
            score += 1;
        }

    } catch (e) {
        console.error("Analysis failed:", e);
    }

    return score;
}


chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    

    if (changeInfo.url) {
        

        if (changeInfo.url.startsWith("chrome://") || 
            changeInfo.url.includes("chrome-extension://") ||
            changeInfo.url.includes("goaway.html")) {
            return;
        }

        console.log("Analyzing:", changeInfo.url);


        const score = calculateRiskScore(changeInfo.url);

        if (score > 0) {
            console.log(`[Risk Analysis] Score: ${score} | URL: ${changeInfo.url}`);
        }


        if (score >= 3) {
            console.log("BLOCKING MALICIOUS SITE");
            
            const warningPage = chrome.runtime.getURL("goaway.html");
            const finalUrl = warningPage + "?url=" + encodeURIComponent(changeInfo.url);


            chrome.tabs.update(tabId, { url: finalUrl });
        }
    }
});
