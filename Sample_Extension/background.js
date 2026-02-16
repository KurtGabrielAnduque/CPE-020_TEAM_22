console.log("Phishing Guard service worker loaded");

chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing Guard installed / updated");
});

