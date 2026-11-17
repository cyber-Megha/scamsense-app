javascript
// 1. 5-Second Hollywood Hacker Decryption Intro Controller
const statusMessages = [
    "BYPASSING PROXY PROTOCOLS...",
    "LOADING THREAT SIGNATURES...",
    "ARMING AI NEURAL SHIELD...",
    "ACCESS GRANTED // WELCOME"
];
let msgIndex = 0;
const msgInterval = setInterval(() => {
    const el = document.getElementById("decryptStatus");
    if (el && msgIndex < statusMessages.length) {
        el.innerText = statusMessages[msgIndex++];
    }
}, 1050);

setTimeout(() => {
    clearInterval(msgInterval);
    const splash = document.getElementById("splash-screen");
    if (splash) {
        splash.style.opacity = "0";
        setTimeout(() => { splash.style.display = "none"; }, 800);
    }
}, 5000);

// 2. Static Grand Electric Blue, Purple & Bright Pink Cyber Code Texture
function renderStaticCyberBackdrop() {
    const canvas = document.getElementById("bg-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const glyphs = "01アイウエオカキクケコ01011001XYZ<>/{}[]";
    const colors = [
        "rgba(255, 20, 147, 0.58)",
        "rgba(255, 70, 190, 0.52)",
        "rgba(0, 243, 255, 0.55)",
        "rgba(56, 189, 248, 0.48)",
        "rgba(192, 38, 211, 0.52)"
    ];

    const colWidth = 16;
    const rowHeight = 15;
    const cols = Math.ceil(canvas.width / colWidth);
    const rows = Math.ceil(canvas.height / rowHeight);

    ctx.font = "bold 12px 'Fira Code', monospace";

    for (let c = 0; c < cols; c++) {
        if (Math.random() > 0.72) continue;
        const colColor = colors[Math.floor(Math.random() * colors.length)];
        const startRow = Math.floor(Math.random() * 6);
        const endRow = rows - Math.floor(Math.random() * 6);

        ctx.fillStyle = colColor.replace(/0\.\d+\)/, "0.11)");
        ctx.fillRect(c * colWidth - 1, startRow * rowHeight, 11, (endRow - startRow) * rowHeight);

        for (let r = startRow; r < endRow; r++) {
            if (Math.random() > 0.76) continue;
            const char = glyphs[Math.floor(Math.random() * glyphs.length)];
            ctx.fillStyle = colColor;
            ctx.fillText(char, c * colWidth, r * rowHeight);
        }
    }
}

window.addEventListener("resize", renderStaticCyberBackdrop);
renderStaticCyberBackdrop();

// 3. True 3D Interactive Tilt Effect on Hover
document.querySelectorAll(".float-card").forEach(card => {
    card.addEventListener("mousemove", e => {
        const rect = card.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        card.style.transform = `perspective(1000px) rotateY(${x * 16}deg) rotateX(${-y * 16}deg) translateY(-8px)`;
    });
    card.addEventListener("mouseleave", () => {
        card.style.transform = "perspective(1000px) rotateY(0deg) rotateX(0deg) translateY(0px)";
    });
});

// 4. Popup Lock-Shield & Cinematic Verdict Controller
let typingTimer = null;

function closePopup() {
    document.getElementById("scanPopupOverlay").classList.add("hidden");
    if (typingTimer) clearInterval(typingTimer);
}

function setScanning(moduleName) {
    if (typingTimer) clearInterval(typingTimer);
    const overlay = document.getElementById("scanPopupOverlay");
    overlay.classList.remove("hidden");

    document.getElementById("shieldSpinnerStage").classList.remove("hidden");
    document.getElementById("verdictRevealStage").classList.add("hidden");
    document.getElementById("verdictDetailsPanel").classList.add("hidden");

    const shackle = document.getElementById("lockShacklePath");
    if (shackle) shackle.classList.remove("unlocked");

    const unlockBanner = document.getElementById("unlockBigBanner");
    if (unlockBanner) unlockBanner.classList.add("hidden");

    const scanLabel = document.getElementById("scanningModuleLabel");
    scanLabel.classList.remove("hidden");
    scanLabel.innerText = `SCANNING ${moduleName} PAYLOAD...`;
}

// CLEAN WORD-BY-WORD TYPING SO SPACES ARE 100% PRESERVED AND TEXT NEVER OVERFLOWS
function typeGreenText(element, fullText) {
    element.textContent = "";
    const words = fullText.replace(/\s+/g, " ").trim().split(" ");
    let idx = 0;
    typingTimer = setInterval(() => {
        if (idx < words.length) {
            element.textContent += (idx === 0 ? "" : " ") + words[idx];
            idx++;
        } else {
            clearInterval(typingTimer);
        }
    }, 65);
}

function showResult(res) {
    if (res.status === "error") {
        closePopup();
        alert("❌ " + res.message);
        return;
    }

    const d = res.data;
    const score = d.risk_score || 0;
    const isRisky = score >= 40;

    // Step A: Unlock the shield padlock & float big RISKY/SAFE text
    const shackle = document.getElementById("lockShacklePath");
    if (shackle) shackle.classList.add("unlocked");

    document.getElementById("scanningModuleLabel").classList.add("hidden");

    const unlockBanner = document.getElementById("unlockBigBanner");
    unlockBanner.classList.remove("hidden");
    unlockBanner.innerText = isRisky ? "⚠️ RISKY" : "✅ SAFE";
    unlockBanner.style.color = isRisky ? "#ff1e56" : "#00f3ff";
    unlockBanner.style.textShadow = isRisky ? "0 0 25px #ff1e56" : "0 0 25px #00f3ff";

    // Step B: Transition to blinking verdict shape
    setTimeout(() => {
        document.getElementById("shieldSpinnerStage").classList.add("hidden");
        document.getElementById("verdictRevealStage").classList.remove("hidden");

        const heroBox = document.getElementById("verdictHeroBox");
        const statusText = document.getElementById("verdictStatusText");
        const percentText = document.getElementById("verdictPercentText");

        heroBox.className = "verdict-hero blink-2s " + (isRisky ? "shape-risky" : "shape-safe");
        statusText.innerText = isRisky ? "RISKY" : "SAFE";
        percentText.innerText = `${score}% ${isRisky ? "RISK" : "SAFE"}`;

        const actionsList = (d.how_to_stay_safe || []).join(" ");
        const reasonsList = (d.why_risky || []).slice(0, 2).join(" ");

        const alertPill = document.getElementById("alertTagBadge");
        const shortReasonEl = document.getElementById("shortReasonText");
        const qrBanner = document.getElementById("decodedQrBanner");

        if (res.decoded_qr) {
            qrBanner.classList.remove("hidden");
            qrBanner.innerText = "Decoded QR Payload: " + res.decoded_qr;
        } else {
            qrBanner.classList.add("hidden");
        }

        if (isRisky) {
            alertPill.innerText = "ALERT";
            alertPill.className = "alert-pill pill-danger";
            shortReasonEl.innerText = reasonsList || "High probability of phishing, financial loss, or malware infection.";
        } else {
            alertPill.innerText = "VERIFIED";
            alertPill.className = "alert-pill pill-safe";
            shortReasonEl.innerText = reasonsList || "No malicious signatures or phishing threats detected in this target.";
        }

        // Step C: After 2 seconds blink, dock verdict to top & type clean spaced green advice
        setTimeout(() => {
            heroBox.classList.remove("blink-2s");
            heroBox.classList.add("docked-top");
            document.getElementById("verdictDetailsPanel").classList.remove("hidden");
            typeGreenText(document.getElementById("liveActionText"), actionsList || "Proceed safely, but always keep security awareness active.");
        }, 2000);
    }, 1100);
}

async function sendReq(endpoint, formData, name) {
    setScanning(name);
    try {
        const r = await fetch("/api/scan" + endpoint, { method: "POST", body: formData });
        if (!r.ok) {
            closePopup();
            alert("Server Error (" + r.status + ")");
            return;
        }
        showResult(await r.json());
    } catch (e) {
        closePopup();
        alert("Connection Error: " + e.message);
    }
}

function scanURL() { const v = document.getElementById("urlInput").value.trim(); if (!v) return alert("Enter a URL!"); const fd = new FormData(); fd.append("url", v); sendReq("/url", fd, "URL"); }
function scanQR() { const f = document.getElementById("qrInput").files; if (!f) return alert("Upload a QR image!"); const fd = new FormData(); fd.append("file", f); sendReq("/qr", fd, "QR"); }
function scanEmail() { const s = document.getElementById("emailSender").value.trim(); const b = document.getElementById("emailBody").value.trim(); if (!b) return alert("Paste email content!"); const fd = new FormData(); fd.append("sender", s); fd.append("body", b); sendReq("/email", fd, "EMAIL"); }
function scanMessage() { const m = document.getElementById("msgInput").value.trim(); if (!m) return alert("Paste message!"); const fd = new FormData(); fd.append("message", m); sendReq("/message", fd, "MESSAGE"); }
function scanDocument() { const f = document.getElementById("docInput").files; if (!f) return alert("Upload PDF/TXT!"); const fd = new FormData(); fd.append("file", f); sendReq("/document", fd, "DOCUMENT"); }
function scanImage() { const f = document.getElementById("imgInput").files; if (!f) return alert("Upload an image!"); const fd = new FormData(); fd.append("file", f); sendReq("/image", fd, "IMAGE"); }
