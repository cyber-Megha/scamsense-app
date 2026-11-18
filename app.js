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

// 4. 3-Tier Forensic Verdict Controller
let typingTimer = null;

function closePopup() {
    const overlay = document.getElementById("scanPopupOverlay");
    if (overlay) overlay.classList.add("hidden");
    if (typingTimer) clearInterval(typingTimer);
}

function setScanning(moduleName) {
    if (typingTimer) clearInterval(typingTimer);
    const overlay = document.getElementById("scanPopupOverlay");
    if (overlay) overlay.classList.remove("hidden");

    document.getElementById("shieldSpinnerStage").classList.remove("hidden");
    document.getElementById("verdictRevealStage").classList.add("hidden");
    document.getElementById("verdictDetailsPanel").classList.add("hidden");

    const shackle = document.getElementById("lockShacklePath");
    if (shackle) shackle.classList.remove("unlocked");

    const unlockBanner = document.getElementById("unlockBigBanner");
    if (unlockBanner) unlockBanner.classList.add("hidden");

    const scanLabel = document.getElementById("scanningModuleLabel");
    if (scanLabel) {
        scanLabel.classList.remove("hidden");
        scanLabel.innerText = `FORENSIC SCANNING ${moduleName}...`;
    }
}

function typeGreenText(element, fullText) {
    if (!element) return;
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
    }, 55);
}

function showResult(res) {
    if (res.status === "error") {
        closePopup();
        alert("❌ " + res.message);
        return;
    }

    const d = res.data || {};
    const score = Number(d.risk_score || 0);

    // 3-Tier Classification Logic: 0-30 SAFE, 31-60 SUSPICIOUS, 61-100 HIGH RISK
    let tierLabel = "SAFE";
    let shapeClass = "shape-safe";
    let bannerText = "✅ SAFE";
    let bannerColor = "#00f3ff";

    if (score >= 61) {
        tierLabel = "HIGH RISK";
        shapeClass = "shape-high-risk";
        bannerText = "🚨 HIGH RISK";
        bannerColor = "#ff1e56";
    } else if (score >= 31) {
        tierLabel = "SUSPICIOUS";
        shapeClass = "shape-suspicious";
        bannerText = "⚠️ SUSPICIOUS";
        bannerColor = "#fbbf24";
    }

    // Step A: Unlock the shield padlock
    const shackle = document.getElementById("lockShacklePath");
    if (shackle) shackle.classList.add("unlocked");

    const scanLabel = document.getElementById("scanningModuleLabel");
    if (scanLabel) scanLabel.classList.add("hidden");

    const unlockBanner = document.getElementById("unlockBigBanner");
    if (unlockBanner) {
        unlockBanner.classList.remove("hidden");
        unlockBanner.innerText = bannerText;
        unlockBanner.style.color = bannerColor;
        unlockBanner.style.textShadow = `0 0 25px ${bannerColor}`;
    }

    // Step B: Transition to 2-second blinking verdict shape
    setTimeout(() => {
        document.getElementById("shieldSpinnerStage").classList.add("hidden");
        document.getElementById("verdictRevealStage").classList.remove("hidden");

        const heroBox = document.getElementById("verdictHeroBox");
        const statusText = document.getElementById("verdictStatusText");
        const percentText = document.getElementById("verdictPercentText");

        heroBox.className = `verdict-hero blink-2s ${shapeClass}`;
        statusText.innerText = tierLabel;
        percentText.innerText = `${score}% RISK SCORE`;

        const qrBanner = document.getElementById("decodedQrBanner");
        if (qrBanner) {
            if (res.decoded_qr) {
                qrBanner.classList.remove("hidden");
                qrBanner.innerText = "Decoded QR Payload: " + res.decoded_qr;
            } else {
                qrBanner.classList.add("hidden");
            }
        }

        // Populate 4 Module-Specific Forensic Sections
        document.getElementById("fDetected").textContent = d.what_was_detected || "Target payload analyzed.";
        document.getElementById("fWhy").textContent = d.why_suspicious || "Evaluated domain structure and threat intelligence.";
        document.getElementById("fImpact").textContent = d.how_affects_user || "Standard security precautions apply.";
        document.getElementById("fEvidence").textContent = d.evidence || `Risk Index: ${score}/100`;

        const actionsList = (d.how_to_stay_safe || []).join(" ");

        // Step C: After 2 seconds blink, dock verdict to top & reveal 4-point forensic breakdown
        setTimeout(() => {
            heroBox.classList.remove("blink-2s");
            heroBox.classList.add("docked-top");
            document.getElementById("verdictDetailsPanel").classList.remove("hidden");
            typeGreenText(document.getElementById("liveActionText"), actionsList || "Maintain standard cybersecurity precautions.");
        }, 2000);
    }, 1000);
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
