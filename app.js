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

// 2. Red & Green Matrix Hacker Code Rain Background
const canvas = document.getElementById("bg-canvas");
const ctx = canvas.getContext("2d");
function resizeCanvas() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
window.addEventListener("resize", resizeCanvas);
resizeCanvas();

const chars = "01アイウエオカキクケコSCAMSENSE$#@%&*";
const fontSize = 15;
let columns = Math.floor(canvas.width / fontSize);
let drops = Array(columns).fill(1);

function drawHackerMatrix() {
    ctx.fillStyle = "rgba(5, 2, 5, 0.14)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = fontSize + "px monospace";

    for (let i = 0; i < drops.length; i++) {
        const text = chars[Math.floor(Math.random() * chars.length)];
        // Alternate between Hacker Green and Crimson Red
        ctx.fillStyle = (i % 4 === 0) ? "rgba(255, 30, 86, 0.55)" : "rgba(0, 255, 102, 0.45)";
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }
        drops[i]++;
    }
}
setInterval(drawHackerMatrix, 45);

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

// 4. Backend AI Scanner Logic
const API_BASE = "/api/scan";


function setScanning(name) {
    document.getElementById("resultSection").scrollIntoView({ behavior: "smooth" });
    document.getElementById("scanStatus").innerText = "SCANNING " + name + "...";
    document.getElementById("riskLevelBadge").innerText = "ANALYZING";
    document.getElementById("riskScoreText").innerText = "...";
    document.getElementById("aiResultContainer").innerHTML = "<p style='color:#00ff66;font-family:monospace;'>> [SYSTEM] Intercepting payload & executing AI deep scan...</p>";
}

function showResult(res) {
    if (res.status === "error") {
        document.getElementById("scanStatus").innerText = "SCAN ERROR";
        document.getElementById("aiResultContainer").innerHTML = "<p style='color:#ff1e56;'>❌ " + res.message + "</p>";
        return;
    }
    const d = res.data;
    const score = d.risk_score || 0;
    document.getElementById("riskScoreText").innerText = score + "%";
    document.getElementById("riskLevelBadge").innerText = d.risk_level || "DONE";
    document.getElementById("threatCategoryText").innerText = d.threat_category || "Analyzed";
    document.getElementById("scanStatus").innerText = "SCAN COMPLETE";

    const color = score >= 70 ? "#ff1e56" : (score >= 35 ? "#fbbf24" : "#00ff66");
    document.getElementById("riskScoreText").style.color = color;
    document.getElementById("riskLevelBadge").style.color = color;
    document.getElementById("ring1").style.borderColor = color;

    const risky = (d.why_risky || []).map(i => "<li style='margin-bottom:5px;'>• " + i + "</li>").join("");
    const safe = (d.how_to_stay_safe || []).map(i => "<li style='margin-bottom:5px;'>✓ " + i + "</li>").join("");
    const qrInfo = res.decoded_qr ? "<p style='color:#00ff66;font-family:monospace;margin-bottom:12px;'><b>Decoded QR:</b> " + res.decoded_qr + "</p>" : "";

    document.getElementById("aiResultContainer").innerHTML = qrInfo +
        "<div class='verdict-grid'>" +
        "<div class='box-risky'><h4 style='color:#ff1e56;font-family:Orbitron,sans-serif;font-size:0.82rem;margin-bottom:8px;'>🧐 WHY IT IS RISKY:</h4><ul style='list-style:none;font-size:0.88rem;color:#fecdd3;'>" + risky + "</ul></div>" +
        "<div class='box-safe'><h4 style='color:#00ff66;font-family:Orbitron,sans-serif;font-size:0.82rem;margin-bottom:8px;'>🛡️ HOW TO STAY SAFE:</h4><ul style='list-style:none;font-size:0.88rem;color:#a7f3d0;'>" + safe + "</ul></div>" +
        "</div><p style='font-family:monospace;font-size:0.8rem;color:#fda4af;'><b>FORENSICS:</b> " + (d.technical_indicators || "") + "</p>";
}

async function sendReq(endpoint, formData, name) {
    setScanning(name);
    try {
        const r = await fetch("/api/scan" + endpoint, { method: "POST", body: formData });
        if (!r.ok) {
            const errText = await r.text();
            alert("Server Error (" + r.status + "): " + errText);
            return;
        }
        showResult(await r.json());
    } catch (e) {
        alert("Connection Error: " + e.message);
    }
}


function scanURL() { const v = document.getElementById("urlInput").value.trim(); if (!v) return alert("Enter a URL!"); const fd = new FormData(); fd.append("url", v); sendReq("/url", fd, "URL"); }
function scanQR() { const f = document.getElementById("qrInput").files; if (!f) return alert("Upload a QR image!"); const fd = new FormData(); fd.append("file", f); sendReq("/qr", fd, "QR"); }
function scanEmail() { const s = document.getElementById("emailSender").value.trim(); const b = document.getElementById("emailBody").value.trim(); if (!b) return alert("Paste email content!"); const fd = new FormData(); fd.append("sender", s); fd.append("body", b); sendReq("/email", fd, "EMAIL"); }
function scanMessage() { const m = document.getElementById("msgInput").value.trim(); if (!m) return alert("Paste message!"); const fd = new FormData(); fd.append("message", m); sendReq("/message", fd, "MESSAGE"); }
function scanDocument() { const f = document.getElementById("docInput").files; if (!f) return alert("Upload PDF/TXT!"); const fd = new FormData(); fd.append("file", f); sendReq("/document", fd, "DOCUMENT"); }
function scanImage() { const f = document.getElementById("imgInput").files; if (!f) return alert("Upload an image!"); const fd = new FormData(); fd.append("file", f); sendReq("/image", fd, "IMAGE"); }
