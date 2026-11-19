function scanURL() {
    const v = document.getElementById("urlInput").value.trim();
    if (!v) return alert("Enter a URL!");
    const fd = new FormData();
    fd.append("url", v);
    sendReq("/url", fd, "URL");
}

function scanQR() {
    const f = document.getElementById("qrInput").files[0];
    if (!f) return alert("Upload a QR image!");
    const fd = new FormData();
    fd.append("file", f);
    sendReq("/qr", fd, "QR");
}

function scanEmail() {
    const s = document.getElementById("emailSender").value.trim();
    const b = document.getElementById("emailBody").value.trim();
    if (!b) return alert("Paste email content!");
    const fd = new FormData();
    fd.append("sender", s);
    fd.append("body", b);
    sendReq("/email", fd, "EMAIL");
}

function scanMessage() {
    const m = document.getElementById("msgInput").value.trim();
    if (!m) return alert("Paste message!");
    const fd = new FormData();
    fd.append("message", m);
    sendReq("/message", fd, "MESSAGE");
}

function scanDocument() {
    const f = document.getElementById("docInput").files[0];
    if (!f) return alert("Upload PDF/TXT!");
    const fd = new FormData();
    fd.append("file", f);
    sendReq("/document", fd, "DOCUMENT");
}

function scanImage() {
    const f = document.getElementById("imgInput").files[0];
    if (!f) return alert("Upload an image!");
    const fd = new FormData();
    fd.append("file", f);
    sendReq("/image", fd, "IMAGE");
}
