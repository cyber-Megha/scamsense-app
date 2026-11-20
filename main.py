import re
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scanners import extract_text_from_document, decode_qr_from_image
from threat_intel import analyze_url_deep, check_email_domain_dns, analyze_email_source
from ai_engine import analyze_threat

app = FastAPI(title="ScamSense Zero-Trust Threat Engine", version="5.3")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def extract_and_scan_embedded_urls(text: str):
    try:
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text or "")
        intel_reports = []
        seen = set()
        for raw_u in urls:
            clean_u = raw_u.rstrip(".,;:!?)]}>\"'")
            if not clean_u or clean_u in seen:
                continue
            seen.add(clean_u)
            intel_reports.append(analyze_url_deep(clean_u))
            if len(intel_reports) >= 3:
                break
        return intel_reports if intel_reports else None
    except Exception:
        return None


@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    try:
        clean_url = (url or "").strip()
        if not clean_url:
            return {"status": "error", "message": "Please provide a valid URL."}
        deep_intel = analyze_url_deep(clean_url)
        result = analyze_threat(
            content_type="Website URL",
            text_data=clean_url,
            extra_intel=deep_intel
        )
        return {"status": "success", "url_intel": deep_intel, "data": result}
    except Exception as exc:
        return {"status": "error", "message": f"URL scan failed: {exc}"}


@app.post("/api/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        if not file_bytes:
            return {"status": "error", "message": "Uploaded QR image is empty."}
        qr_payload = decode_qr_from_image(file_bytes)
        if not qr_payload:
            return {"status": "error", "message": "No valid QR code found or QR could not be decoded."}

        payload_str = qr_payload.strip()
        url_intel = None
        if re.search(r"(https?://|www\.|\.[a-z]{2,})", payload_str.lower()) and " " not in payload_str:
            url_intel = analyze_url_deep(payload_str)

        c_type = "UPI Payment QR Payload" if payload_str.lower().startswith("upi://") else "QR Code Payload"
        result = analyze_threat(
            content_type=c_type,
            text_data=f"Decoded QR Data: {payload_str}",
            extra_intel=url_intel
        )
        return {"status": "success", "decoded_qr": payload_str, "url_intel": url_intel, "data": result}
    except Exception as exc:
        return {"status": "error", "message": f"QR scan failed: {exc}"}


@app.post("/api/scan/email")
async def scan_email(sender: str = Form(""), subject: str = Form(""), body: str = Form("")):
    try:
        s_clean = (sender or "").strip()
        sub_clean = (subject or "").strip()
        b_clean = (body or "").strip()

        if not s_clean and not b_clean:
            return {"status": "error", "message": "Please provide a source email address or email body."}

        parts = []
        if s_clean:
            parts.append(f"Sender: {s_clean}")
        if sub_clean:
            parts.append(f"Subject: {sub_clean}")
        if b_clean:
            parts.append(f"Email Body: {b_clean}")
        email_full = "\n".join(parts)

        dns_intel = check_email_domain_dns(s_clean) if s_clean else None
        source_intel = analyze_email_source(s_clean or email_full) if s_clean else None
        embedded_intel = extract_and_scan_embedded_urls(email_full)

        c_type = "Source Email & Body Check" if b_clean else "Source Email Check"
        result = analyze_threat(
            content_type=c_type,
            text_data=email_full,
            extra_intel={
                "sender_dns_forensics": dns_intel,
                "source_email_forensics": source_intel,
                "embedded_urls_intel": embedded_intel
            }
        )
        return {"status": "success", "source_intel": source_intel, "data": result}
    except Exception as exc:
        return {"status": "error", "message": f"Email scan failed: {exc}"}


@app.post("/api/scan/message")
async def scan_message(message: str = Form(...)):
    try:
        msg_clean = (message or "").strip()
        if not msg_clean:
            return {"status": "error", "message": "Message text cannot be empty."}
        embedded_intel = extract_and_scan_embedded_urls(msg_clean)
        result = analyze_threat(
            content_type="SMS / Social Media Message",
            text_data=msg_clean,
            extra_intel={"embedded_urls_intel": embedded_intel}
        )
        return {"status": "success", "data": result}
    except Exception as exc:
        return {"status": "error", "message": f"Message scan failed: {exc}"}


@app.post("/api/scan/document")
async def scan_document(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        if not file_bytes:
            return {"status": "error", "message": "Uploaded document is empty."}
        extracted_text = extract_text_from_document(file_bytes, file.filename or "")
        embedded_intel = extract_and_scan_embedded_urls(extracted_text[:5000])
        result = analyze_threat(
            content_type="Suspicious Document",
            text_data=extracted_text[:5000],
            extra_intel={"embedded_urls_intel": embedded_intel}
        )
        return {"status": "success", "data": result}
    except Exception as exc:
        return {"status": "error", "message": f"Document scan failed: {exc}"}


@app.post("/api/scan/image")
async def scan_image(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        if not file_bytes:
            return {"status": "error", "message": "Uploaded image is empty."}
        result = analyze_threat(
            content_type="Screenshot / Fake Receipt Image",
            image_bytes=file_bytes
        )
        return {"status": "success", "data": result}
    except Exception as exc:
        return {"status": "error", "message": f"Image scan failed: {exc}"}


app.mount("/", StaticFiles(directory=".", html=True), name="frontend")
