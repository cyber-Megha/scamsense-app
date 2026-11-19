import re
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scanners import extract_text_from_document, decode_qr_from_image
from threat_intel import analyze_url_deep, check_email_domain_dns
from ai_engine import analyze_threat

app = FastAPI(title="ScamSense Zero-Trust Threat Engine", version="5.1")

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
    if not (url or "").strip():
        return {"status": "error", "message": "Please provide a valid URL."}
    deep_intel = analyze_url_deep(url.strip())
    result = analyze_threat(
        content_type="Website URL",
        text_data=url.strip(),
        extra_intel=deep_intel
    )
    return {"status": "success", "url_intel": deep_intel, "data": result}

@app.post("/api/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    file_bytes = await file.read()
    if not file_bytes:
        return {"status": "error", "message": "Uploaded QR image is empty."}
    qr_payload = decode_qr_from_image(file_bytes)
    if not qr_payload:
        return {"status": "error", "message": "No valid QR code found or QR could not be decoded."}

    url_intel = None
    if re.search(r"(https?://|www\.|\.[a-z]{2,})", qr_payload.lower()) and " " not in qr_payload.strip():
        url_intel = analyze_url_deep(qr_payload.strip())

    result = analyze_threat(
        content_type="QR Code Payload",
        text_data=f"Decoded QR Data: {qr_payload}",
        extra_intel=url_intel
    )
    return {"status": "success", "decoded_qr": qr_payload, "url_intel": url_intel, "data": result}

@app.post("/api/scan/email")
async def scan_email(sender: str = Form(""), subject: str = Form(""), body: str = Form(...)):
    if not (body or "").strip():
        return {"status": "error", "message": "Email body cannot be empty."}
    email_full = f"Sender: {sender}\nSubject: {subject}\nEmail Body: {body}"
    dns_intel = check_email_domain_dns(sender)
    embedded_intel = extract_and_scan_embedded_urls(email_full)
    result = analyze_threat(
        content_type="Email Phishing Check",
        text_data=email_full,
        extra_intel={
            "sender_dns_forensics": dns_intel,
            "embedded_urls_intel": embedded_intel
        }
    )
    return {"status": "success", "data": result}

@app.post("/api/scan/message")
async def scan_message(message: str = Form(...)):
    if not (message or "").strip():
        return {"status": "error", "message": "Message text cannot be empty."}
    embedded_intel = extract_and_scan_embedded_urls(message)
    result = analyze_threat(
        content_type="SMS / Social Media Message",
        text_data=message,
        extra_intel={"embedded_urls_intel": embedded_intel}
    )
    return {"status": "success", "data": result}

@app.post("/api/scan/document")
async def scan_document(file: UploadFile = File(...)):
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

@app.post("/api/scan/image")
async def scan_image(file: UploadFile = File(...)):
    file_bytes = await file.read()
    if not file_bytes:
        return {"status": "error", "message": "Uploaded image is empty."}
    result = analyze_threat(
        content_type="Screenshot / Fake Receipt Image",
        image_bytes=file_bytes
    )
    return {"status": "success", "data": result}

app.mount("/", StaticFiles(directory=".", html=True), name="frontend")
