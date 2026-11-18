import re
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from scanners import extract_text_from_document, decode_qr_from_image
from threat_intel import check_virustotal_url, check_email_domain_dns
from ai_engine import analyze_threat

app = FastAPI(title="ScamSense 7-Layer Zero-Trust Threat Engine", version="5.0")

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
        for u in urls[:3]:
            clean_u = u.rstrip(".,;:!?)")
            intel_reports.append(check_virustotal_url(clean_u))
        return intel_reports if intel_reports else None
    except Exception:
        return None

@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    vt_intel = check_virustotal_url(url)
    result = analyze_threat(content_type="Website URL", text_data=url, extra_intel=vt_intel)
    return {"status": "success", "virustotal": vt_intel, "data": result}

@app.post("/api/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    file_bytes = await file.read()
    qr_url = decode_qr_from_image(file_bytes)
    if not qr_url:
        return {"status": "error", "message": "No valid QR code found in the image."}
    vt_intel = check_virustotal_url(qr_url) if ("http" in qr_url.lower() or "." in qr_url) else None
    result = analyze_threat(content_type="QR Code Payload", text_data=f"Decoded QR Data: {qr_url}", extra_intel=vt_intel)
    return {"status": "success", "decoded_qr": qr_url, "virustotal": vt_intel, "data": result}

@app.post("/api/scan/email")
async def scan_email(sender: str = Form(""), subject: str = Form(""), body: str = Form(...)):
    email_full = f"Sender: {sender}\nSubject: {subject}\nEmail Body: {body}"
    dns_intel = check_email_domain_dns(sender)
    embedded_intel = extract_and_scan_embedded_urls(email_full)
    result = analyze_threat(
        content_type="Email Phishing Check",
        text_data=email_full,
        extra_intel={"sender_dns_forensics": dns_intel, "embedded_urls_intel": embedded_intel}
    )
    return {"status": "success", "data": result}

@app.post("/api/scan/message")
async def scan_message(message: str = Form(...)):
    embedded_intel = extract_and_scan_embedded_urls(message)
    result = analyze_threat(content_type="SMS / Social Media Message", text_data=message, extra_intel={"embedded_urls_intel": embedded_intel})
    return {"status": "success", "data": result}

@app.post("/api/scan/document")
async def scan_document(file: UploadFile = File(...)):
    file_bytes = await file.read()
    extracted_text = extract_text_from_document(file_bytes, file.filename)
    embedded_intel = extract_and_scan_embedded_urls(extracted_text[:5000])
    result = analyze_threat(content_type="Suspicious Document", text_data=extracted_text[:5000], extra_intel={"embedded_urls_intel": embedded_intel})
    return {"status": "success", "data": result}

@app.post("/api/scan/image")
async def scan_image(file: UploadFile = File(...)):
    file_bytes = await file.read()
    result = analyze_threat(content_type="Screenshot / Fake Receipt Image", image_bytes=file_bytes)
    return {"status": "success", "data": result}

app.mount("/", StaticFiles(directory=".", html=True), name="frontend")
