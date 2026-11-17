
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from scanners import extract_text_from_document, decode_qr_from_image
from threat_intel import check_virustotal_url
from ai_engine import analyze_threat

app = FastAPI(title="ScamSense 6-in-1 Threat Intelligence API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ১. URL Scanner
@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    vt_intel = check_virustotal_url(url)
    result = analyze_threat(content_type="Website URL", text_data=url, extra_intel=vt_intel)
    return {"status": "success", "virustotal": vt_intel, "data": result}

# ২. QR Code Scanner
@app.post("/api/scan/qr")
async def scan_qr(file: UploadFile = File(...)):
    file_bytes = await file.read()
    qr_url = decode_qr_from_image(file_bytes)
    if not qr_url:
        return {"status": "error", "message": "No valid QR code found in the image."}
    
    vt_intel = check_virustotal_url(qr_url)
    result = analyze_threat(content_type="QR Code Payload", text_data=f"Decoded QR Data: {qr_url}", extra_intel=vt_intel)
    return {"status": "success", "decoded_qr": qr_url, "virustotal": vt_intel, "data": result}

# ৩. Email Scanner
@app.post("/api/scan/email")
async def scan_email(sender: str = Form(""), subject: str = Form(""), body: str = Form(...)):
    email_full = f"Sender: {sender}\nSubject: {subject}\nEmail Body: {body}"
    result = analyze_threat(content_type="Email Phishing Check", text_data=email_full)
    return {"status": "success", "data": result}

# ৪. SMS / WhatsApp Message Scanner
@app.post("/api/scan/message")
async def scan_message(message: str = Form(...)):
    result = analyze_threat(content_type="SMS / Social Media Message", text_data=message)
    return {"status": "success", "data": result}

# ৫. Document Scanner (PDF / TXT)
@app.post("/api/scan/document")
async def scan_document(file: UploadFile = File(...)):
    file_bytes = await file.read()
    extracted_text = extract_text_from_document(file_bytes, file.filename)
    result = analyze_threat(content_type="Suspicious Document", text_data=extracted_text[:5000])
    return {"status": "success", "data": result}

# ৬. Image / Screenshot Scanner
@app.post("/api/scan/image")
async def scan_image(file: UploadFile = File(...)):
    file_bytes = await file.read()
    result = analyze_threat(content_type="Screenshot / Fake Receipt Image", image_bytes=file_bytes)
    return {"status": "success", "data": result}
from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory=".", html=True), name="frontend")
