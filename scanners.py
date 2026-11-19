import os
import io
import PyPDF2
from PIL import Image
from google import genai

GEMINI_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
client = genai.Client(api_key=GEMINI_KEY) if GEMINI_KEY else None

def extract_text_from_document(file_bytes: bytes, filename: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        try:
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
            pages_text = [(page.extract_text() or "") for page in pdf_reader.pages]
            return "\n".join(pages_text).strip()
        except Exception as e:
            return f"Could not parse PDF content: {e}"
    if name.endswith(".txt"):
        return file_bytes.decode("utf-8", errors="ignore")
    return "Unsupported document format. Please upload PDF or TXT."

def decode_qr_from_image(file_bytes: bytes) -> str | None:
    if not client:
        return None
    for model_name in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
        try:
            img = Image.open(io.BytesIO(file_bytes))
            response = client.models.generate_content(
                model=model_name,
                contents=[
                    "Extract ONLY the exact URL or text encoded inside this QR code. If there is no QR code, reply strictly with NONE.",
                    img
                ]
            )
            decoded = (response.text or "").strip()
            if decoded and decoded.upper() != "NONE":
                return decoded
        except Exception:
            continue
    return None
