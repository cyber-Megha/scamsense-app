import PyPDF2
import io
from PIL import Image
from google import genai
import os

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def extract_text_from_document(file_bytes: bytes, filename: str) -> str:
    if filename.lower().endswith(".pdf"):
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() or ""
        return text
    elif filename.lower().endswith(".txt"):
        return file_bytes.decode("utf-8", errors="ignore")
    return "Unsupported document format. Please upload PDF or TXT."

def decode_qr_from_image(file_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(file_bytes))
    response = client.models.generate_content(
        model='gemini-3.8-flash',
        contents=[
            "Extract ONLY the exact URL or text encoded inside this QR code. If there is no QR code, reply strictly with NONE.", 
            img
        ]
    )
    decoded = response.text.strip()
    return None if decoded == "NONE" or not decoded else decoded
