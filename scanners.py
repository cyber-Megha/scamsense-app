import os
import io
import re
import PyPDF2
import cv2
import numpy as np
from PIL import Image, ImageOps, ImageEnhance
from google import genai

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
except Exception:
    pyzbar_decode = None

GEMINI_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
client = genai.Client(api_key=GEMINI_KEY, http_options={"timeout": 10.0}) if GEMINI_KEY else None


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


def _clean_decoded_payload(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = raw.strip()
    if not cleaned or cleaned.upper() in ("NONE", "NULL", "N/A"):
        return None
    if cleaned.startswith(("http://", "https://", "www.", "upi://", "mailto:", "tel:", "sms:")):
        return cleaned.split()[0].strip()
    return cleaned


def _build_image_variants(file_bytes: bytes) -> list[Image.Image]:
    pil_img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    bordered = ImageOps.expand(pil_img, border=48, fill="white")
    gray = ImageOps.grayscale(bordered)
    inverted = ImageOps.invert(gray)
    high_contrast = ImageEnhance.Contrast(gray).enhance(1.8)
    sharp = ImageEnhance.Sharpness(high_contrast).enhance(2.0)

    variants = [pil_img, bordered, gray, inverted, high_contrast, sharp]

    for base in (gray, inverted):
        try:
            arr_g = np.array(base)
            _, otsu = cv2.threshold(arr_g, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            variants.append(Image.fromarray(otsu).convert("RGB"))
        except Exception:
            pass

    for scale in (1.5, 0.75, 2.0):
        w, h = bordered.size
        rw = max(64, min(2400, int(w * scale)))
        rh = max(64, min(2400, int(h * scale)))
        variants.append(bordered.resize((rw, rh)))

    return variants


def _decode_with_pyzbar(variants: list[Image.Image]) -> str | None:
    if not pyzbar_decode:
        return None
    for img in variants:
        try:
            decoded_items = pyzbar_decode(img)
            for item in decoded_items or []:
                raw_text = (item.data or b"").decode("utf-8", errors="ignore")
                clean = _clean_decoded_payload(raw_text)
                if clean:
                    return clean
        except Exception:
            continue
    return None


def _decode_with_cv2(variants: list[Image.Image]) -> str | None:
    detector = cv2.QRCodeDetector()
    for img in variants:
        for angle in (0, 90, 180, 270):
            rotated = img.rotate(angle, expand=True) if angle else img
            try:
                arr = np.array(rotated.convert("RGB"))
                data, _, _ = detector.detectAndDecode(arr)
                clean = _clean_decoded_payload(data)
                if clean:
                    return clean
            except Exception:
                pass

            try:
                arr = np.array(rotated.convert("RGB"))
                retval, decoded_info, _, _ = detector.detectAndDecodeMulti(arr)
                if retval and decoded_info:
                    for item in decoded_info:
                        clean = _clean_decoded_payload(item)
                        if clean:
                            return clean
            except Exception:
                pass

    return None


def _decode_with_gemini_vision(file_bytes: bytes) -> str | None:
    if not client:
        return None
    for model_name in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
        try:
            img = Image.open(io.BytesIO(file_bytes))
            response = client.models.generate_content(
                model=model_name,
                contents=[
                    (
                        "Read the QR code in this image with exact character-for-character accuracy. "
                        "Return ONLY the exact raw decoded string/URL/URI without markdown, quotes, or explanation. "
                        "If no readable QR code is present, return strictly NONE."
                    ),
                    img
                ],
                config={"temperature": 0.0}
            )
            clean = _clean_decoded_payload(getattr(response, "text", None))
            if clean:
                uri_match = re.search(
                    r"(?:https?://|www\.|upi://|mailto:|tel:|sms:)[^\s<>\"']+",
                    clean,
                    flags=re.IGNORECASE
                )
                if uri_match:
                    return uri_match.group(0).rstrip(".,;:!?)]}>\"'")
                lines = [ln.strip() for ln in clean.splitlines() if ln.strip()]
                if lines:
                    return lines[0]
        except Exception:
            continue
    return None


def decode_qr_from_image(file_bytes: bytes) -> str | None:
    if not file_bytes:
        return None

    try:
        variants = _build_image_variants(file_bytes)
    except Exception:
        variants = []

    if variants:
        cv_res = _decode_with_cv2(variants)
        if cv_res:
            return cv_res

    if variants:
        zbar_res = _decode_with_pyzbar(variants)
        if zbar_res:
            return zbar_res

    return _decode_with_gemini_vision(file_bytes)
