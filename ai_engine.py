import os
import json
from google import genai
from google.genai import types
from PIL import Image
import io

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    prompt = f"""
    You are an elite Cybersecurity Threat Analyst for 'ScamSense'. 
    Analyze the following {content_type} for phishing, fraud, malware, or social engineering.
    Additional Threat Intel Data: {json.dumps(extra_intel) if extra_intel else 'None'}
    
    Return ONLY a valid JSON object with this exact schema:
    {{
        "risk_score": <integer from 0 to 100>,
        "risk_level": "<CRITICAL | HIGH | MEDIUM | LOW | SAFE>",
        "threat_category": "<e.g., Phishing, Fake Invoice, Malware Link, Safe Content>",
        "why_risky": [
            "<clear point 1>",
            "<clear point 2>"
        ],
        "how_to_stay_safe": [
            "<actionable step 1>",
            "<actionable step 2>"
        ],
        "technical_indicators": "<brief technical summary of red flags found>"
    }}
    
    Content to analyze: {text_data}
    """
    contents = [prompt]
    if image_bytes:
        img = Image.open(io.BytesIO(image_bytes))
        contents.append(img)

    # আপনার API Key-র জন্য সচল মডেলটি অটোমেটিক চেষ্টা করবে
    last_error = ""
    for model_name in ['gemini-3.0-flash', 'gemini-2.5-flash', 'gemini-2.0-flash']:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=contents,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            return json.loads(response.text)
        except Exception as e:
            last_error = str(e)
            continue

    return {
        "risk_score": 50,
        "risk_level": "CAUTION",
        "threat_category": "API Key Issue",
        "why_risky": [f"Model Error: {last_error}"],
        "how_to_stay_safe": ["Check your GEMINI_API_KEY in Render Environment settings."],
        "technical_indicators": "All fallback models failed."
    }
