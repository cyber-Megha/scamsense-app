import os
import json
import google.generativeai as genai
from PIL import Image
import io
from dotenv import load_dotenv

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

generation_config = {
    "response_mime_type": "application/json",
}
model = genai.GenerativeModel('gemini-3.0-flash', generation_config=generation_config)

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
    
    inputs = [prompt]
    if image_bytes:
        img = Image.open(io.BytesIO(image_bytes))
        inputs.append(img)
        
    response = model.generate_content(inputs)
    return json.loads(response.text)
