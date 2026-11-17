import os
import json
import google.generativeai as genai
from PIL import Image
import io

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def get_working_model(use_json=True):
    # আপনার API Key-র জন্য সচল থাকা সেরা মডেলটি অটোমেটিক খুঁজে নেবে
    available = [
        m.name for m in genai.list_models()
        if 'generateContent' in m.supported_generation_methods and 'flash' in m.name.lower()
    ]
    model_name = available[0] if available else 'gemini-flash-latest'
    config = {"response_mime_type": "application/json"} if use_json else {}
    return genai.GenerativeModel(model_name, generation_config=config)

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    try:
        model = get_working_model(use_json=True)
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
    except Exception as e:
        return {
            "risk_score": 50,
            "risk_level": "CAUTION",
            "threat_category": "System Alert",
            "why_risky": [f"AI Engine Note: {str(e)}"],
            "how_to_stay_safe": ["Check your GEMINI_API_KEY in Render Environment settings.", "Do not trust unverified links."],
            "technical_indicators": "Fallback safety handler active."
        }
