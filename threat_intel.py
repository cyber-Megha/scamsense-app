import os
import requests
import base64
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def check_virustotal_url(url: str):
    if not VT_API_KEY:
        return {"status": "skipped", "message": "No VT API Key"}
    
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"https://virustotal.com{url_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0)
        }
    return {"status": "not_found_in_vt", "malicious": 0}
