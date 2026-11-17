import os
import requests
import base64

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def check_google_safe_browsing(url: str):
    if not GSB_API_KEY:
        return {"status": "skipped", "is_dangerous": False}
    try:
        endpoint = f"https://googleapis.com{GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-app", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(endpoint, json=payload, timeout=5)
        if res.status_code == 200:
            data = res.json()
            if "matches" in data and len(data["matches"]) > 0:
                return {
                    "is_dangerous": True,
                    "threat_type": data["matches"][0].get("threatType", "MALICIOUS"),
                    "source": "Google Safe Browsing"
                }
            return {"is_dangerous": False, "source": "Google Safe Browsing"}
        return {"status": "gsb_error", "code": res.status_code, "is_dangerous": False}
    except Exception as e:
        return {"status": "gsb_exception", "error": str(e), "is_dangerous": False}

def check_virustotal_url(url: str):
    gsb_result = check_google_safe_browsing(url)
    vt_result = {"status": "skipped", "malicious": 0}

    if VT_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": VT_API_KEY}
            api_endpoint = "https://virustotal.com" + url_id
            response = requests.get(api_endpoint, headers=headers, timeout=6)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                vt_result = {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0)
                }
        except Exception as e:
            vt_result = {"status": "vt_error", "error": str(e), "malicious": 0}

    return {
        "google_safe_browsing": gsb_result,
        "virustotal": vt_result
    }
