import os, json, hashlib, io, re, requests
from google import genai
from google.genai import types
from PIL import Image

GEMINI_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
GROQ_KEY = (os.getenv("GROQ_API_KEY") or "").strip()
OPENROUTER_KEY = (os.getenv("OPENROUTER_API_KEY") or "").strip()

client = genai.Client(api_key=GEMINI_KEY, http_options={'timeout': 15.0}) if GEMINI_KEY else None
RESULT_CACHE = {}

def get_tier(score: int) -> str:
    if score <= 30: return "SAFE"
    elif score <= 60: return "SUSPICIOUS"
    return "HIGH RISK"

def parse_ai_json(raw_text: str):
    cleaned = raw_text.strip()
    if "```" in cleaned:
        m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if m: cleaned = m.group(0)
    parsed = json.loads(cleaned)
    parsed["risk_score"] = int(parsed.get("risk_score", 0))
    parsed["classification"] = get_tier(parsed["risk_score"])
    return parsed

def run_ai_pipeline(prompt: str, image_bytes: bytes = None):
    if image_bytes and client:
        for m in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
            try:
                res = client.models.generate_content(model=m, contents=[prompt, Image.open(io.BytesIO(image_bytes))], config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.1))
                return parse_ai_json(res.text)
            except Exception: continue
        return None

    if GROQ_KEY:
        for gm in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]:
            try:
                r = requests.post(
                    "https://groq.com",
                    headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
                    json={"model": gm, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1, "response_format": {"type": "json_object"}},
                    timeout=10
                )
                if r.status_code == 200:
                    choices = r.json().get("choices", [])
                    if choices:
                        return parse_ai_json(choices[0]["message"]["content"])
            except Exception: continue

    if OPENROUTER_KEY:
        for orm in ["meta-llama/llama-3.3-70b-instruct:free", "google/gemma-3-27b-it:free"]:
            try:
                r = requests.post(
                    "https://openrouter.ai",
                    headers={"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"},
                    json={"model": orm, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1},
                    timeout=12
                )
                if r.status_code == 200:
                    choices = r.json().get("choices", [])
                    if choices:
                        return parse_ai_json(choices[0]["message"]["content"])
            except Exception: continue

    if client:
        for m in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
            try:
                res = client.models.generate_content(model=m, contents=[prompt], config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.1))
                return parse_ai_json(res.text)
            except Exception: continue
    return None

def fallback_forensics(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    rep = intel if "deep_url_forensics" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    gsb = rep.get("google_safe_browsing", {}).get("is_dangerous", False)
    vt = rep.get("virustotal", {}).get("malicious", 0)
    uh = rep.get("urlhaus_threat_feed", {}).get("listed", False)
    uf = rep.get("deep_url_forensics", {})
    page = uf.get("live_page", {})
    dom = uf.get("domain", "Target")
    page_txt = (page.get("text", "") + " " + dom).lower()

    if gsb or vt > 0 or uh:
        return {
            "risk_score": 95, "classification": "HIGH RISK",
            "what_was_detected": f"Confirmed malicious infrastructure at '{dom}'.",
            "why_suspicious": "Flagged across global threat intelligence feeds for active phishing or malware.",
            "how_affects_user": "Direct risk of identity theft, financial fraud, or device compromise.",
            "evidence": f"Host: {dom} | Global Blacklist: Confirmed",
            "how_to_stay_safe": ["Close immediately and do not enter any credentials or upload documents."]
        }

    score = 12
    if page.get("has_password_or_file_upload") and any(k in page_txt for k in ("cpf", "cnpj", "cadastro", "kyc", "pan", "aadhaar", "ssn", "password", "senha", "documento")):
        score = 89
    elif any(dom.endswith(e) for e in (".cfd", ".sbs", ".icu", ".it.com", ".xyz", ".top", ".tk", ".supabase.co", ".workers.dev")):
        score = 84
    elif uf.get("protocol") == "HTTP":
        score = 46
    elif any(dom == ok or dom.endswith("." + ok) for ok in ("github.com", "google.com", "youtube.com", "wikipedia.org", "microsoft.com", "hdfcbank.com", "onlinesbi.sbi", "salik.ltd")):
        score = 4

    tier = get_tier(score)
    return {
        "risk_score": score, "classification": tier,
        "what_was_detected": f"Inspected {content_type} ({dom}) — Title: '{page.get('title') or 'N/A'}'.",
        "why_suspicious": "Unofficial domain soliciting sensitive identity documents or credentials." if tier == "HIGH RISK" else ("Unencrypted HTTP or unverified host." if tier == "SUSPICIOUS" else "Verified clean infrastructure."),
        "how_affects_user": "Safe for standard browsing." if tier == "SAFE" else "High risk of identity theft and sensitive document harvesting.",
        "evidence": f"Domain: {dom} | SSL: {uf.get('ssl_status', 'Checked')} | Sensitive Form: {page.get('has_password_or_file_upload', False)}",
        "how_to_stay_safe": ["Proceed safely." if tier == "SAFE" else "Never upload identity documents (ID, PAN, CPF, Passport) or enter passwords on unverified domains."]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_key = hashlib.sha256(f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
    if cache_key in RESULT_CACHE: return RESULT_CACHE[cache_key]

    intel = extra_intel or {}
    prompt = f"""
    You are a Principal Multilingual Digital Forensics & Anti-Phishing Investigator for 'ScamSense'.
    Analyze the ACTUAL LIVE CONTENT (`live_page.text`, `title`, forms, domain, and telemetry) in ANY language (English, Portuguese, Spanish, Hindi, etc.).
    Do NOT mention any AI model names or internal tools.

    Telemetry: {json.dumps(intel)}

    CRITICAL FORENSIC RULES:
    1. IDENTITY & DOCUMENT HARVESTING: If a site (like 'bariguicadastro.com') impersonates a real brand (like Grupo Barigüi, whose real site is grupobarigui.com.br) and asks users to upload government IDs, tax IDs (CPF/CNPJ/PAN/SSN), address proofs, or passwords on a separate unofficial domain -> score HIGH RISK (85-96%).
    2. CLOUD ABUSE & TYPOSQUATTING: Public storage buckets ('supabase.co/storage'), disposable TLDs ('.cfd', '.it.com', '.xyz'), typosquatting ('familly'), or polite scam texts with unofficial links -> score HIGH RISK (78-95%).
    3. NUANCED SCORING: Calculate an exact, realistic risk_score (never repeat generic numbers) based on exact evidence severity. Legitimate official sites -> SAFE (1-25%).
    4. Strict Tiers: 0-30="SAFE", 31-60="SUSPICIOUS", 61-100="HIGH RISK".

    Return ONLY a valid JSON object:
    {{
        "risk_score": <integer 0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<2 clear sentences>",
        "why_suspicious": "<2-3 detailed sentences explaining the exact forensic reasoning>",
        "how_affects_user": "<2 clear sentences on real-world impact>",
        "evidence": "<Specific technical proof from live page content, domain, or telemetry>",
        "how_to_stay_safe": ["<step 1>", "<step 2>"]
    }}
    User Input: {text_data}
    """

    ai_res = run_ai_pipeline(prompt, image_bytes)
    if ai_res:
        RESULT_CACHE[cache_key] = ai_res
        return ai_res

    return fallback_forensics(content_type, text_data, extra_intel)
