import os, json, hashlib, io, re, requests
from google import genai
from google.genai import types
from PIL import Image

GEMINI_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
GROQ_KEY = (os.getenv("GROQ_API_KEY") or "").strip()
OPENROUTER_KEY = (os.getenv("OPENROUTER_API_KEY") or "").strip()

client = genai.Client(api_key=GEMINI_KEY, http_options={'timeout': 18.0}) if GEMINI_KEY else None
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

def try_all_ai_engines(prompt: str, image_bytes: bytes = None):
    diag_errors = []

    # 1. Multimodal Image Analysis (Gemini)
    if image_bytes:
        if not client:
            diag_errors.append("Gemini: Key Missing")
        else:
            for m in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
                try:
                    res = client.models.generate_content(
                        model=m, contents=[prompt, Image.open(io.BytesIO(image_bytes))],
                        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0)
                    )
                    return parse_ai_json(res.text), ""
                except Exception as e:
                    diag_errors.append(f"Gemini({m}): {str(e)[:45]}")
        return None, " | ".join(diag_errors)

    # 2. Groq Cloud (Llama 3.3 70B & Llama 3.1 8B)
    if not GROQ_KEY:
        diag_errors.append("Groq: Key Missing")
    else:
        for gm in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]:
            try:
                r = requests.post(
                    "https://groq.com",
                    headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
                    json={"model": gm, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0, "response_format": {"type": "json_object"}},
                    timeout=12
                )
                if r.status_code == 200:
                    choices = r.json().get("choices", [])
                    content = choices[0].get("message", {}).get("content", "") if choices else ""
                    if content: return parse_ai_json(content), ""
                else:
                    diag_errors.append(f"Groq HTTP {r.status_code}")
            except Exception as e:
                diag_errors.append(f"Groq Err: {str(e)[:35]}")

    # 3. OpenRouter Free Pool
    if not OPENROUTER_KEY:
        diag_errors.append("OpenRouter: Key Missing")
    else:
        for orm in ["meta-llama/llama-3.3-70b-instruct:free", "google/gemma-3-27b-it:free", "qwen/qwen-2.5-72b-instruct:free"]:
            try:
                r = requests.post(
                    "https://openrouter.ai",
                    headers={"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"},
                    json={"model": orm, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0},
                    timeout=14
                )
                if r.status_code == 200:
                    choices = r.json().get("choices", [])
                    content = choices[0].get("message", {}).get("content", "") if choices else ""
                    if content: return parse_ai_json(content), ""
                else:
                    diag_errors.append(f"OR HTTP {r.status_code}")
            except Exception as e:
                diag_errors.append(f"OR Err: {str(e)[:35]}")

    # 4. Gemini Text Fallback
    if client:
        for m in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
            try:
                res = client.models.generate_content(
                    model=m, contents=[prompt],
                    config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0)
                )
                return parse_ai_json(res.text), ""
            except Exception as e:
                diag_errors.append(f"Gemini Err: {str(e)[:35]}")

    return None, " | ".join(diag_errors)

def intelligent_local_fallback(content_type: str, text_data: str, extra_intel: dict, diag_note: str):
    intel = extra_intel or {}
    rep = intel if "deep_url_forensics" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    gsb = rep.get("google_safe_browsing", {}).get("is_dangerous", False)
    vt = rep.get("virustotal", {}).get("malicious", 0)
    uh = rep.get("urlhaus_threat_feed", {}).get("listed", False)
    uf = rep.get("deep_url_forensics", {})
    page = uf.get("live_page_content", {})
    dom = uf.get("domain", "")

    if gsb or vt > 0 or uh:
        return {
            "risk_score": 96, "classification": "HIGH RISK",
            "what_was_detected": f"Confirmed malicious target identified at '{dom}'.",
            "why_suspicious": "Actively flagged across global threat intelligence feeds for phishing or malware.",
            "how_affects_user": "Direct risk of credential theft, financial loss, or device compromise.",
            "evidence": f"Host: {dom} | Global Threat Feed: Flagged ({diag_note})",
            "how_to_stay_safe": ["Close immediately and do not enter any personal or financial details."]
        }

    # Dynamic structural evaluation (Never stuck at 42%)
    score = 12
    if uf.get("has_at_symbol_trap"): score += 75
    if any(dom.endswith(e) for e in (".cfd", ".sbs", ".icu", ".it.com", ".xyz", ".top", ".tk", ".click", ".cyou", ".bond", ".supabase.co", ".workers.dev", ".pages.dev")): score += 68
    if uf.get("protocol") == "HTTP": score += 28
    if "No Valid SSL" in uf.get("ssl_status", ""): score += 16
    if page.get("asks_password_or_pin") and page.get("external_form_targets"): score += 60
    if any(w in dom for w in ("familly", "paypa1", "arnazon", "popular", "colombia", "kyc", "verify", "secure-login")): score += 55
    if any(dom == ok or dom.endswith("." + ok) for ok in ("github.com", "google.com", "youtube.com", "wikipedia.org", "microsoft.com", "apple.com", "amazon.in", "amazon.com", "hdfcbank.com", "onlinesbi.sbi", "icicibank.com", "salik.ltd", "linkedin.com")): score = 3

    score = min(98, max(3, score))
    tier = get_tier(score)
    return {
        "risk_score": score, "classification": tier,
        "what_was_detected": f"Analyzed {content_type} ({dom or 'Payload'}) — Title: '{page.get('page_title') or 'Protected/API Endpoint'}'.",
        "why_suspicious": "Evaluated domain integrity, SSL certificate, and structural risk indicators.",
        "how_affects_user": "Safe for standard browsing." if tier == "SAFE" else "Exercise caution before sharing credentials or sensitive data.",
        "evidence": f"Domain: {dom} | SSL: {uf.get('ssl_status', 'Checked')} | Diag: {diag_note}",
        "how_to_stay_safe": ["Proceed safely." if tier == "SAFE" else "Verify the source before entering any sensitive information."]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_key = hashlib.sha256(f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
    if cache_key in RESULT_CACHE: return RESULT_CACHE[cache_key]

    intel = extra_intel or {}
    prompt = f"""
    You are an elite, independent Senior Cybersecurity & Digital Forensics Investigator for 'ScamSense'.
    Evaluate the ACTUAL CONTENT, INTENT, AND CONTEXT of this {content_type} using the live telemetry below.
    Do NOT mention any AI model names, API names, or internal tools in your output.

    Telemetry: {json.dumps(intel)}

    EVALUATION PRINCIPLES:
    - Legitimate platforms, developer hubs (e.g., GitHub), official portals (e.g., Salik, banks), blogs, and benign messages -> SAFE (1-25%).
    - Deceptive domains, typosquatting ('familly'), cloud storage phishing buckets ('supabase.co/storage'), disposable TLDs ('.cfd', '.it.com'), external credential forms, or polite scam texts hiding unofficial links -> HIGH RISK (75-98%).
    - Ambiguous, unverified, or unencrypted HTTP targets -> SUSPICIOUS (35-60%).
    - Strict Tiers: 0-30="SAFE", 31-60="SUSPICIOUS", 61-100="HIGH RISK".

    Return ONLY a valid JSON object:
    {{
        "risk_score": <integer 0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<2 clear sentences>",
        "why_suspicious": "<2-3 detailed sentences explaining the exact forensic reasoning>",
        "how_affects_user": "<2 clear sentences on real-world impact>",
        "evidence": "<Specific technical proof from content, domain, SSL, or telemetry>",
        "how_to_stay_safe": ["<step 1>", "<step 2>"]
    }}
    User Input: {text_data}
    """

    ai_res, diag_note = try_all_ai_engines(prompt, image_bytes)
    if ai_res:
        RESULT_CACHE[cache_key] = ai_res
        return ai_res

    return intelligent_local_fallback(content_type, text_data, extra_intel, diag_note)
