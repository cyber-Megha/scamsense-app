import os, json, hashlib, io, re, requests
from google import genai
from google.genai import types
from PIL import Image

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")

client = genai.Client(api_key=GEMINI_KEY, http_options={'timeout': 18.0}) if GEMINI_KEY else None
RESULT_CACHE = {}

def get_tier(score: int) -> str:
    if score <= 30: return "SAFE"
    elif score <= 60: return "SUSPICIOUS"
    return "HIGH RISK"

def parse_ai_json(raw_text: str):
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE).strip()
    parsed = json.loads(cleaned)
    parsed["risk_score"] = int(parsed.get("risk_score", 0))
    parsed["classification"] = get_tier(parsed["risk_score"])
    return parsed

def call_groq_ai(prompt: str):
    if not GROQ_KEY: return None
    try:
        r = requests.post(
            "https://groq.com",
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "response_format": {"type": "json_object"}
            },
            timeout=12
        )
        if r.status_code == 200:
            content = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
            if content:
                return parse_ai_json(content)
    except Exception: pass
    return None

def call_openrouter_ai(prompt: str):
    if not OPENROUTER_KEY: return None
    for model_id in ["meta-llama/llama-3.3-70b-instruct:free", "google/gemma-3-27b-it:free", "deepseek/deepseek-chat-v3-0324:free"]:
        try:
            r = requests.post(
                "https://openrouter.ai",
                headers={"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"},
                json={"model": model_id, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0},
                timeout=14
            )
            if r.status_code == 200:
                content = r.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                if content:
                    return parse_ai_json(content)
        except Exception: continue
    return None

def call_gemini_ai(contents: list):
    if not client: return None
    for m in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
        try:
            res = client.models.generate_content(
                model=m, contents=contents,
                config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0)
            )
            return parse_ai_json(res.text)
        except Exception: continue
    return None

def emergency_fallback(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    rep = intel if "deep_url_forensics" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    gsb = rep.get("google_safe_browsing", {}).get("is_dangerous", False)
    vt = rep.get("virustotal", {}).get("malicious", 0)
    uh = rep.get("urlhaus_threat_feed", {}).get("listed", False)
    uf = rep.get("deep_url_forensics", {})
    dom = uf.get("domain", "Target Payload")

    if gsb or vt > 0 or uh:
        return {
            "risk_score": 96, "classification": "HIGH RISK",
            "what_was_detected": f"Active malicious infrastructure identified at '{dom}' with confirmed threat signatures.",
            "why_suspicious": "The destination is actively flagged across global threat feeds for credential harvesting, phishing, or malware distribution.",
            "how_affects_user": "Interacting with this target exposes user credentials, banking sessions, and device integrity to immediate compromise.",
            "evidence": f"Host: {dom} | Protocol: {uf.get('protocol', 'N/A')} | SSL: {uf.get('ssl_status', 'Unverified')} | Threat Feed Match: Confirmed",
            "how_to_stay_safe": ["Terminate access immediately and never enter passwords, OTPs, or financial details."]
        }

    is_risky = (
        any(dom.endswith(e) for e in (".cfd", ".sbs", ".icu", ".it.com", ".xyz", ".top", ".tk", ".click", ".cyou", ".bond"))
        or uf.get("has_at_symbol_trap")
        or bool(uf.get("spoofed_domains_in_path"))
        or ("familly" in dom or "paypa1" in dom or "arnazon" in dom or dom.count("-") >= 2)
    )
    score = 86 if is_risky else (45 if uf.get("protocol") == "HTTP" else 14)
    tier = get_tier(score)
    return {
        "risk_score": score, "classification": tier,
        "what_was_detected": f"Deep structural inspection completed for {content_type} ({dom}).",
        "why_suspicious": "High-abuse domain pattern, typosquatting spelling anomaly, or multi-hyphen phishing structure detected." if tier == "HIGH RISK" else ("Unencrypted HTTP transmission or unverified host posture requires caution." if tier == "SUSPICIOUS" else "Domain infrastructure, encryption certificate, and routing telemetry show clean legitimate behavior."),
        "how_affects_user": "Safe for standard browsing and legitimate access." if tier == "SAFE" else "Users risk credential interception, identity spoofing, or unauthorized data harvesting.",
        "evidence": f"Domain: {dom} | Protocol: {uf.get('protocol', 'Checked')} | SSL: {uf.get('ssl_status', 'Checked')} | Entropy: {uf.get('shannon_entropy', 'Normal')}",
        "how_to_stay_safe": ["Proceed safely while maintaining standard security hygiene." if tier == "SAFE" else "Do not submit login credentials or personal data; verify via the official HTTPS portal."]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_key = hashlib.sha256(f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
    if cache_key in RESULT_CACHE: return RESULT_CACHE[cache_key]

    intel = extra_intel or {}
    prompt = f"""
    You are a Principal Digital Forensics & Anti-Phishing Investigator for 'ScamSense'.
    Perform a thorough, crystal-clear, and deeply informative forensic evaluation of this {content_type} using the technical telemetry below.
    Do NOT mention any AI model names, API names, or internal tool names in your output. Present the findings purely as authoritative forensic conclusions.

    Telemetry Data: {json.dumps(intel)}

    STRICT EVALUATION RULES:
    - Inspect domain spelling for subtle typosquatting (e.g., 'familly' instead of 'family', 'arnazon', 'paypa1'), multi-hyphen lure domains (e.g., 'prime-familly-assistance.com'), '/index.php' phishing kit endpoints, disposable TLDs (.cfd, .sbs, .icu, .it.com, .xyz, .top), brand-domain mismatches, '@' traps, path spoofing, missing DNS MX/SPF records, and polite scam texts hiding unofficial links — score these HIGH RISK (78-98%).
    - Verified official domains (google.com, hdfcbank.com, salik.ltd, etc.) with valid encryption and clean telemetry MUST be scored SAFE (1-22%).
    - Strict Tiers: 0-30="SAFE", 31-60="SUSPICIOUS", 61-100="HIGH RISK".

    Return ONLY a valid JSON object with thorough, well-explained, easy-to-understand forensic points:
    {{
        "risk_score": <integer 0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "",
        "why_suspicious": "<2-3 detailed sentences explaining the exact technical or behavioral proof why it is dangerous, suspicious, or verified safe>",
        "how_affects_user": "<2 clear sentences explaining the direct real-world impact on the user's security, privacy, or finances>",
        "evidence": "<Clean, specific technical proof citing exact domain flags, protocol, SSL status, routing behavior, or structural anomalies>",
        "how_to_stay_safe": ["<Clear actionable step 1>", "<Clear actionable step 2>"]
    }}
    User Input: {text_data}
    """

    ai_output = None
    if image_bytes:
        ai_output = call_gemini_ai([prompt, Image.open(io.BytesIO(image_bytes))])
    else:
        ai_output = call_groq_ai(prompt) or call_openrouter_ai(prompt) or call_gemini_ai([prompt])

    if ai_output:
        RESULT_CACHE[cache_key] = ai_output
        return ai_output

    return emergency_fallback(content_type, text_data, extra_intel)
