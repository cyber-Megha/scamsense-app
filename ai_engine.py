import os
import json
import hashlib
import io
import re
import time
import requests
from google import genai
from google.genai import types
from PIL import Image

GEMINI_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()
GROQ_KEY = (os.getenv("GROQ_API_KEY") or "").strip()
OPENROUTER_KEY = (os.getenv("OPENROUTER_API_KEY") or "").strip()

gemini_client = genai.Client(api_key=GEMINI_KEY, http_options={"timeout": 15.0}) if GEMINI_KEY else None

RESULT_CACHE = {}
CACHE_TTL_SECONDS = 600
MAX_CACHE_ITEMS = 256

def get_tier(score: int) -> str:
    s = max(0, min(100, int(score)))
    if s <= 30:
        return "SAFE"
    if s <= 60:
        return "SUSPICIOUS"
    return "HIGH RISK"

def compute_behavioral_score(content_type: str, text_data: str, intel: dict) -> tuple[int, list[str]]:
    score = 5
    reasons = []

    data = intel or {}
    report = data if "behaviour" in data else next(iter(data.get("embedded_urls_intel") or []), {})

    gsb = report.get("google_safe_browsing") or {}
    vt = report.get("virustotal") or {}
    uh = report.get("urlhaus_threat_feed") or {}
    heur = report.get("heuristics") or {}
    beh = report.get("behaviour") or {}
    ssl_info = heur.get("ssl") or {}

    if gsb.get("is_dangerous"):
        score += 65
        reasons.append(f"Flagged by Safe Browsing ({gsb.get('threat_type')})")

    vt_mal = int(vt.get("malicious") or 0)
    vt_sus = int(vt.get("suspicious") or 0)
    if vt_mal >= 3:
        score += 55
        reasons.append(f"{vt_mal} security vendors flagged URL as malicious")
    elif vt_mal > 0:
        score += 30
        reasons.append(f"{vt_mal} security vendor(s) flagged URL as malicious")
    if vt_sus >= 2:
        score += 12
        reasons.append(f"{vt_sus} vendor(s) marked URL suspicious")

    if uh.get("listed"):
        score += 60
        reasons.append(f"Listed in active malware feed ({uh.get('threat') or 'URLhaus'})")

    if heur.get("is_ip_host"):
        score += 22
        reasons.append("Uses raw IP address instead of domain name")
    if heur.get("is_punycode"):
        score += 25
        reasons.append("Punycode (xn--) domain detected")
    if heur.get("has_at_trap"):
        score += 25
        reasons.append("Contains '@' redirect/credential trap in URL")
    if heur.get("risky_tld"):
        score += 18
        reasons.append(f"High-risk or disposable TLD on '{heur.get('domain')}'")
    if heur.get("free_or_cloud_host"):
        score += 14
        reasons.append("Hosted on free/cloud/tunneling infrastructure")
    if int(heur.get("subdomain_count") or 0) >= 3:
        score += 10
        reasons.append("Excessive subdomains in host")
    if float(heur.get("url_entropy") or 0) >= 4.5 and int(heur.get("path_length") or 0) > 25:
        score += 10
        reasons.append("High-entropy / randomized URL path")

    if heur.get("protocol") == "HTTP" and not heur.get("is_ip_host"):
        score += 10
        reasons.append("Unencrypted HTTP transport")
    elif heur.get("protocol") == "HTTPS" and heur.get("domain") and not ssl_info.get("tls_valid"):
        score += 18
        reasons.append("HTTPS connection failed TLS certificate check")

    redirs = int(beh.get("redirect_count") or 0)
    if redirs >= 3:
        score += 15
        reasons.append(f"Multiple redirects ({redirs} hops)")
    elif redirs >= 1 and beh.get("cross_domain_redirect"):
        score += 14
        reasons.append("Redirected across different domains")

    has_pwd = bool(beh.get("has_password_field"))
    has_file = bool(beh.get("has_file_upload"))
    ext_forms = beh.get("external_form_actions") or []
    susp_forms = beh.get("suspicious_form_actions") or []
    obf_hits = beh.get("script_obfuscation_hits") or []
    hidden_iframes = int(beh.get("hidden_iframes") or 0)
    urgency_hits = beh.get("urgency_keywords_found") or []

    if has_pwd and (heur.get("risky_tld") or heur.get("free_or_cloud_host") or heur.get("is_ip_host") or len(ext_forms) > 0):
        score += 28
        reasons.append("Password input on untrusted or external-action page")
    elif has_pwd:
        score += 8
        reasons.append("Password/login input field present on page")

    if has_file and (heur.get("risky_tld") or heur.get("free_or_cloud_host") or len(ext_forms) > 0):
        score += 26
        reasons.append("File upload field on untrusted or external-action page")

    if ext_forms:
        score += 20
        reasons.append("Form submits data to an external domain")
    if susp_forms and (has_pwd or has_file):
        score += 12
        reasons.append("Sensitive form lacks standard submission target")

    if obf_hits:
        score += min(24, len(obf_hits) * 8)
        reasons.append(f"Script obfuscation/evasion patterns: {', '.join(obf_hits[:3])}")

    if hidden_iframes > 0:
        score += min(20, hidden_iframes * 10)
        reasons.append(f"{hidden_iframes} hidden iframe(s) detected")

    combined_txt = f"{text_data or ''} {beh.get('text_snippet') or ''}".lower()
    if len(urgency_hits) >= 2 and (heur.get("risky_tld") or heur.get("free_or_cloud_host") or beh.get("cross_domain_redirect") or has_pwd):
        score += 16
        reasons.append("Urgent/verification language paired with suspicious link/page")
    elif any(w in combined_txt for w in ("otp", "pin", "cvv", "kyc update", "account blocked", "pay now")):
        score += 12
        reasons.append("High-pressure scam/credential keywords detected")

    dns_info = data.get("sender_dns_forensics") or {}
    if dns_info.get("status") == "checked":
        if not dns_info.get("has_mx"):
            score += 20
            reasons.append("Sender domain has no MX mail records")
        if not dns_info.get("has_spf") and not dns_info.get("has_dmarc"):
            score += 14
            reasons.append("Sender domain lacks SPF and DMARC records")

    final_score = max(0, min(100, int(score)))
    if not reasons:
        reasons.append("No major malicious indicators or risky behavioral patterns detected")
    return final_score, reasons

def parse_ai_json(raw_text: str, deterministic_score: int) -> dict:
    cleaned = (raw_text or "").strip()
    if "```" in cleaned:
        m = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if m:
            cleaned = m.group(0)
    parsed = json.loads(cleaned)

    ai_raw = parsed.get("risk_score", deterministic_score)
    try:
        ai_score = max(0, min(100, int(float(ai_raw))))
    except Exception:
        ai_score = deterministic_score

    if deterministic_score >= 65:
        final_score = max(deterministic_score, int(round(0.75 * deterministic_score + 0.25 * ai_score)))
    else:
        final_score = int(round(0.65 * deterministic_score + 0.35 * ai_score))

    final_score = max(0, min(100, final_score))
    tier = get_tier(final_score)

    steps = parsed.get("how_to_stay_safe")
    if not isinstance(steps, list) or not steps:
        steps = ["Avoid entering sensitive credentials or personal details on unverified links."]

    return {
        "risk_score": final_score,
        "classification": tier,
        "what_was_detected": str(parsed.get("what_was_detected") or "Target analyzed for behavioral and security signals.").strip(),
        "why_suspicious": str(parsed.get("why_suspicious") or "Evaluated domain structure, network behavior, and page indicators.").strip(),
        "how_affects_user": str(parsed.get("how_affects_user") or "Follow standard security precautions before interacting.").strip(),
        "evidence": str(parsed.get("evidence") or f"Computed Risk Score: {final_score}/100").strip(),
        "how_to_stay_safe": [str(s).strip() for s in steps[:3] if str(s).strip()]
    }

def run_ai_pipeline(prompt: str, deterministic_score: int, image_bytes: bytes = None):
    if image_bytes and gemini_client:
        for model_name in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
            try:
                img = Image.open(io.BytesIO(image_bytes))
                res = gemini_client.models.generate_content(
                    model=model_name,
                    contents=[prompt, img],
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.0
                    )
                )
                if res and res.text:
                    return parse_ai_json(res.text, deterministic_score)
            except Exception:
                continue
        return None

    if GROQ_KEY:
        for gm in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]:
            try:
                r = requests.post(
                    "[https://api.groq.com/openai/v1/chat/completions](https://api.groq.com/openai/v1/chat/completions)",
                    headers={
                        "Authorization": f"Bearer {GROQ_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": gm,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.0,
                        "response_format": {"type": "json_object"}
                    },
                    timeout=10
                )
                if r.status_code == 200:
                    choices = r.json().get("choices") or []
                    if choices:
                        content = (choices[0].get("message") or {}).get("content")
                        if content:
                            return parse_ai_json(content, deterministic_score)
            except Exception:
                continue

    if OPENROUTER_KEY:
        for orm in ["meta-llama/llama-3.3-70b-instruct:free", "google/gemma-3-27b-it:free"]:
            try:
                r = requests.post(
                    "[https://openrouter.ai/api/v1/chat/completions](https://openrouter.ai/api/v1/chat/completions)",
                    headers={
                        "Authorization": f"Bearer {OPENROUTER_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": orm,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.0
                    },
                    timeout=12
                )
                if r.status_code == 200:
                    choices = r.json().get("choices") or []
                    if choices:
                        content = (choices[0].get("message") or {}).get("content")
                        if content:
                            return parse_ai_json(content, deterministic_score)
            except Exception:
                continue

    if gemini_client:
        for model_name in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
            try:
                res = gemini_client.models.generate_content(
                    model=model_name,
                    contents=[prompt],
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.0
                    )
                )
                if res and res.text:
                    return parse_ai_json(res.text, deterministic_score)
            except Exception:
                continue

    return None

def fallback_forensics(content_type: str, text_data: str, intel: dict, score: int, reasons: list[str]) -> dict:
    tier = get_tier(score)
    report = intel if "behaviour" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    heur = report.get("heuristics") or {}
    beh = report.get("behaviour") or {}
    target_label = heur.get("domain") or beh.get("final_url") or (text_data[:60] if text_data else content_type)

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Analyzed {content_type} targeting '{target_label}' with title '{beh.get('title') or 'N/A'}'.",
        "why_suspicious": "; ".join(reasons) + ".",
        "how_affects_user": (
            "High likelihood of credential theft, financial fraud, or unwanted software/redirect."
            if tier == "HIGH RISK"
            else ("Some anomalies warrant caution before sharing personal or login details." if tier == "SUSPICIOUS" else "No high-risk behavioral or feed indicators observed.")
        ),
        "evidence": f"Score: {score}/100 | Final URL: {beh.get('final_url') or 'N/A'} | Signals: {'; '.join(reasons[:3])}",
        "how_to_stay_safe": [
            "Do not enter passwords, OTPs, or ID details on untrusted pages." if tier != "SAFE" else "Verify the exact domain before entering sensitive credentials."
        ]
    }

def _cleanup_cache():
    now = time.time()
    expired = [k for k, (ts, _) in RESULT_CACHE.items() if now - ts > CACHE_TTL_SECONDS]
    for k in expired:
        RESULT_CACHE.pop(k, None)
    if len(RESULT_CACHE) > MAX_CACHE_ITEMS:
        oldest_keys = sorted(RESULT_CACHE.keys(), key=lambda k: RESULT_CACHE[k][0])[: len(RESULT_CACHE) - MAX_CACHE_ITEMS]
        for k in oldest_keys:
            RESULT_CACHE.pop(k, None)

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None) -> dict:
    _cleanup_cache()
    intel = extra_intel or {}
    img_hash = hashlib.sha256(image_bytes).hexdigest() if image_bytes else "no_img"
    cache_key = hashlib.sha256(
        f"{content_type}:{text_data}:{img_hash}:{json.dumps(intel, sort_keys=True, default=str)}".encode()
    ).hexdigest()

    cached = RESULT_CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) <= CACHE_TTL_SECONDS:
        return cached[1]

    det_score, reasons = compute_behavioral_score(content_type, text_data, intel)
    compact_intel = json.dumps(intel, default=str)[:6000]

    prompt = f"""
You are a Digital Forensics & Anti-Phishing Analyst for ScamSense.
Analyze the target using ONLY the observed telemetry, page behavior, and user input.
Do not invent facts not present in the telemetry, and do not mention internal model names.

Content Type: {content_type}
User Input: {(text_data or "")[:1500]}
Computed Baseline Score: {det_score}/100
Observed Signals: {reasons}
Telemetry JSON: {compact_intel}

Strict Tiers: 0-30 = SAFE, 31-60 = SUSPICIOUS, 61-100 = HIGH RISK.
Return ONLY valid JSON:
{{
    "risk_score": <integer 0-100 consistent with observed evidence>,
    "classification": "<SAFE HIGH RISK SUSPICIOUS |>",
    "what_was_detected": "<2 clear sentences>",
    "why_suspicious": "<2-3 clear sentences based on concrete signals>",
    "how_affects_user": "<2 clear sentences on practical user impact>",
    "evidence": "<Concise behavior, domain, from or proof technical telemetry>",
    "how_to_stay_safe": ["<actionable step 1>", "<actionable step 2>"]
}}
"""

    ai_result = run_ai_pipeline(prompt, det_score, image_bytes=image_bytes)
    final_result = ai_result or fallback_forensics(content_type, text_data, intel, det_score, reasons)

    RESULT_CACHE[cache_key] = (time.time(), final_result)
    return final_result
