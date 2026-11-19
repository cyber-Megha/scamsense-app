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
    score = 8
    reasons = []

    data = intel or {}
    report = data if "behaviour" in data else next(iter(data.get("embedded_urls_intel") or []), {})

    gsb = report.get("google_safe_browsing") or {}
    vt = report.get("virustotal") or {}
    uh = report.get("urlhaus_threat_feed") or {}
    heur = report.get("heuristics") or {}
    beh = report.get("behaviour") or {}
    ssl_info = heur.get("ssl") or {}
    oauth_info = heur.get("oauth_analysis") or {}
    path_ctx = heur.get("path_context") or {}

    # 1. Threat intelligence feeds
    if gsb.get("is_dangerous"):
        score += 70
        reasons.append(f"Flagged by Safe Browsing ({gsb.get('threat_type')})")

    vt_mal = int(vt.get("malicious") or 0)
    vt_sus = int(vt.get("suspicious") or 0)
    if vt_mal >= 3:
        score += 60
        reasons.append(f"{vt_mal} security vendors flagged URL as malicious")
    elif vt_mal > 0:
        score += 35
        reasons.append(f"{vt_mal} security vendor(s) flagged URL as malicious")
    if vt_sus >= 2:
        score += 15
        reasons.append(f"{vt_sus} vendor(s) marked URL suspicious")

    if uh.get("listed"):
        score += 65
        reasons.append(f"Listed in active malware feed ({uh.get('threat') or 'URLhaus'})")

    # 2. OAuth Consent Phishing & Open Redirect / Smuggling
    if oauth_info.get("external_redirect_params"):
        score += 48
        reasons.append(
            f"OAuth/login parameter redirects user to external domain: {oauth_info['external_redirect_params'][0]}"
        )
    if oauth_info.get("suspicious_param_values"):
        score += 50
        reasons.append("Dangerous scheme (javascript:/data:/vbscript:) embedded inside URL parameters")
    if oauth_info.get("risky_oauth_scopes"):
        score += 32
        reasons.append(f"High-privilege OAuth scopes requested: {', '.join(oauth_info['risky_oauth_scopes'])}")
    if oauth_info.get("is_oauth_or_auth_flow") and oauth_info.get("has_truncated_ellipsis"):
        score += 42
        reasons.append(
            "Truncated OAuth authorization URL hides redirect_uri and client_id parameters (OAuth consent phishing vector)"
        )
    elif oauth_info.get("is_oauth_or_auth_flow"):
        score += 30
        reasons.append(
            "OAuth authentication flow detected—verify client_id, redirect_uri, and consent permissions before approving"
        )

    # 3. Legitimate Platform / UGC / Resume / Cloud Abuse & Lure Paths
    if path_ctx.get("lure_on_ugc_or_profile_path"):
        score += 45
        reasons.append(
            f"Credential/login lure ({', '.join(path_ctx.get('login_or_lure_tokens') or [])}) hidden inside a resume/profile/UGC path"
        )
    if path_ctx.get("lure_on_cloud_or_tunnel_host"):
        score += 42
        reasons.append(
            f"Login/verification lure ({', '.join(path_ctx.get('login_or_lure_tokens') or [])}) hosted on cloud/tunneling infrastructure"
        )
    elif path_ctx.get("login_or_lure_tokens") and not heur.get("is_ip_host"):
        score += 18
        reasons.append(
            f"Authentication/account lure keyword in URL path/query: {', '.join(path_ctx.get('login_or_lure_tokens')[:4])}"
        )

    if path_ctx.get("brand_mismatch_tokens"):
        score += 26
        reasons.append(
            f"Brand/service impersonation token ({', '.join(path_ctx.get('brand_mismatch_tokens') or [])}) outside official root domain"
        )

    if path_ctx.get("has_double_dash_trick"):
        score += 14
        reasons.append("Consecutive hyphen/dash deception pattern detected in URL")

    if int(path_ctx.get("encoded_percent_count") or 0) >= 4:
        score += 14
        reasons.append("Heavy percent-encoding used to obscure URL path or parameters")

    # 4. Domain, TLS & Structural Heuristics
    if heur.get("is_ip_host"):
        score += 28
        reasons.append("Uses raw IP address instead of domain name")
    if heur.get("is_punycode"):
        score += 32
        reasons.append("Punycode (xn--) homoglyph/lookalike domain detected")
    if heur.get("has_at_trap"):
        score += 30
        reasons.append("Contains '@' credential/redirect trap in URL")
    if heur.get("risky_tld"):
        score += 22
        reasons.append(f"High-risk or disposable TLD on '{heur.get('domain')}'")
    if heur.get("free_or_cloud_host"):
        score += 18
        reasons.append("Hosted on free/cloud/tunneling infrastructure")
    if int(heur.get("subdomain_count") or 0) >= 3:
        score += 12
        reasons.append("Excessive subdomains used to mask target domain")
    if float(heur.get("url_entropy") or 0) >= 4.5 and int(heur.get("path_length") or 0) > 25:
        score += 12
        reasons.append("High-entropy / randomized URL path")

    if heur.get("protocol") == "HTTP" and not heur.get("is_ip_host"):
        score += 14
        reasons.append("Unencrypted HTTP transport")
    elif heur.get("protocol") == "HTTPS" and heur.get("domain") and not ssl_info.get("tls_valid"):
        score += 22
        reasons.append("HTTPS connection failed TLS certificate verification")

    # 5. Live Page & Script Forensics
    redirs = int(beh.get("redirect_count") or 0)
    if redirs >= 3:
        score += 18
        reasons.append(f"Multiple HTTP redirects ({redirs} hops)")
    elif redirs >= 1 and beh.get("cross_domain_redirect"):
        score += 18
        reasons.append("Cross-domain redirect chain detected")

    has_pwd = bool(beh.get("has_password_field"))
    has_file = bool(beh.get("has_file_upload"))
    ext_forms = beh.get("external_form_actions") or []
    susp_forms = beh.get("suspicious_form_actions") or []
    obf_hits = beh.get("script_obfuscation_hits") or []
    hidden_iframes = int(beh.get("hidden_iframes") or 0)
    urgency_hits = beh.get("urgency_keywords_found") or []

    if has_pwd and (
        heur.get("risky_tld") or heur.get("free_or_cloud_host") or heur.get("is_ip_host")
        or len(ext_forms) > 0 or path_ctx.get("login_or_lure_tokens")
    ):
        score += 34
        reasons.append("Password/credential input on untrusted, deceptive, or external-action page")
    elif has_pwd:
        score += 10
        reasons.append("Password/login input field present on page")

    if has_file and (heur.get("risky_tld") or heur.get("free_or_cloud_host") or len(ext_forms) > 0):
        score += 28
        reasons.append("File upload field on untrusted or external-action page")

    if ext_forms:
        score += 24
        reasons.append("Form submits data to an external domain")
    if susp_forms and (has_pwd or has_file):
        score += 14
        reasons.append("Sensitive form lacks standard submission target")

    if obf_hits:
        score += min(28, len(obf_hits) * 9)
        reasons.append(f"Script obfuscation/evasion/redirect patterns: {', '.join(obf_hits[:3])}")

    if hidden_iframes > 0:
        score += min(24, hidden_iframes * 12)
        reasons.append(f"{hidden_iframes} hidden iframe(s) detected")

    # 6. Social Engineering & DNS Forensics
    combined_txt = f"{text_data or ''} {beh.get('text_snippet') or ''}".lower()
    if len(urgency_hits) >= 2 and (
        heur.get("risky_tld") or heur.get("free_or_cloud_host") or beh.get("cross_domain_redirect")
        or has_pwd or path_ctx.get("login_or_lure_tokens")
    ):
        score += 20
        reasons.append("Urgent/verification language paired with suspicious link or page behavior")
    elif any(w in combined_txt for w in ("otp", "pin", "cvv", "kyc update", "account blocked", "pay now")):
        score += 14
        reasons.append("High-pressure scam/credential keywords detected")

    dns_info = data.get("sender_dns_forensics") or {}
    if dns_info.get("status") == "checked":
        if not dns_info.get("has_mx"):
            score += 22
            reasons.append("Sender domain has no MX mail records")
        if not dns_info.get("has_spf") and not dns_info.get("has_dmarc"):
            score += 16
            reasons.append("Sender domain lacks SPF and DMARC records")

    final_score = max(0, min(100, int(score)))
    if not reasons:
        reasons.append("No high-risk structural, behavioral, or deception indicators observed")
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

    if deterministic_score >= 60:
        final_score = max(deterministic_score, int(round(0.75 * deterministic_score + 0.25 * ai_score)))
    else:
        final_score = int(round(0.65 * deterministic_score + 0.35 * ai_score))

    final_score = max(0, min(100, final_score))
    tier = get_tier(final_score)

    steps = parsed.get("how_to_stay_safe")
    if not isinstance(steps, list) or not steps:
        steps = [
            "Do not enter passwords, OTPs, or approve permissions on unverified links.",
            "Navigate directly to the official platform in a fresh browser session."
        ]

    return {
        "risk_score": final_score,
        "classification": tier,
        "what_was_detected": str(parsed.get("what_was_detected") or "Target analyzed for structural, behavioral, and deception signals.").strip(),
        "why_suspicious": str(parsed.get("why_suspicious") or "Evaluated host reputation, path deception, OAuth/redirect parameters, and page behavior.").strip(),
        "how_affects_user": str(parsed.get("how_affects_user") or "Assess credential and permission risk before interacting with the target.").strip(),
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
    ssl_info = heur.get("ssl") or {}
    oauth_info = heur.get("oauth_analysis") or {}
    path_ctx = heur.get("path_context") or {}

    domain = heur.get("domain") or "Target Payload"
    proto = heur.get("protocol") or "N/A"
    final_url = beh.get("final_url") or text_data or "N/A"
    title = beh.get("title") or "Dynamic/JS-rendered or protected page"
    redirects = int(beh.get("redirect_count") or 0)
    tls_ok = ssl_info.get("tls_valid")

    if oauth_info.get("is_oauth_or_auth_flow"):
        what_detected = (
            f"Detected an OAuth/Authentication flow on '{domain}' ({proto}) with {redirects} HTTP redirect(s) and page state '{title}'. "
            f"OAuth telemetry inspected query parameters, redirect targets, and truncation state."
        )
        why_text = (
            f"{'; '.join(reasons)}. Attackers abuse genuine identity providers by crafting OAuth consent URLs with attacker-controlled "
            f"'client_id', 'redirect_uri', or high-privilege scopes so the victim trusts the domain while authorizing a malicious app."
        )
        impact_text = (
            "Approving an untrusted OAuth prompt can allow an attacker's application to access emails, files, or account tokens—"
            "or bounce you to a credential-harvesting page—even when the starting domain looks legitimate."
        )
        evidence_text = (
            f"Score: {score}/100 | Host: {domain} | OAuth Flow: True | "
            f"External Redirects: {oauth_info.get('external_redirect_params') or 'None/Hidden'} | "
            f"Truncated: {oauth_info.get('has_truncated_ellipsis')}"
        )
        safe_steps = [
            "Do not grant OAuth consent or enter credentials on links from untrusted sources—verify the exact app publisher and 'redirect_uri' first.",
            "Open the official service directly in a clean browser tab and revoke suspicious third-party app permissions in your account settings."
        ]
    elif path_ctx.get("lure_on_ugc_or_profile_path") or path_ctx.get("login_or_lure_tokens"):
        what_detected = (
            f"Inspected {content_type} targeting '{domain}' ({proto}) with page title '{title}' and {redirects} redirect(s). "
            f"Path and query analysis checked for credential/login lure keywords and platform hosting abuse."
        )
        why_text = (
            f"{'; '.join(reasons)}. Threat actors frequently embed login, webmail, or account-verification lure paths inside legitimate "
            f"resume, profile, blog, or cloud pages—and serve dynamic or geo/user-filtered lures that evade static checks."
        )
        impact_text = (
            "Entering email, banking, or account credentials on a deceptive or user-controlled path risks credential theft, "
            "phishing redirection, or account takeover even when the root domain itself is well known."
        )
        evidence_text = (
            f"Score: {score}/100 | Domain: {domain} | Lure Tokens: {path_ctx.get('login_or_lure_tokens') or []} | "
            f"UGC/Profile Host: {path_ctx.get('is_ugc_or_profile_host')} | Final URL: {final_url}"
        )
        safe_steps = [
            "Never enter email passwords, webmail logins, or personal data on resume, profile, or shared links—go directly to the official provider's domain.",
            "If you received this link via email, chat, or a threat feed, treat it as high-risk and report it rather than interacting with any form or button."
        ]
    elif tier == "SAFE":
        what_detected = (
            f"Inspected {content_type} targeting '{domain}' ({proto}) with {redirects} redirect(s); "
            f"page title reported as '{title}'."
        )
        why_text = (
            f"No high-risk domain anomalies, malicious threat-feed hits, deceptive login/OAuth paths, obfuscated scripts, or external "
            f"credential-harvesting forms were detected. "
            f"{'TLS certificate validation succeeded over HTTPS, confirming encrypted transport.' if proto == 'HTTPS' and tls_ok else 'Observed structural and network signals align with normal traffic.'}"
        )
        impact_text = (
            "Low immediate threat based on structural, behavioral, and threat-intelligence checks. "
            "Still verify context and domain spelling before entering sensitive passwords or financial information."
        )
        evidence_text = (
            f"Domain: {domain} | Protocol: {proto} | TLS Valid: {tls_ok} | "
            f"Redirects: {redirects} | Risk Score: {score}/100"
        )
        safe_steps = [
            "Confirm the exact domain spelling in your browser address bar before submitting sensitive credentials.",
            "Avoid opening unexpected links from unsolicited messages even if the domain appears familiar."
        ]
    else:
        what_detected = f"Analyzed {content_type} targeting '{domain}' ({proto}) with page state '{title}' and {redirects} redirect(s)."
        why_text = "; ".join(reasons) + "."
        impact_text = (
            "High likelihood of credential theft, token hijacking, financial fraud, or deceptive redirection."
            if tier == "HIGH RISK"
            else "Anomalous structural, path, or behavioral indicators were detected; proceeding without verification risks account compromise."
        )
        evidence_text = f"Score: {score}/100 | Final URL: {final_url} | Key Signals: {'; '.join(reasons[:3])}"
        safe_steps = [
            "Do not enter passwords, OTPs, payment details, or approve permissions on this link.",
            "Navigate manually to the official website and verify through trusted channels."
        ]

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": what_detected,
        "why_suspicious": why_text,
        "how_affects_user": impact_text,
        "evidence": evidence_text,
        "how_to_stay_safe": safe_steps
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
You are a Principal Digital Forensics & Anti-Phishing Analyst for ScamSense.
Conduct a thorough, zero-trust forensic analysis using ONLY the observed telemetry, URL path/query/OAuth inspection, page behavior, and user input.
Expose subtle attacker tricks: abuse of legitimate domains/UGC/resume/cloud paths, login/mail lures in paths, OAuth consent phishing (redirect_uri, client_id, scopes, truncation), brand impersonation, redirects, obfuscation, and dynamic/evasive pages.
Do not invent facts not present in the telemetry, and do not mention internal AI model names.

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
    "what_was_detected": "<2-3 clear sentences detailing the target, host, path/OAuth/page behavior, and scan state>",
    "why_suspicious": "<3-4 clear sentences explaining concrete signals and attacker deception techniques>",
    "how_affects_user": "<2-3 clear sentences on real-world impact to credentials, accounts, or data>",
    "evidence": "<Concise domain, from or params, path/OAuth proof redirects, technical telemetry>",
    "how_to_stay_safe": ["<actionable step 1>", "<actionable step 2>"]
}}
"""

    ai_result = run_ai_pipeline(prompt, det_score, image_bytes=image_bytes)
    final_result = ai_result or fallback_forensics(content_type, text_data, intel, det_score, reasons)

    RESULT_CACHE[cache_key] = (time.time(), final_result)
    return final_result
