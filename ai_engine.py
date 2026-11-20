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

gemini_client = genai.Client(api_key=GEMINI_KEY, http_options={"timeout": 10.0}) if GEMINI_KEY else None

RESULT_CACHE = {}
CACHE_TTL_SECONDS = 300
MAX_CACHE_ITEMS = 256


def get_tier(score: int) -> str:
    s = max(0, min(100, int(score)))
    if s <= 30:
        return "SAFE"
    if s <= 60:
        return "SUSPICIOUS"
    return "HIGH RISK"


def _extract_email_from_text(txt: str) -> str:
    m = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", (txt or "").strip())
    return m.group(0).lower() if m else ""


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
    wrap_info = heur.get("wrapper_cloak") or {}
    oauth_info = heur.get("oauth_analysis") or {}
    path_ctx = heur.get("path_context") or {}
    dom_age = heur.get("domain_age") or {}

    if gsb.get("is_dangerous"):
        score += 75
        reasons.append(f"Flagged by Safe Browsing ({gsb.get('threat_type')})")

    vt_mal = int(vt.get("malicious") or 0)
    vt_sus = int(vt.get("suspicious") or 0)
    if vt_mal >= 2:
        score += 65
        reasons.append(f"{vt_mal} security vendors flagged URL as malicious")
    elif vt_mal == 1:
        score += 42
        reasons.append("1 security vendor flagged URL as malicious")
    if vt_sus >= 1:
        score += 20
        reasons.append(f"{vt_sus} security vendor(s) marked URL suspicious")

    if uh.get("listed"):
        score += 70
        reasons.append(f"Listed in active malware feed ({uh.get('threat') or 'URLhaus'})")

    apk_cheat_hits = path_ctx.get("apk_or_cheat_lure_tokens") or []
    if len(apk_cheat_hits) >= 2:
        score += 42
        reasons.append(
            f"Unofficial APK/panel/cheat/mod lure terms detected ({', '.join(apk_cheat_hits[:4])})—high risk of trojanized packages or account/device bans"
        )
    elif len(apk_cheat_hits) == 1:
        score += 28
        reasons.append(
            f"APK/mod/cheat/gaming lure keyword detected ({apk_cheat_hits[0]})—verify package authenticity and avoid untrusted installers"
        )

    gib_subs = heur.get("gibberish_subdomains") or []
    gib_paths = path_ctx.get("gibberish_path_segments") or []
    if gib_subs:
        score += 36
        reasons.append(
            f"Randomized/gibberish subdomain label(s) ({', '.join(gib_subs)}) on '{heur.get('domain')}' regardless of TLD"
        )
    if gib_paths:
        score += 22
        reasons.append(
            f"Randomized/gibberish URL path segment(s) detected ({', '.join(gib_paths[:2])})"
        )

    if wrap_info.get("external_wrapped_hosts"):
        score += 54
        reasons.append(
            f"Outer link wraps external target host(s): {', '.join(wrap_info['external_wrapped_hosts'])}"
        )
    elif wrap_info.get("has_nested_wrapped_url"):
        score += 36
        reasons.append("Nested URL or encoded destination embedded inside link wrapper")

    if wrap_info.get("decoded_base64_lures"):
        score += 48
        reasons.append("Decoded Base64 parameter reveals embedded URL or login/verification lure")

    if wrap_info.get("double_encoded_url"):
        score += 32
        reasons.append("Double percent-encoding used to disguise underlying target or parameters")

    if wrap_info.get("has_fragment_payload"):
        score += 22
        reasons.append("Long URL fragment (#) payload—often used for client-side routing or credential tricks")

    if dom_age.get("checked") and dom_age.get("is_newly_registered"):
        age_d = dom_age.get("age_days")
        if age_d is not None and age_d <= 30:
            score += 45
            reasons.append(f"Very fresh domain registration ({age_d} days old, created {dom_age.get('created_date')})")
        else:
            score += 28
            reasons.append(f"Recently registered domain ({age_d} days old, created {dom_age.get('created_date')})")

    if oauth_info.get("external_redirect_params"):
        score += 55
        reasons.append(
            f"Parameter redirects to external domain: {oauth_info['external_redirect_params'][0]}"
        )
    if oauth_info.get("suspicious_param_values"):
        score += 58
        reasons.append("Executable/script scheme (javascript:/data:/vbscript:) inside URL query")
    if oauth_info.get("risky_oauth_scopes"):
        score += 38
        reasons.append(f"High-privilege OAuth scopes requested: {', '.join(oauth_info['risky_oauth_scopes'])}")
    if oauth_info.get("is_oauth_or_auth_flow") and oauth_info.get("has_truncated_ellipsis"):
        score += 55
        reasons.append("Truncated OAuth flow URL hiding redirect_uri or client_id parameters")
    elif oauth_info.get("is_oauth_or_auth_flow"):
        score += 36
        reasons.append("OAuth/authentication flow detected—verify client_id, redirect_uri, and consent permissions")

    smuggle_params = oauth_info.get("smuggle_or_affiliate_params") or []
    if smuggle_params and oauth_info.get("has_base64_query_blob"):
        score += 44
        reasons.append(f"Base64-encoded payload paired with tracking/redirect params ({', '.join(smuggle_params[:3])})")
    elif smuggle_params:
        score += 24
        reasons.append(f"Tracking/redirect/session parameters present ({', '.join(smuggle_params[:3])})")
    elif oauth_info.get("has_base64_query_blob"):
        score += 22
        reasons.append("Encoded Base64 string detected in URL query")

    if path_ctx.get("lure_on_ugc_or_profile_path"):
        score += 56
        reasons.append(
            f"Login/credential lure ({', '.join(path_ctx.get('login_or_lure_tokens') or [])}) inside profile/resume/UGC path"
        )
    if path_ctx.get("lure_on_tunnel_or_cloud_host"):
        score += 55
        reasons.append(
            f"Login/verification lure ({', '.join(path_ctx.get('login_or_lure_tokens') or [])}) on tunneling/cloud host"
        )
    elif path_ctx.get("login_or_lure_tokens") and not heur.get("is_ip_host"):
        score += 28
        reasons.append(
            f"Credential/account lure keyword in URL path/query: {', '.join(path_ctx.get('login_or_lure_tokens')[:4])}"
        )

    if path_ctx.get("has_short_code"):
        score += 32
        reasons.append(
            f"URL shortener link ('{heur.get('domain')}') masks the final destination behind a short path"
        )
    elif path_ctx.get("is_url_shortener"):
        score += 24
        reasons.append(f"Hosted on URL shortener domain ('{heur.get('domain')}')")

    if path_ctx.get("has_shared_user_path"):
        score += 30
        reasons.append(
            f"User-created/shared path on '{heur.get('domain')}'—legitimate platforms are often used as a shell to host phishing or scam lures"
        )
    elif path_ctx.get("is_scheduling_or_form_host"):
        score += 26
        reasons.append(
            f"Hosted on scheduling/meeting/form platform ('{heur.get('domain')}')—frequently abused for fake interview/meeting/credential lures"
        )

    if path_ctx.get("brand_mismatch_tokens"):
        score += 36
        reasons.append(
            f"Brand/service keyword ({', '.join(path_ctx.get('brand_mismatch_tokens') or [])}) outside official root domain"
        )

    if path_ctx.get("has_double_dash_trick"):
        score += 18
        reasons.append("Consecutive hyphen/dash obfuscation pattern in URL")

    if int(path_ctx.get("encoded_percent_count") or 0) >= 3:
        score += 18
        reasons.append("Heavy percent-encoding obscuring URL path or query")

    if heur.get("is_ip_host"):
        score += 38
        reasons.append("Direct IP address host instead of registered domain")
    if heur.get("is_punycode"):
        score += 40
        reasons.append("Punycode (xn--) homoglyph/lookalike domain")
    if heur.get("has_at_trap"):
        score += 36
        reasons.append("'@' trap in URL authority/redirect syntax")
    if heur.get("risky_tld"):
        score += 30
        reasons.append(f"High-risk or disposable TLD on '{heur.get('domain')}'")
    if heur.get("tunnel_or_cloud_host"):
        score += 32
        reasons.append(f"Hosted on tunneling/free/cloud platform ('{heur.get('domain')}') often used for instant phishing")
    if int(heur.get("subdomain_count") or 0) >= 3:
        score += 18
        reasons.append("Multi-level subdomain structure potentially masking target")
    if float(heur.get("url_entropy") or 0) >= 4.4 and int(heur.get("path_length") or 0) > 20:
        score += 16
        reasons.append("High-entropy / randomized path string")

    if heur.get("protocol") == "HTTP" and not heur.get("is_ip_host"):
        score += 20
        reasons.append("Unencrypted HTTP transport")
    elif heur.get("protocol") == "HTTPS" and heur.get("domain") and not ssl_info.get("tls_valid"):
        score += 28
        reasons.append("TLS certificate verification failed")

    if beh.get("sparse_or_js_page"):
        score += 26
        reasons.append(
            "Page relies on dynamic scripts or returns minimal static content—hidden lures or post-render traps may not appear in static fetch"
        )

    if beh.get("meta_refresh_detected"):
        score += 26
        reasons.append("Automatic HTML meta-refresh redirect detected on page")

    if gib_subs and (
        beh.get("bot_blocked_or_evasive")
        or dom_age.get("is_newly_registered")
        or int(beh.get("redirect_count") or 0) >= 1
    ):
        score += 22
        reasons.append("Randomized subdomain combined with anti-bot challenge, redirect, or fresh domain signal")

    if beh.get("bot_blocked_or_evasive") and (
        path_ctx.get("has_short_code")
        or path_ctx.get("has_shared_user_path")
        or path_ctx.get("is_scheduling_or_form_host")
    ):
        score += 24
        reasons.append(
            "Anti-bot or Cloudflare challenge blocked inspection on a short/shared link—actual destination could not be verified"
        )

    if beh.get("bot_blocked_or_evasive") and (
        smuggle_params
        or wrap_info.get("has_nested_wrapped_url")
        or path_ctx.get("login_or_lure_tokens")
        or oauth_info.get("is_oauth_or_auth_flow")
        or heur.get("tunnel_or_cloud_host")
        or dom_age.get("is_newly_registered")
    ):
        score += 30
        reasons.append("Scanner blocked or served anti-bot/JS challenge on a wrapped, parameterized, or high-signal link")

    redirs = int(beh.get("redirect_count") or 0)
    if redirs >= 3:
        score += 22
        reasons.append(f"Multiple HTTP redirects ({redirs} hops)")
    elif redirs >= 1 and beh.get("cross_domain_redirect"):
        score += 26
        reasons.append("Cross-domain redirect chain observed")

    has_pwd = bool(beh.get("has_password_field"))
    has_cred_inputs = bool(beh.get("has_credential_inputs"))
    has_file = bool(beh.get("has_file_upload"))
    ext_forms = beh.get("external_form_actions") or []
    susp_forms = beh.get("suspicious_form_actions") or []
    obf_hits = beh.get("script_obfuscation_hits") or []
    hidden_iframes = int(beh.get("hidden_iframes") or 0)
    urgency_hits = beh.get("urgency_keywords_found") or []

    if has_pwd:
        score += 28
        reasons.append("Password input field detected on page")
        if (
            heur.get("risky_tld")
            or heur.get("tunnel_or_cloud_host")
            or heur.get("is_ip_host")
            or len(ext_forms) > 0
            or path_ctx.get("login_or_lure_tokens")
            or path_ctx.get("brand_mismatch_tokens")
            or dom_age.get("is_newly_registered")
            or gib_subs
        ):
            score += 28
            reasons.append("Password field paired with suspicious subdomain/host/domain age, deceptive path, or external form")
    elif has_cred_inputs and (
        heur.get("tunnel_or_cloud_host")
        or heur.get("risky_tld")
        or path_ctx.get("login_or_lure_tokens")
        or gib_subs
    ):
        score += 24
        reasons.append("Credential/account input fields present alongside suspicious host, subdomain, or lure path")

    if has_file and (heur.get("risky_tld") or heur.get("tunnel_or_cloud_host") or len(ext_forms) > 0):
        score += 32
        reasons.append("File upload input on untrusted, tunnel/cloud, or external-form page")

    if ext_forms:
        score += 30
        reasons.append("Form submits data to an external domain")
    if susp_forms and (has_pwd or has_cred_inputs or has_file):
        score += 20
        reasons.append("Credential/sensitive form uses empty/anchor/JS/GET submission behavior")

    if obf_hits:
        score += min(34, len(obf_hits) * 11)
        reasons.append(f"Obfuscation/evasion/redirect scripts: {', '.join(obf_hits[:4])}")

    if hidden_iframes > 0:
        score += min(30, hidden_iframes * 15)
        reasons.append(f"{hidden_iframes} hidden iframe(s) embedded on page")

    combined_txt = f"{text_data or ''} {beh.get('text_snippet') or ''}".lower()
    if len(urgency_hits) >= 2:
        score += 24
        reasons.append("Urgency/verification/login social engineering language detected")
    elif any(
        w in combined_txt
        for w in (
            "otp", "pin", "cvv", "kyc update", "account blocked",
            "pay now", "free skin", "claim reward", "download apk", "panel"
        )
    ):
        score += 22
        reasons.append("High-pressure credential, OTP, APK, or reward lure keywords detected")

    dns_info = data.get("sender_dns_forensics") or {}
    if dns_info.get("status") == "checked":
        if not dns_info.get("has_mx"):
            score += 25
            reasons.append("Sender domain has no MX mail records")
        if not dns_info.get("has_spf") and not dns_info.get("has_dmarc"):
            score += 20
            reasons.append("Sender domain lacks SPF and DMARC records")

    email_src = data.get("source_email_forensics") or {}
    if email_src.get("status") == "checked":
        e_dns = email_src.get("dns") or {}
        e_age = email_src.get("domain_age") or {}

        if email_src.get("is_disposable"):
            score += 55
            reasons.append(f"Disposable/temporary email provider detected ({email_src.get('sender_domain')})")

        if email_src.get("is_punycode"):
            score += 48
            reasons.append("Punycode (xn--) lookalike characters in sender domain")

        if email_src.get("free_provider_impersonation"):
            score += 45
            reasons.append(
                f"Public free email ({email_src.get('sender_domain')}) using official/brand-style username ('{email_src.get('local_part')}')"
            )

        if email_src.get("brand_mismatch_in_domain"):
            score += 42
            reasons.append(
                f"Brand keyword ({', '.join(email_src['brand_mismatch_in_domain'])}) spoofed inside sender domain '{email_src.get('sender_domain')}'"
            )

        if email_src.get("risky_tld"):
            score += 32
            reasons.append(f"Sender domain uses high-risk/disposable TLD ('{email_src.get('sender_domain')}')")

        if not e_dns.get("has_mx"):
            score += 35
            reasons.append(f"Sender domain '{email_src.get('sender_domain')}' has no valid MX mail server records")
        if not e_dns.get("has_spf") and not e_dns.get("has_dmarc"):
            score += 24
            reasons.append("Sender domain lacks both SPF and DMARC anti-spoofing records")
        elif not e_dns.get("has_dmarc"):
            score += 12
            reasons.append("Sender domain lacks DMARC policy record")

        if e_age.get("checked") and e_age.get("is_newly_registered"):
            age_d = e_age.get("age_days")
            score += 38 if (age_d is not None and age_d <= 30) else 24
            reasons.append(f"Newly registered sender domain ({age_d} days old, created {e_age.get('created_date')})")

        if email_src.get("lure_in_local") and not email_src.get("is_free_provider"):
            score += 20
            reasons.append(f"Account/verification lure keyword in sender address ({', '.join(email_src['lure_in_local'][:3])})")

        if email_src.get("high_digit_local"):
            score += 15
            reasons.append("Auto-generated numeric pattern in sender username")

    final_score = max(0, min(100, int(score)))
    if not reasons:
        reasons.append("No shortener/wrapper/cloak anomalies, APK/cheat lures, shared-path risks, sender anomalies, structural flaws, or live-page threats observed")
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

    final_score = max(deterministic_score, int(round(0.68 * deterministic_score + 0.32 * ai_score)))
    final_score = max(0, min(100, final_score))
    tier = get_tier(final_score)

    steps = parsed.get("how_to_stay_safe")
    if not isinstance(steps, list) or not steps:
        steps = [
            "Do not reply with personal details, OTPs, or passwords or click links from an unexpected email sender.",
            "Verify the sender independently through the official website or known contact channel before taking action."
        ]

    return {
        "risk_score": final_score,
        "classification": tier,
        "what_was_detected": str(
            parsed.get("what_was_detected")
            or "Target/sender analyzed for email authentication, domain age, brand spoofing, shortener/wrapper deception, and threat signals."
        ).strip(),
        "why_suspicious": str(
            parsed.get("why_suspicious")
            or "Evaluated source email signals, domain reputation, shortener/wrapped targets, and structural/behavioral indicators."
        ).strip(),
        "how_affects_user": str(
            parsed.get("how_affects_user")
            or "Assess spoofing, phishing, credential theft, or malware risk before trusting or responding."
        ).strip(),
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
                    timeout=8
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
                    timeout=8
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
    email_src = (intel or {}).get("source_email_forensics") or {}

    if email_src.get("status") == "checked":
        sender_addr = email_src.get("email") or _extract_email_from_text(text_data) or "Unknown Sender"
        s_dom = email_src.get("sender_domain") or "N/A"
        e_dns = email_src.get("dns") or {}
        e_age = email_src.get("domain_age") or {}
        age_str = f"{e_age.get('age_days')} days" if e_age.get("age_days") is not None else "Unknown"

        if tier == "SAFE":
            what_detected = (
                f"Inspected source email address '{sender_addr}' on domain '{s_dom}' (domain age: {age_str}; "
                f"MX: {e_dns.get('has_mx')}, SPF: {e_dns.get('has_spf')}, DMARC: {e_dns.get('has_dmarc')})."
            )
            why_text = (
                "No disposable mail provider, lookalike/Punycode domain, brand spoofing, high-risk TLD, "
                "or glaring sender authentication anomalies were detected from the source email address alone."
            )
            impact_text = (
                "Source address checks look normal so far, though you should still stay cautious if an email asks for urgent action, OTP, or unexpected links."
            )
            evidence_text = (
                f"Sender: {sender_addr} | Domain: {s_dom} | Age: {age_str} | "
                f"MX/SPF/DMARC: {e_dns.get('has_mx')}/{e_dns.get('has_spf')}/{e_dns.get('has_dmarc')} | Score: {score}/100"
            )
            safe_steps = [
                "The sender address itself looks normal, but never share OTPs, passwords, or payment info just because an email appears to come from a familiar address.",
                "If anything feels unexpected, confirm directly through the official website or app rather than trusting email prompts alone."
            ]
        else:
            what_detected = (
                f"Source email check on '{sender_addr}' (domain '{s_dom}', age: {age_str}) flagged risk signals "
                f"(MX: {e_dns.get('has_mx')}, SPF: {e_dns.get('has_spf')}, DMARC: {e_dns.get('has_dmarc')})."
            )
            why_text = (
                f"{'; '.join(reasons)}. Attackers often use lookalike domains, newly registered domains, free/disposable addresses, "
                "or weak mail authentication to impersonate trusted senders even without complex email body text."
            )
            impact_text = (
                "High risk of phishing, business/brand impersonation, credential theft, or financial fraud if you trust or reply to this sender."
            )
            evidence_text = (
                f"Score: {score}/100 | Sender: {sender_addr} | Domain: {s_dom} | Age: {age_str} | "
                f"Disposable: {email_src.get('is_disposable')} | Free Impersonation: {email_src.get('free_provider_impersonation')}"
            )
            safe_steps = [
                "Do not reply, click links, download attachments, or share credentials/OTPs with this sender address.",
                "Mark it as suspicious/spam and verify any request independently via the official organization website."
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

    report = intel if "behaviour" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    heur = report.get("heuristics") or {}
    beh = report.get("behaviour") or {}
    ssl_info = heur.get("ssl") or {}
    path_ctx = heur.get("path_context") or {}
    dom_age = heur.get("domain_age") or {}

    domain = heur.get("domain") or "Target Payload"
    proto = heur.get("protocol") or "N/A"
    final_url = beh.get("final_url") or text_data or "N/A"
    title = beh.get("title") or "Protected / JS-rendered / wrapped page"
    redirects = int(beh.get("redirect_count") or 0)
    tls_ok = ssl_info.get("tls_valid")
    age_str = f"{dom_age.get('age_days')} days" if dom_age.get("age_days") is not None else "Unknown"

    if tier == "SAFE":
        what_detected = (
            f"Inspected {content_type} targeting '{domain}' ({proto}, age: {age_str}) with {redirects} redirect(s); "
            f"page title reported as '{title}'."
        )
        why_text = (
            f"No URL shortener masking, wrapped/nested external destinations, APK/mod/cheat lures, deceptive login/OAuth paths, "
            f"gibberish subdomains, fresh-domain red flags, credential forms, or obfuscated scripts were observed. "
            f"{'HTTPS TLS certificate check succeeded.' if proto == 'HTTPS' and tls_ok else 'Observed transport and structure appear normal.'}"
