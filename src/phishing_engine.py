import re
from datetime import datetime, timezone
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from .config import (
    CREDENTIAL_KEYWORDS,
    FEAR_KEYWORDS,
    FINANCIAL_KEYWORDS,
    PERSONAL_INFO_KEYWORDS,
    SHORTENER_PATTERNS,
    SUSPICIOUS_DOMAIN_KEYWORDS,
    URGENT_KEYWORDS,
    FILE_EXTENSIONS,
)


SAMPLE_SAFE_EMAIL = {
    "sender": "alice@university.example.edu",
    "display_name": "Student Services Office",
    "subject": "Course schedule update",
    "body": (
        "Hello Alice,\n\nThis is a routine notice from the Student Services Office. "
        "Your course schedule has been updated for the next semester. Please review the "
        "attached syllabus in the student portal.\n\nRegards,\nStudent Services Office"
    ),
    "urls": ["https://portal.example.edu/schedule"],
    "attachment_name": "schedule.pdf",
}

SAMPLE_PHISHING_EMAIL = {
    "sender": "it-security@secure-account-update.example.net",
    "display_name": "IT Security",
    "subject": "URGENT: Your account will be suspended today",
    "body": (
        "Your account has been flagged for suspicious activity. Verify your credentials now "
        "or your account will be locked and access restricted immediately. Use the secure "
        "link below to confirm your password and update payment information.\n\n"
        "https://tinyurl.com/account-security-check"
    ),
    "urls": ["https://tinyurl.com/account-security-check"],
    "attachment_name": "invoice.exe",
}


def normalize_text(value: Optional[str]) -> str:
    if value is None:
        return ""
    return str(value).strip()


def coerce_url_list(urls) -> list[str]:
    if urls is None:
        return []
    if isinstance(urls, str):
        if not urls.strip():
            return []
        return [part.strip() for part in re.split(r"[,;\s]+", urls.strip()) if part.strip()]
    if isinstance(urls, Iterable):
        return [str(item).strip() for item in urls if str(item).strip()]
    return [str(urls).strip()]


def extract_sender_domain(sender: str) -> str:
    sender = normalize_text(sender)
    if "@" not in sender:
        return ""
    return sender.rsplit("@", 1)[1].lower()


def get_domain_tokens(domain: str) -> set[str]:
    return {token.lower() for token in re.split(r"[.-]", domain) if token}


def extract_email_features(sender, subject, body, urls=None, attachment_name=None):
    text = f"{subject} {body}".lower()
    url_list = coerce_url_list(urls)
    attachment = normalize_text(attachment_name)
    extension = attachment.rsplit(".", 1)[-1].lower() if "." in attachment else ""
    sender_domain = extract_sender_domain(sender)

    features = {
        "urgent_keyword_count": sum(1 for keyword in URGENT_KEYWORDS if keyword in text),
        "credential_keyword_count": sum(1 for keyword in CREDENTIAL_KEYWORDS if keyword in text),
        "financial_keyword_count": sum(1 for keyword in FINANCIAL_KEYWORDS if keyword in text),
        "threat_keyword_count": sum(1 for keyword in FEAR_KEYWORDS if keyword in text),
        "url_count": len(url_list),
        "suspicious_url_count": sum(1 for url in url_list if is_suspicious_url(url)),
        "has_ip_url": any(re.search(r"https?://\d+\.\d+\.\d+\.\d+", url.lower()) for url in url_list),
        "has_shortened_url_pattern": any(any(pattern in url.lower() for pattern in SHORTENER_PATTERNS) for url in url_list),
        "sender_domain_length": len(sender_domain),
        "subdomain_count": max(0, sender_domain.count(".") - 1),
        "suspicious_attachment": extension in {"exe", "scr", "dll", "js", "vbs", "bat", "lnk"},
        "generic_greeting": bool(re.search(r"\b(dear|hello|hi)\b", body.lower())),
        "contains_password_request": any(keyword in text for keyword in CREDENTIAL_KEYWORDS),
        "contains_personal_info_request": any(keyword in text for keyword in PERSONAL_INFO_KEYWORDS),
        "exclamation_count": text.count("!"),
        "uppercase_ratio": round(sum(1 for char in text if char.isupper()) / max(len(text), 1), 4),
        "body_length": len(normalize_text(body)),
        "subject_length": len(normalize_text(subject)),
        "attachment_extension": extension,
    }
    return features


def is_suspicious_url(url: str) -> bool:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    lowered = url.lower()
    if not domain:
        return False
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        return True
    if any(pattern in lowered for pattern in SHORTENER_PATTERNS):
        return True
    if domain.count(".") >= 3:
        return True
    suspicious_tokens = {"verify", "confirm", "secure", "update", "login", "alerts", "payment"}
    if suspicious_tokens.intersection(get_domain_tokens(domain)):
        return True
    if parsed.scheme not in {"http", "https"}:
        return True
    if "@" in domain:
        return True
    return False


def analyze_sender(sender: str, display_name: Optional[str] = None):
    findings = []
    sender = normalize_text(sender)
    domain = extract_sender_domain(sender)
    risk_score = 0

    if "@" not in sender:
        risk_score += 25
        findings.append("Sender email format appears invalid or incomplete.")
    else:
        if len(domain) > 25:
            risk_score += 12
            findings.append("Sender domain is unusually long for a standard email address.")
        if domain.count(".") > 2:
            risk_score += 10
            findings.append("Sender domain contains multiple subdomain layers.")
        if any(token in domain for token in ["verify", "security", "alert", "secure", "update", "login", "confirm"]):
            risk_score += 12
            findings.append("Sender domain contains keywords frequently associated with spoofing or urgent verification flows.")

    if display_name:
        display = display_name.lower().strip()
        if display and "".join(ch for ch in display if ch.isalpha()) not in "".join(ch for ch in domain if ch.isalpha()):
            if any(token in display for token in ["it", "security", "hr", "support", "bank", "finance"]):
                risk_score += 8
                findings.append("Display name does not clearly match the sender domain and may be misleading.")

    if not findings:
        findings.append("Sender structure looks normal and does not display obvious phishing indicators.")

    return {"sender_risk_score": min(100, risk_score), "sender_findings": findings}


def analyze_email_content(subject: str, body: str):
    text = f"{normalize_text(subject)} {normalize_text(body)}".lower()
    findings = []
    risk_score = 0

    category_map = {
        "URGENCY": URGENT_KEYWORDS,
        "FEAR": FEAR_KEYWORDS,
        "FINANCIAL_PRESSURE": FINANCIAL_KEYWORDS,
        "CREDENTIAL_REQUEST": CREDENTIAL_KEYWORDS,
        "PERSONAL_INFO_REQUEST": PERSONAL_INFO_KEYWORDS,
    }

    for label, keyword_set in category_map.items():
        hits = [keyword for keyword in keyword_set if keyword in text]
        if hits:
            score = min(20, len(hits) * 6)
            risk_score += score
            findings.append(f"{label} language detected: {', '.join(hits[:3])}.")

    if re.search(r"\b(urgent|immediately|act now|today|asap)\b", text):
        risk_score += 10
        findings.append("Urgency language is used to push a quick action without proper review.")
    if re.search(r"\b(verify|confirm|reset|update)\b", text) and any(
        token in text for token in ["account", "password", "login", "credentials", "invoice", "payment"]
    ):
        risk_score += 8
        findings.append("The message asks the recipient to verify or update an account in a pressured way.")
    if re.search(r"\b(dear (customer|user|member)|hi\b)", text):
        risk_score += 4
        findings.append("The email uses a generic greeting rather than a personalized one.")

    if not findings:
        findings.append("Content does not show strong urgency or manipulation signals.")

    return {"content_risk_score": min(100, risk_score), "content_findings": findings}


def analyze_url_indicators(urls):
    url_list = coerce_url_list(urls)
    findings = []
    risk_score = 0

    if not url_list:
        return {"url_risk_score": 0, "url_findings": ["No URL was provided for evaluation."]}

    suspicious_found = 0
    for url in url_list:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            suspicious_found += 1
            findings.append("A URL contains a raw IP address instead of a normal hostname.")
        if any(pattern in url.lower() for pattern in SHORTENER_PATTERNS):
            suspicious_found += 1
            findings.append("A URL uses a shortener pattern that can hide the destination.")
        if parsed.scheme not in {"http", "https"}:
            suspicious_found += 1
            findings.append("A URL uses an unexpected or unusual scheme.")
        domain_tokens = get_domain_tokens(domain)
        if domain_tokens.intersection({"verify", "secure", "login", "confirm", "update", "payment", "alert"}):
            suspicious_found += 1
            findings.append("A destination hostname contains warnings or verification keywords that may be deceptive.")
        if domain.count(".") >= 3:
            suspicious_found += 1
            findings.append("A URL includes an unusually deep hostname structure.")

    risk_score = min(100, suspicious_found * 18)

    if not findings:
        findings.append("URLs appear to use standard-looking destinations without obvious deception cues.")

    return {"url_risk_score": risk_score, "url_findings": findings}


def analyze_attachments(attachment_name: Optional[str]):
    filename = normalize_text(attachment_name)
    findings = []
    risk_score = 0
    if not filename:
        return {"attachment_risk_score": 0, "attachment_findings": ["No attachment was provided."]}

    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension in FILE_EXTENSIONS:
        risk_score += 25
        findings.append(f"Attachment type '{extension}' is associated with risky or executable content.")
    if filename.lower().endswith(".zip") or filename.lower().endswith(".rar"):
        risk_score += 10
        findings.append("Archive file types can conceal malicious content and should be treated carefully.")
    if not findings:
        findings.append("Attachment type does not show obvious suspicious characteristics.")

    return {"attachment_risk_score": min(100, risk_score), "attachment_findings": findings}


def classify_email(risk_score: int) -> str:
    if risk_score >= 75:
        return "HIGH RISK / LIKELY PHISHING"
    if risk_score >= 50:
        return "SUSPICIOUS"
    if risk_score >= 25:
        return "LOW RISK"
    return "SAFE"


def build_recommendations(risk_score: int, findings: List[str]):
    if risk_score >= 75:
        return [
            "Do not click any links or open attachments.",
            "Verify the message using an official contact method instead of the email itself.",
            "Report the email to your IT or security team and isolate any suspicious files.",
        ]
    if risk_score >= 50:
        return [
            "Proceed carefully: confirm the sender through a trusted channel.",
            "Hover over links before clicking and confirm the destination is legitimate.",
            "Watch for urgency, fear, and requests for credentials or money.",
        ]
    if risk_score >= 25:
        return [
            "Check the sender identity and verify the message with the organization.",
            "Review the URL and ensure it matches the expected site exactly.",
            "Be cautious with urgent requests for personal or financial details.",
        ]
    return [
        "No immediate suspicious indicators were found.",
        "Continue to follow normal email hygiene practices and report unusual messages.",
    ]


def generate_analysis(sender, subject, body, display_name=None, urls=None, attachment_name=None):
    url_list = coerce_url_list(urls)
    features = extract_email_features(sender, subject, body, url_list, attachment_name)
    sender_result = analyze_sender(sender, display_name)
    content_result = analyze_email_content(subject, body)
    url_result = analyze_url_indicators(url_list)
    attachment_result = analyze_attachments(attachment_name)

    weighted_score = (
        sender_result["sender_risk_score"] * 0.40
        + content_result["content_risk_score"] * 0.50
        + url_result["url_risk_score"] * 0.20
        + attachment_result["attachment_risk_score"] * 0.15
    )
    risk_score = min(100, round(weighted_score))
    classification = classify_email(risk_score)

    findings = []
    findings.extend(sender_result["sender_findings"])
    findings.extend(content_result["content_findings"])
    findings.extend(url_result["url_findings"])
    findings.extend(attachment_result["attachment_findings"])

    explanation = findings if findings else ["No major phishing indicators were detected during this review."]
    recommendations = build_recommendations(risk_score, findings)

    return {
        "sender": normalize_text(sender),
        "display_name": normalize_text(display_name),
        "subject": normalize_text(subject),
        "body": normalize_text(body),
        "urls": url_list,
        "attachment_name": normalize_text(attachment_name),
        "features": features,
        "sender_details": sender_result,
        "content_details": content_result,
        "url_details": url_result,
        "attachment_details": attachment_result,
        "risk_score": risk_score,
        "classification": classification,
        "findings": findings,
        "explanation": explanation,
        "recommendations": recommendations,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
