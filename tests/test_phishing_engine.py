from src.phishing_engine import generate_analysis


def test_phishing_email_is_flagged_high_risk():
    report = generate_analysis(
        sender="it-security@secure-account-update.example.net",
        subject="URGENT: Your account will be suspended today",
        body="Your account has been flagged for suspicious activity. Verify your credentials now or your account will be locked and access restricted immediately.",
        display_name="IT Security",
        urls="https://tinyurl.com/account-security-check",
        attachment_name="invoice.exe",
    )
    assert report["risk_score"] >= 50
    assert report["classification"] in {"SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"}


def test_safe_email_stays_low_risk():
    report = generate_analysis(
        sender="alice@university.example.edu",
        subject="Course schedule update",
        body="Hello Alice, this is a routine notice from the Student Services Office. Your course schedule has been updated for the next semester.",
        display_name="Student Services Office",
        urls="https://portal.example.edu/schedule",
        attachment_name="schedule.pdf",
    )
    assert report["risk_score"] < 50
    assert report["classification"] in {"SAFE", "LOW RISK"}
