import csv
import random
import sys
from pathlib import Path

try:
    from .config import DATASET_PATH
except ImportError:  # pragma: no cover - direct script execution fallback
    ROOT = Path(__file__).resolve().parent.parent
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from src.config import DATASET_PATH

LEGITIMATE_SUBJECTS = [
    "Course schedule update",
    "University notice: New orientation schedule",
    "HR update: Annual benefits enrollment",
    "Project meeting reminder",
    "Order confirmation: Shopping portal",
    "Newsletter: Weekly security awareness tips",
    "Password change confirmation",
    "Bank-style notification: Account summary",
]

PHISHING_SUBJECTS = [
    "URGENT: Your account will be suspended today",
    "Action required: Verify your email account",
    "Final notice: Invoice payment due immediately",
    "Congratulations! You have won a digital rewards prize",
    "Security alert: Password expires within 24 hours",
    "Delivery issue: Confirm your shipment details",
    "Executive request: Please review this file",
    "HR notice: Payroll verification required",
]

SAFE_DOMAINS = [
    "example.edu",
    "university.example.edu",
    "careers.example.com",
    "support.example.org",
    "billing.example.net",
    "newsletter.example.com",
]

PHISHING_DOMAINS = [
    "verify-account.example.net",
    "secure-update.example.com",
    "payment-confirmation.example.org",
    "alert-support.example.net",
    "hr-help.example.com",
    "account-portal.example.net",
]

LEGITIMATE_BODIES = [
    "Hello, this is an update from Student Services. Please review your schedule in the portal.",
    "Dear Team, the HR department has pushed updated benefits information. Please review it before Friday.",
    "Hi there, this is a meeting reminder for the product roadmap review. We have moved the session to 3:00 PM.",
    "Your order has been confirmed and the invoice is attached for your reference.",
    "Your password was updated successfully. This is a standard confirmation message.",
    "Greetings, this is a weekly newsletter from the learning center. Please find attached the latest updates.",
]

PHISHING_BODIES = [
    "Your account has been flagged for suspicious activity. Verify your credentials immediately or your access will be restricted.",
    "We noticed a failed payment and require confirmation of your invoice details. Use the secure portal to resolve this today.",
    "Congratulations, you have been selected for a limited-time reward. Click the link to claim your benefit before the offer expires.",
    "Your password is expiring soon. Update your account to avoid temporary suspension.",
    "Urgent review required for your pending package. Confirm your delivery details before the shipment is returned.",
    "The payroll team needs your confirmation details for a recent update. Please complete the form immediately.",
]

LEGITIMATE_URLS = [
    "https://portal.example.edu/schedule",
    "https://hr.example.org/benefits",
    "https://meetings.example.com/project-review",
    "https://shop.example.net/order/45430",
    "https://security.example.com/account-summary",
]

PHISHING_URLS = [
    "http://89.116.60.1/verify",
    "https://tinyurl.com/hr-payroll-update",
    "https://secure-login.example.net/confirm",
    "https://verify-account.example.net/alert",
    "https://payment-confirmation.example.org/invoice",
]

ATTACHMENTS = ["schedule.pdf", "benefits.pdf", "invoice.pdf", "meeting-notes.docx", "award.exe", "report.zip", "passport.pdf", "suspicious.exe"]


def generate_dataset(output_path: Path = DATASET_PATH, record_count: int = 600):
    rows = []
    random.seed(42)

    for i in range(record_count):
        is_phishing = i % 2 == 0
        if is_phishing:
            sender = f"user{random.randint(10, 999)}@{random.choice(PHISHING_DOMAINS)}"
            subject = random.choice(PHISHING_SUBJECTS)
            body = random.choice(PHISHING_BODIES)
            urls = random.choice(PHISHING_URLS)
            attachment = random.choice(["invoice.exe", "package.zip", "award.exe"])
            label = "PHISHING"
        else:
            sender = f"{random.choice(['student', 'finance', 'ops', 'hr', 'alerts'])}{random.randint(1, 999)}@{random.choice(SAFE_DOMAINS)}"
            subject = random.choice(LEGITIMATE_SUBJECTS)
            body = random.choice(LEGITIMATE_BODIES)
            urls = random.choice(LEGITIMATE_URLS)
            attachment = random.choice(["schedule.pdf", "meeting-notes.docx", "invoice.pdf", "newsletter.pdf"])
            label = "LEGITIMATE"

        row = {
            "email_id": f"E{str(i + 1).zfill(4)}",
            "sender": sender,
            "sender_domain": sender.rsplit("@", 1)[1].lower(),
            "subject": subject,
            "body": body,
            "urls": urls,
            "attachment_name": attachment,
            "label": label,
        }
        rows.append(row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=["email_id", "sender", "sender_domain", "subject", "body", "urls", "attachment_name", "label"],
        )
        writer.writeheader()
        writer.writerows(rows)

    return rows


if __name__ == "__main__":
    rows = generate_dataset()
    print(f"Generated {len(rows)} records in {DATASET_PATH}")
