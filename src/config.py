from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DATASET_PATH = DATA_DIR / "phishing_email_dataset.csv"
HISTORY_DB_PATH = DATA_DIR / "analysis_history.db"

URGENT_KEYWORDS = {
    "urgent", "immediately", "act now", "today", "asap", "deadline", "limited time",
    "final notice", "do not delay"
}
FEAR_KEYWORDS = {
    "suspended", "locked", "deactivated", "security breach", "verify now", "account restricted",
    "restricted", "alert", "urgent action required"
}
FINANCIAL_KEYWORDS = {
    "invoice", "payment", "overdue", "refund", "wire transfer", "tax", "outstanding balance",
    "payment due", "compensation"
}
CREDENTIAL_KEYWORDS = {
    "password", "login", "credential", "verify account", "reset password", "confirm your password",
    "security question", "secure your account"
}
PERSONAL_INFO_KEYWORDS = {
    "social security", "ssn", "passport", "driver license", "full name", "home address",
    "bank account", "routing number", "date of birth"
}
SUSPICIOUS_DOMAIN_KEYWORDS = {
    "verify", "secure", "alert", "update", "support", "login", "account", "payment", "confirm",
    "invoice", "hr", "recruitment"
}
SHORTENER_PATTERNS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "tiny.cc"]

FILE_EXTENSIONS = {
    "exe": "executable",
    "scr": "screensaver",
    "dll": "dynamic library",
    "js": "script",
    "vbs": "visual basic script",
    "bat": "batch",
    "zip": "archive",
    "rar": "archive",
    "iso": "disk image",
    "lnk": "shortcut",
}
