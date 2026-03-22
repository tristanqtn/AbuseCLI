ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"

ENV_FILE = ".env"
ENV_KEY_NAME = "ABUSEIPDB_API_KEY"

DEFAULT_MAX_AGE_IN_DAYS = 90
MAX_AGE_IN_DAYS_MIN = 1
MAX_AGE_IN_DAYS_MAX = 365

VALID_REPORT_CATEGORIES = {
    3, 4, 5, 6, 7, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28
}

ABUSE_CATEGORIES = {
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping Flood",
    7:  "Proxy / TOR",
    9:  "Web Spam",
    10: "Email Spam",
    11: "Blog Spam",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "FTP Brute-Force",
    22: "Ping of Death",
    23: "Phishing",
    24: "Fraud VoIP",
    25: "Open Proxy",
    26: "Web Spam",
    27: "Email Spam",
    28: "Exploited Host",
}

RISK_CRITICAL_MIN = 75
RISK_HIGH_MIN = 50
RISK_MEDIUM_MIN = 25
RISK_LOW_MIN = 0

RISK_LEVELS = {
    "critical": (RISK_CRITICAL_MIN, 100),
    "high": (RISK_HIGH_MIN, RISK_CRITICAL_MIN - 1),
    "medium": (RISK_MEDIUM_MIN, RISK_HIGH_MIN - 1),
    "low": (RISK_LOW_MIN, RISK_MEDIUM_MIN - 1),
}

RISK_COLORS = {
    "critical": "red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "green",
}

EXPORT_FORMATS = ["csv", "json", "excel", "html", "parquet"]

IMPORT_EXTENSION_MAP = {
    ".csv": "csv",
    ".json": "json",
    ".xlsx": "excel",
    ".xls": "excel",
    ".parquet": "parquet",
    ".pq": "parquet",
}

REQUIRED_COLUMNS = ["ipAddress", "abuseConfidenceScore"]
OPTIONAL_COLUMNS = ["countryCode", "isWhitelisted", "isTor", "isPublic", "risk_level"]

COLUMN_DEFAULTS = {
    "countryCode": "Unknown",
    "isWhitelisted": False,
    "isTor": False,
    "isPublic": True,
}

DISPLAY_COLUMN_ORDER = [
    "ipAddress",
    "risk_level",
    "abuseConfidenceScore",
    "countryCode",
    "isWhitelisted",
    "isTor",
    "isPublic",
]