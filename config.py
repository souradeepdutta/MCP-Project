"""
Centralized configuration for the Phishing Triage Agent.

All shared constants, paths, and environment variables are defined here.
Import from this module instead of duplicating values across files.
"""

from pathlib import Path
from dotenv import load_dotenv
import os

# Load .env once — all other modules import from here
load_dotenv()

# ── Paths ──
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "soc_db.sqlite"

# ── Mailpit ──
MAILPIT_URL = os.getenv("MAILPIT_URL", "http://localhost:8025")

# ── Splunk ──
SPLUNK_URL = os.getenv("SPLUNK_URL", "https://localhost:8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")

# ── VirusTotal ──
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_MALICIOUS_THRESHOLD = 5  # Detections above this = MALICIOUS verdict

# ── MCP Gateway ──
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8035/sse")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8035"))
INTERNAL_DOMAINS = ["yourcompany.com"]  # Domains blocked from external TI lookups
