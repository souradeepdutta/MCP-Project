from mcp.server.fastmcp import FastMCP
import json
import os
import re
import email
import requests
import urllib3
import sqlite3
import uuid
import datetime
import hashlib
from pathlib import Path
from email import policy
from email.parser import BytesParser
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Disable insecure request warnings for local self-signed Splunk certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mcp = FastMCP("Phishing Investigator")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cases.db"

# Splunk configuration from environment
SPLUNK_URL = os.getenv("SPLUNK_URL", "https://localhost:8089")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")

# VirusTotal configuration from environment
VT_API_KEY = os.getenv("VT_API_KEY", "")

# Email ingestion configuration
EMAIL_SOURCE = os.getenv("EMAIL_SOURCE", "mock")
MAILPIT_URL = os.getenv("MAILPIT_URL", "http://localhost:8025")
EML_FILE_PATH = os.getenv("EML_FILE_PATH", "")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS investigations
                 (case_id TEXT PRIMARY KEY,
                  timestamp TEXT,
                  message_id TEXT,
                  verdict TEXT,
                  summary TEXT,
                  technical_details TEXT,
                  actions TEXT)''')
    conn.commit()
    conn.close()
# Run this when the script loads
init_db()


# ─────────────────────────────────────────────────────────────
# TOOL 1: Extract Email Artifacts
# ─────────────────────────────────────────────────────────────

def _parse_eml_file(file_path: str) -> dict:
    """Parse a local .eml file and extract artifacts."""
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg["from"] or ""
    subject = msg["subject"] or ""
    recipients = [addr.strip() for addr in (msg["to"] or "").split(",")]
    message_id = msg["message-id"] or ""

    # Extract URLs from body
    urls = []
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                payload = part.get_content()
                if payload:
                    body_text += payload
    else:
        body_text = msg.get_content() or ""

    # Regex to extract URLs from text or HTML
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    urls = list(set(url_pattern.findall(body_text)))

    # Extract attachment filenames
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)

    return {
        "message_id": message_id,
        "sender": sender,
        "subject": subject,
        "recipients": recipients,
        "urls": urls,
        "attachments": attachments,
        "body_snippet": body_text[:500]
    }


def _fetch_from_mailpit(target_message_id: str = "") -> dict:
    """Fetch an email from Mailpit API and parse it."""
    try:
        # Get all messages from Mailpit
        resp = requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
        resp.raise_for_status()
        messages = resp.json().get("messages", [])

        if not messages:
            return {"error": "No messages found in Mailpit inbox."}

        target_internal_id = None
        for m in messages:
            msg_id_header = m.get("MessageID", "")
            subject = m.get("Subject", "")
            
            clean_target = target_message_id.lower().strip("\"'")
            if clean_target:
                if clean_target in msg_id_header.lower() or clean_target in subject.lower():
                    target_internal_id = m["ID"]
                    break

        if not target_internal_id:
            target_internal_id = messages[0]["ID"]  # Fallback to latest

        # Fetch the raw .eml source
        eml_resp = requests.get(f"{MAILPIT_URL}/api/v1/message/{target_internal_id}/raw", timeout=10)
        eml_resp.raise_for_status()

        msg = BytesParser(policy=policy.default).parsebytes(eml_resp.content)

        sender = msg["from"] or ""
        subject = msg["subject"] or ""
        recipients = [addr.strip() for addr in (msg["to"] or "").split(",")]
        message_id = msg["message-id"] or target_internal_id

        urls = []
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    payload = part.get_content()
                    if payload:
                        body_text += payload
        else:
            body_text = msg.get_content() or ""

        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        urls = list(set(url_pattern.findall(body_text)))

        attachments = []
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)

        return {
            "message_id": message_id,
            "sender": sender,
            "subject": subject,
            "recipients": recipients,
            "urls": urls,
            "attachments": attachments,
            "body_snippet": body_text[:500]
        }

    except Exception as e:
        return {"error": f"Failed to fetch from Mailpit: {str(e)}"}


def _mock_email_data() -> dict:
    """Fallback mock email data for demo/testing."""
    return {
        "sender": "billing@update-microsoft-support.com",
        "subject": "URGENT: Your invoice #9948 is overdue",
        "recipients": ["finance@yourcompany.com"],
        "urls": ["http://update-microsoft-support.com/login"],
        "attachments": ["invoice_9948.pdf"]
    }


@mcp.tool()
def extract_email_artifacts(message_id: str) -> str:
    """
    Retrieves extracted indicators from a reported suspicious email.
    Always run this first when investigating an email.

    Supports three modes (configured via EMAIL_SOURCE env var):
    - 'mock': Returns hardcoded demo data (default)
    - 'file': Parses a local .eml file (set EML_FILE_PATH in .env)
    - 'mailpit': Fetches the latest email from Mailpit API
    """
    if EMAIL_SOURCE == "file" and EML_FILE_PATH:
        if not Path(EML_FILE_PATH).exists():
            return json.dumps({"error": f"EML file not found: {EML_FILE_PATH}"}, indent=2)
        result = _parse_eml_file(EML_FILE_PATH)
    elif EMAIL_SOURCE == "mailpit":
        result = _fetch_from_mailpit(message_id)
    else:
        result = _mock_email_data()

    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────
# TOOL 2: Query Splunk for URL Clicks (Blast Radius)
# ─────────────────────────────────────────────────────────────

@mcp.tool()
def query_splunk_for_clicks(url: str) -> str:
    """
    Queries the SIEM (Splunk) to see if any users clicked a specific URL.
    Use this to determine the blast radius and user impact.
    """
    splunk_endpoint = f"{SPLUNK_URL}/services/search/jobs/export"

    # SPL query looking for the exact URL (raw text search)
    search_query = f'search index="proxy_logs" "{url}"'

    try:
        response = requests.post(
            splunk_endpoint,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data={
                "search": search_query,
                "output_mode": "json"
            },
            verify=False, # Ignore self-signed certs for local Splunk
            timeout=10
        )

        response.raise_for_status()

        # Splunk export endpoint returns multiple JSON objects separated by newlines
        results = []
        import csv
        import io
        for line in response.text.strip().split('\n'):
            if line:
                data = json.loads(line)
                if 'result' in data:
                    res = data['result']
                    # Try to use extracted fields if they exist
                    if 'user' in res and 'src_ip' in res:
                        results.append({'_time': res.get('_time'), 'user': res.get('user'), 'src_ip': res.get('src_ip'), 'action': res.get('action')})
                    elif '_raw' in res:
                        # Fallback to parsing _raw CSV
                        raw = res['_raw']
                        if raw.startswith('_time'):
                            continue # skip header
                        reader = csv.reader(io.StringIO(raw))
                        for row in reader:
                            if len(row) >= 5:
                                results.append({'_time': row[0], 'src_ip': row[1], 'user': row[2], 'url': row[3], 'action': row[4]})

        if not results:
            return f"0 clicks found for URL: {url}"

        return f"ALERT: Found {len(results)} clicks for this URL. Details: {json.dumps(results)}"

    except Exception as e:
        return f"Error querying Splunk: {str(e)}"


# ─────────────────────────────────────────────────────────────
# TOOL 3: Query Endpoint Activity (EDR / Sysmon)
# ─────────────────────────────────────────────────────────────

@mcp.tool()
def query_endpoint_activity(ip_address: str) -> str:
    """
    Queries Endpoint Detection and Response (EDR) logs in Splunk to check for 
    suspicious process execution on a specific machine.
    Run this ONLY IF a user has clicked a malicious link.
    """
    splunk_endpoint = f"{SPLUNK_URL}/services/search/jobs/export"

    # SPL query looking for host_ip (raw text search)
    search_query = f'search index="edr_logs" "{ip_address}"'

    try:
        response = requests.post(
            splunk_endpoint,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data={
                "search": search_query,
                "output_mode": "json"
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        results = []
        import csv
        import io
        for line in response.text.strip().split('\n'):
            if line:
                data = json.loads(line)
                if 'result' in data:
                    res = data['result']
                    if 'process_name' in res and 'command_line' in res:
                        results.append({'_time': res.get('_time'), 'process_name': res.get('process_name'), 'command_line': res.get('command_line')})
                    elif '_raw' in res:
                        raw = res['_raw']
                        if raw.startswith('_time'):
                            continue
                        reader = csv.reader(io.StringIO(raw))
                        for row in reader:
                            if len(row) >= 6:
                                results.append({'_time': row[0], 'host_ip': row[1], 'user': row[2], 'process_name': row[3], 'command_line': row[4], 'action': row[5]})

        if not results:
            return f"No endpoint activity found for IP: {ip_address}"

        return f"Endpoint Activity for {ip_address}: {json.dumps(results)}"

    except Exception as e:
        return f"Error querying Splunk EDR logs: {str(e)}"


# ─────────────────────────────────────────────────────────────
# TOOL 4: Threat Intelligence Lookup
# ─────────────────────────────────────────────────────────────

def _query_virustotal(indicator: str, indicator_type: str) -> dict | None:
    """Query VirusTotal API v3 for a given indicator. Returns None on failure."""
    if not VT_API_KEY or indicator_type == "filename":
        return None

    headers = {"x-apikey": VT_API_KEY}
    base_url = "https://www.virustotal.com/api/v3"

    try:
        if indicator_type == "domain":
            resp = requests.get(f"{base_url}/domains/{indicator}", headers=headers, timeout=15)
        elif indicator_type == "ip":
            resp = requests.get(f"{base_url}/ip_addresses/{indicator}", headers=headers, timeout=15)
        elif indicator_type == "hash":
            resp = requests.get(f"{base_url}/files/{indicator}", headers=headers, timeout=15)
        elif indicator_type == "url":
            # VT requires URL ID as base64(url) without padding
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            resp = requests.get(f"{base_url}/urls/{url_id}", headers=headers, timeout=15)
        else:
            return None

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            reputation = data.get("reputation", "N/A")

            return {
                "source": "VirusTotal",
                "indicator": indicator,
                "type": indicator_type,
                "malicious_detections": f"{malicious}/{total}",
                "reputation_score": reputation,
                "tags": data.get("tags", []),
                "verdict": "MALICIOUS" if malicious > 5 else "SUSPICIOUS" if malicious > 0 else "CLEAN"
            }
        elif resp.status_code == 404:
            return {
                "source": "VirusTotal",
                "indicator": indicator,
                "type": indicator_type,
                "verdict": "NOT FOUND",
                "note": "No data available on VirusTotal for this indicator."
            }
        else:
            return None

    except Exception:
        return None


@mcp.tool()
def check_threat_intel(indicator: str, indicator_type: str) -> str:
    """
    Queries threat intelligence for a domain, IP, URL, or file hash.
    Run this on URLs, domains, and attachments extracted from the email.
    indicator_type must be one of: 'domain', 'ip', 'hash', 'url', 'filename'

    If a VirusTotal API key is configured (VT_API_KEY in .env), queries VT live.
    Otherwise, falls back to a local mock database for demo purposes.
    """
    # Normalize the input
    indicator_clean = indicator.lower().strip()

    # If the user passes a full URL and type is 'domain', strip to domain
    if indicator_type == "domain" and "http" in indicator_clean:
        try:
            indicator_clean = indicator_clean.split("/")[2]
        except IndexError:
            pass

    # Attempt live VirusTotal lookup first
    vt_result = _query_virustotal(indicator_clean, indicator_type)
    if vt_result:
        return f"THREAT INTEL (VirusTotal LIVE):\n{json.dumps(vt_result, indent=2)}"

    # Fallback: local mock intel database for demo/testing
    intel_database = {
        # Campaign 1
        "update-microsoft-support.com": {
            "verdict": "MALICIOUS",
            "score": "88/90",
            "threat_actor": "UNC2500",
            "tags": ["typosquatting", "credential-harvesting"]
        },
        "invoice_9948.pdf": {
            "verdict": "MALICIOUS",
            "score": "45/90",
            "threat_actor": "Unknown",
            "tags": ["pdf-phishing", "embedded-javascript"]
        },
        "payload.exe": {
            "verdict": "CRITICAL",
            "score": "72/90",
            "threat_actor": "Cobalt Strike",
            "tags": ["c2-beacon", "ransomware-dropper"]
        },
        # Campaign 2
        "hr-benefits-portal.com": {
            "verdict": "MALICIOUS",
            "score": "65/90",
            "threat_actor": "Scattered Spider",
            "tags": ["credential-harvesting", "mfa-bypass"]
        },
        # Campaign 3
        "secure-dropbox-share.com": {
            "verdict": "MALICIOUS",
            "score": "78/90",
            "threat_actor": "APT29",
            "tags": ["phishing", "malware-delivery"]
        },
        "q1_performance_review.docx": {
            "verdict": "MALICIOUS",
            "score": "52/90",
            "threat_actor": "APT29",
            "tags": ["macro-malware", "downloader"]
        },
        # Campaign 4
        "helpdesk.yourcompany.com": {
            "verdict": "BENIGN",
            "score": "0/90",
            "threat_actor": "None",
            "tags": ["internal", "legitimate"]
        },
        # Campaign 5
        "vendor-portal-update.com": {
            "verdict": "MALICIOUS",
            "score": "81/90",
            "threat_actor": "FIN7",
            "tags": ["supply-chain", "watering-hole"]
        },
        "security_patch_v2.xlsm": {
            "verdict": "MALICIOUS",
            "score": "49/90",
            "threat_actor": "FIN7",
            "tags": ["vba-macro", "dll-sideload"]
        },
        "update.dll": {
            "verdict": "CRITICAL",
            "score": "88/90",
            "threat_actor": "FIN7",
            "tags": ["backdoor", "c2-beacon"]
        }
    }

    if indicator_clean in intel_database:
        result = intel_database[indicator_clean]
        return f"THREAT INTEL MATCH FOUND (mock):\n{json.dumps(result, indent=2)}"
    else:
        return f"No known threat intelligence found for {indicator_type}: {indicator_clean}. Status: UNKNOWN/BENIGN."


# ─────────────────────────────────────────────────────────────
# TOOL 5: Save Investigation Report
# ─────────────────────────────────────────────────────────────

@mcp.tool()
def save_investigation_report(message_id: str, verdict: str, summary: str, technical_details: str, recommended_actions: str) -> str:
    """
    Saves the final investigation verdict and summary into the local case management database.
    Run this ONLY as the final step of an investigation after all evidence is gathered.
    """
    case_id = f"CAS-{str(uuid.uuid4())[:8].upper()}"
    timestamp = datetime.datetime.now().isoformat()

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO investigations VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (case_id, timestamp, message_id, verdict, summary, technical_details, recommended_actions))
        conn.commit()
        conn.close()
        return f"SUCCESS: Investigation formally saved. Case ID generated: {case_id}"
    except Exception as e:
        return f"Error saving case to database: {str(e)}"

if __name__ == "__main__":
    mcp.run()
