from mcp.server.fastmcp import FastMCP
import json
import requests
import urllib3
import sqlite3
import uuid
import datetime
from pathlib import Path
import hashlib

# Disable insecure request warnings for local self-signed Splunk certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mcp = FastMCP("Phishing Investigator")

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cases.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS investigations
                 (case_id TEXT PRIMARY KEY,
                  timestamp TEXT,
                  message_id TEXT,
                  verdict TEXT,
                  summary TEXT,
                  actions TEXT)''')
    conn.commit()
    conn.close()
# Run this when the script loads
init_db()



@mcp.tool()
def extract_email_artifacts(message_id: str) -> str:
    """
    Retrieves extracted indicators from a reported suspicious email.
    Always run this first when investigating an email.
    """
    mock_data = {
        "sender": "billing@update-microsoft-support.com",
        "subject": "URGENT: Your invoice #9948 is overdue",
        "recipients": ["finance@yourcompany.com"],
        "urls": ["http://update-microsoft-support.com/login"],
        "attachments": ["invoice_9948.pdf"]
    }
    return json.dumps(mock_data, indent=2)

@mcp.tool()
def query_splunk_for_clicks(url: str) -> str:
    """
    Queries the SIEM (Splunk) to see if any users clicked a specific URL.
    Use this to determine the blast radius and user impact.
    """
    splunk_url = "https://localhost:8089/services/search/jobs/export"
    username = "souradeepdutta8@gmail.com"
    password = "TG@vA2c9gzikpKs"
    
    # SPL query looking for the exact URL in our new index
    search_query = f'search index="proxy_logs" url="{url}" | table _time, user, src_ip, action'

    try:
        response = requests.post(
            splunk_url,
            auth=(username, password),
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
        for line in response.text.strip().split('\n'):
            if line:
                data = json.loads(line)
                if 'result' in data:
                    results.append(data['result'])
        
        if not results:
            return f"0 clicks found for URL: {url}"
            
        return f"ALERT: Found {len(results)} clicks for this URL. Details: {json.dumps(results)}"

    except Exception as e:
        return f"Error querying Splunk: {str(e)}"


@mcp.tool()
def query_endpoint_activity(ip_address: str) -> str:
    """
    Queries Endpoint Detection and Response (EDR) logs in Splunk to check for 
    suspicious process execution on a specific machine.
    Run this ONLY IF a user has clicked a malicious link.
    """
    splunk_url = "https://localhost:8089/services/search/jobs/export"
    username = "souradeepdutta8@gmail.com"
    password = "TG@vA2c9gzikpKs"
    
    # SPL query looking for process execution within 5 minutes of the click
    search_query = f'search index="edr_logs" host_ip="{ip_address}" | table _time, process_name, command_line'

    try:
        response = requests.post(
            splunk_url,
            auth=(username, password),
            data={
                "search": search_query,
                "output_mode": "json"
            },
            verify=False,
            timeout=10
        )
        
        response.raise_for_status()
        
        results = []
        for line in response.text.strip().split('\n'):
            if line:
                data = json.loads(line)
                if 'result' in data:
                    results.append(data['result'])
        
        if not results:
            return f"No endpoint activity found for IP: {ip_address}"
            
        return f"Endpoint Activity for {ip_address}: {json.dumps(results)}"

    except Exception as e:
        return f"Error querying Splunk EDR logs: {str(e)}"


@mcp.tool()
def check_threat_intel(indicator: str, indicator_type: str) -> str:
    """
    Queries global threat intelligence (like VirusTotal) for a domain, IP, or file hash.
    Run this on URLs, domains, and attachments extracted from the email.
    indicator_type must be one of: 'domain', 'ip', 'hash', 'filename'
    """
    # In a production environment, this would be a requests.get() to the VirusTotal API.
    # For the PoC, we use a deterministic mock dictionary to simulate API responses.
    
    intel_database = {
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
        }
    }

    # Normalize the input
    indicator = indicator.lower().strip()
    
    # If the user passes a URL, strip it down to the domain for the intel lookup
    if "http" in indicator:
        try:
            indicator = indicator.split("/")[2]
        except IndexError:
            pass

    if indicator in intel_database:
        result = intel_database[indicator]
        return f"THREAT INTEL MATCH FOUND:\n{json.dumps(result, indent=2)}"
    else:
        return f"No known threat intelligence found for {indicator_type}: {indicator}. Status: UNKNOWN/BENIGN."

@mcp.tool()
def save_investigation_report(message_id: str, verdict: str, summary: str, recommended_actions: str) -> str:
    """
    Saves the final investigation verdict and summary into the local case management database.
    Run this ONLY as the final step of an investigation after all evidence is gathered.
    """
    case_id = f"CAS-{str(uuid.uuid4())[:8].upper()}"
    timestamp = datetime.datetime.now().isoformat()
    
    try:
        # UPDATED: Use the absolute DB_PATH instead of 'cases.db'
        conn = sqlite3.connect(DB_PATH) 
        c = conn.cursor()
        c.execute("INSERT INTO investigations VALUES (?, ?, ?, ?, ?, ?)",
                  (case_id, timestamp, message_id, verdict, summary, recommended_actions))
        conn.commit()
        conn.close()
        return f"SUCCESS: Investigation formally saved. Case ID generated: {case_id}"
    except Exception as e:
        return f"Error saving case to database: {str(e)}"

if __name__ == "__main__":
    mcp.run()