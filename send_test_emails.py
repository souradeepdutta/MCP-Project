"""
Send test phishing emails to Mailpit for live ingestion testing.
Creates 5 different email campaigns matching sample Splunk data.

Requires Mailpit running on localhost:1025 (SMTP) / localhost:8025 (Web UI).
Start Mailpit:
  docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit

Usage:
  python send_test_emails.py          # Send all 5 campaigns
  python send_test_emails.py 1        # Send only campaign 1
  python send_test_emails.py 2 5      # Send campaigns 2 and 5
"""

import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

SMTP_HOST = "localhost"
SMTP_PORT = 1025


def _send(msg):
    """Send a single email via Mailpit SMTP."""
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
        print(f"  ✅ Sent: {msg['Subject']}")
    except ConnectionRefusedError:
        print(f"  ❌ Could not connect to Mailpit SMTP on {SMTP_HOST}:{SMTP_PORT}")
        print("     Start Mailpit: docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit")
        return False
    return True


# ─────────────────────────────────────────────────────────────
# CAMPAIGN 1 — Invoice Phishing (Credential Harvest + Payload)
# ─────────────────────────────────────────────────────────────

def send_campaign_1():
    print("\n📧 Campaign 1: Invoice Phishing (Microsoft impersonation)")
    msg = MIMEMultipart()
    msg["From"] = "billing@update-microsoft-support.com"
    msg["To"] = "finance@yourcompany.com"
    msg["Subject"] = "URGENT: Your invoice #9948 is overdue"
    msg["Message-ID"] = "<MSG-1049@update-microsoft-support.com>"

    body = """\
Dear Finance Team,

Your invoice #9948 is 30 days overdue. Immediate action is required to avoid
service disruption to your Microsoft 365 subscription.

Please click below to review and pay your invoice:
http://update-microsoft-support.com/login

If you have already made payment, please disregard this notice.

Best regards,
Microsoft Billing Support
billing@update-microsoft-support.com
"""
    msg.attach(MIMEText(body, "plain"))

    # Fake PDF attachment
    fake_pdf = MIMEBase("application", "pdf")
    fake_pdf.set_payload(b"%PDF-1.4 fake invoice content - embedded JS payload")
    encoders.encode_base64(fake_pdf)
    fake_pdf.add_header("Content-Disposition", "attachment", filename="invoice_9948.pdf")
    msg.attach(fake_pdf)

    return _send(msg)


# ─────────────────────────────────────────────────────────────
# CAMPAIGN 2 — HR Benefits Phishing (Credential Harvest)
# ─────────────────────────────────────────────────────────────

def send_campaign_2():
    print("\n📧 Campaign 2: HR Benefits Credential Harvest")
    msg = MIMEMultipart()
    msg["From"] = "hr-notifications@hr-benefits-portal.com"
    msg["To"] = "all-employees@yourcompany.com"
    msg["Subject"] = "ACTION REQUIRED: Open Enrollment Deadline Tomorrow"
    msg["Message-ID"] = "<MSG-2077@hr-benefits-portal.com>"

    body = """\
Dear Employee,

This is a final reminder that the open enrollment period for your 2026
health and dental benefits closes TOMORROW at 5:00 PM EST.

If you do not confirm your selections, you will be defaulted to the
basic coverage plan and lose your current premium benefits.

Verify your benefits selections now:
http://hr-benefits-portal.com/verify

You will need to log in with your corporate credentials to access
the benefits portal.

Thank you,
Human Resources Department
YourCompany Benefits Administration
"""
    msg.attach(MIMEText(body, "plain"))

    return _send(msg)


# ─────────────────────────────────────────────────────────────
# CAMPAIGN 3 — Fake Dropbox File Share (Malware Delivery)
# ─────────────────────────────────────────────────────────────

def send_campaign_3():
    print("\n📧 Campaign 3: Fake Dropbox File Share")
    msg = MIMEMultipart("alternative")
    msg["From"] = "noreply@secure-dropbox-share.com"
    msg["To"] = "engineering@yourcompany.com"
    msg["Subject"] = "David Kim shared 'Q1 Performance Review.docx' with you"
    msg["Message-ID"] = "<MSG-3102@secure-dropbox-share.com>"

    text_body = """\
David Kim has shared a file with you.

Q1 Performance Review.docx (2.4 MB)

View and download the shared file:
http://secure-dropbox-share.com/doc/shared-file

This link will expire in 7 days.

— The Dropbox Team
"""

    html_body = """\
<html>
<body style="font-family: Arial, sans-serif; background-color: #f7f7f7; padding: 20px;">
<div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; padding: 30px;">
    <img src="https://placeholder.com/dropbox-logo.png" alt="Dropbox" width="120">
    <hr style="border: 1px solid #eee;">
    <p><strong>David Kim</strong> has shared a file with you.</p>
    <div style="background: #f0f8ff; border-radius: 6px; padding: 15px; margin: 15px 0;">
        📄 <strong>Q1 Performance Review.docx</strong> (2.4 MB)
    </div>
    <a href="http://secure-dropbox-share.com/doc/shared-file"
       style="display: inline-block; background: #0061ff; color: white; padding: 12px 24px;
              border-radius: 6px; text-decoration: none; font-weight: bold;">
        View File
    </a>
    <p style="color: #999; font-size: 12px; margin-top: 20px;">This link will expire in 7 days.</p>
</div>
</body>
</html>
"""
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # Fake .docx attachment with macro
    fake_docx = MIMEBase("application", "vnd.openxmlformats-officedocument.wordprocessingml.document")
    fake_docx.set_payload(b"PK\x03\x04 fake docx with macro payload")
    encoders.encode_base64(fake_docx)
    fake_docx.add_header("Content-Disposition", "attachment", filename="Q1_Performance_Review.docx")
    msg.attach(fake_docx)

    return _send(msg)


# ─────────────────────────────────────────────────────────────
# CAMPAIGN 4 — Internal Helpdesk Notification (BENIGN)
# ─────────────────────────────────────────────────────────────

def send_campaign_4():
    print("\n📧 Campaign 4: Internal Helpdesk Notification (BENIGN)")
    msg = MIMEMultipart()
    msg["From"] = "helpdesk@yourcompany.com"
    msg["To"] = "efoster@yourcompany.com"
    msg["Subject"] = "RE: Ticket #2847 — VPN access issue resolved"
    msg["Message-ID"] = "<MSG-4200@yourcompany.com>"

    body = """\
Hi Emily,

Your IT support ticket #2847 regarding VPN access has been resolved.

Summary:
- Issue: Unable to connect to corporate VPN from home office
- Resolution: Your VPN profile was re-provisioned and the certificate was renewed
- Status: RESOLVED

You can verify the fix by testing your VPN connection. If you continue
to experience issues, please reply to this email or visit:
https://helpdesk.yourcompany.com/ticket/2847

Regards,
IT Support Team
YourCompany Helpdesk
helpdesk@yourcompany.com | ext. 4357
"""
    msg.attach(MIMEText(body, "plain"))

    return _send(msg)


# ─────────────────────────────────────────────────────────────
# CAMPAIGN 5 — Vendor Supply Chain Attack (Macro-enabled doc)
# ─────────────────────────────────────────────────────────────

def send_campaign_5():
    print("\n📧 Campaign 5: Vendor Supply Chain Attack")
    msg = MIMEMultipart()
    msg["From"] = "security@vendor-portal-update.com"
    msg["To"] = "it-admins@yourcompany.com"
    msg["Subject"] = "CRITICAL: Mandatory Security Patch — Apply Immediately"
    msg["Message-ID"] = "<MSG-5310@vendor-portal-update.com>"

    body = """\
SECURITY ADVISORY — CRITICAL

Dear IT Administrator,

A critical zero-day vulnerability (CVE-2026-28741) has been identified in
the VendorConnect platform that your organization relies on. All partner
organizations must apply the emergency security patch within 24 hours.

Failure to apply this patch may result in:
- Unauthorized access to shared vendor data
- Possible remote code execution via the API gateway
- Compliance violations under your service agreement

Download and apply the patch immediately:
http://vendor-portal-update.com/patch

Alternatively, the patch is attached to this email as an Excel macro-enabled
workbook. Enable macros when prompted to apply the fix automatically.

This advisory is classified as CRITICAL by our security team.

Regards,
VendorConnect Security Operations
security@vendor-portal-update.com
Ref: SEC-ADV-2026-0412
"""
    msg.attach(MIMEText(body, "plain"))

    # Fake .xlsm attachment (macro-enabled Excel)
    fake_xlsm = MIMEBase("application", "vnd.ms-excel.sheet.macroEnabled.12")
    fake_xlsm.set_payload(b"PK\x03\x04 fake xlsm with VBA macro dropper")
    encoders.encode_base64(fake_xlsm)
    fake_xlsm.add_header("Content-Disposition", "attachment", filename="security_patch_v2.xlsm")
    msg.attach(fake_xlsm)

    return _send(msg)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

CAMPAIGNS = {
    "1": ("Invoice Phishing", send_campaign_1),
    "2": ("HR Benefits Harvest", send_campaign_2),
    "3": ("Fake Dropbox Share", send_campaign_3),
    "4": ("Internal Helpdesk (Benign)", send_campaign_4),
    "5": ("Vendor Supply Chain", send_campaign_5),
}


def main():
    print("=" * 60)
    print("  PHISHING TRIAGE AGENT — Test Email Sender")
    print("=" * 60)

    # Determine which campaigns to send
    if len(sys.argv) > 1:
        selected = sys.argv[1:]
    else:
        selected = list(CAMPAIGNS.keys())

    for key in selected:
        if key not in CAMPAIGNS:
            print(f"\n⚠️  Unknown campaign: {key} (valid: 1-5)")
            continue
        name, func = CAMPAIGNS[key]
        func()

    print("\n" + "=" * 60)
    print(f"  Done! View emails at: http://localhost:8025")
    print("=" * 60)


if __name__ == "__main__":
    main()
