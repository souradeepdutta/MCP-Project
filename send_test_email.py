"""
Send a test phishing email to Mailpit for live ingestion testing.
Requires Mailpit running on localhost:1025 (SMTP).
Start Mailpit: docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

def send_test_phishing_email():
    msg = MIMEMultipart()
    msg["From"] = "billing@update-microsoft-support.com"
    msg["To"] = "finance@yourcompany.com"
    msg["Subject"] = "URGENT: Your invoice #9948 is overdue"
    msg["Message-ID"] = "<MSG-1049@update-microsoft-support.com>"

    body = """Dear Finance Team,

Your invoice #9948 is 30 days overdue. Immediate action is required to avoid service disruption.

Please click below to review and pay your invoice:
http://update-microsoft-support.com/login

If you have already made payment, please disregard this notice.

Best regards,
Microsoft Billing Support
billing@update-microsoft-support.com
"""
    msg.attach(MIMEText(body, "plain"))

    # Attach a fake PDF (empty file simulating invoice_9948.pdf)
    fake_pdf = MIMEBase("application", "pdf")
    fake_pdf.set_payload(b"%PDF-1.4 fake invoice content")
    encoders.encode_base64(fake_pdf)
    fake_pdf.add_header("Content-Disposition", "attachment", filename="invoice_9948.pdf")
    msg.attach(fake_pdf)

    try:
        with smtplib.SMTP("localhost", 1025) as server:
            server.send_message(msg)
        print("✅ Test phishing email sent to Mailpit!")
        print("   View it at: http://localhost:8025")
    except ConnectionRefusedError:
        print("❌ Could not connect to Mailpit SMTP on localhost:1025")
        print("   Start Mailpit first: docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit")

if __name__ == "__main__":
    send_test_phishing_email()
