# test_email_to_arya.py

import smtplib
from email.mime.text import MIMEText

# Gmail app email + app password
EMAIL_ADDRESS = "crypticcomm.notify@gmail.com"

EMAIL_PASSWORD = "chbc zihl quew cpyq"  # your generated App Password

# Receiver
RECEIVER_EMAIL = "aryamokashi1375@gmail.com"


def send_test_email():
    try:
        # Compose the email
        msg = MIMEText(
            "Hello Arya! 👋\n\n"
            "This is a test email from CrypticComm SMTP setup ✅\n\n"
            "If you received this, your SMTP settings are working correctly."
        )
        msg["Subject"] = "SMTP Test - CrypticComm"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = RECEIVER_EMAIL  # send to Arya

        # Connect to Gmail SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Secure connection
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message_api(msg)

        print(f"✅ Test email sent successfully to {RECEIVER_EMAIL}! Check your inbox.")
    except Exception as e:
        print("❌ Failed to send test email:", e)

if __name__ == "__main__":
    send_test_email()
