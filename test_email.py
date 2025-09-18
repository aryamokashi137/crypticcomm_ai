# test_email.py

import smtplib
from email.mime.text import MIMEText

# Replace with your Gmail app email + app password
EMAIL_ADDRESS = "crypticcomm.notify@gmail.com"
EMAIL_PASSWORD = "chbc zihl quew cpyq"   # your generated App Password

def send_test_email():
    try:
        # Create the email
        msg = MIMEText("Hello! This is a test email from CrypticComm SMTP setup ✅")
        msg["Subject"] = "SMTP Test - CrypticComm"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = EMAIL_ADDRESS  # send to yourself for testing

        # Connect to Gmail SMTP
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Secure connection
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        print("✅ Test email sent successfully! Check your Gmail inbox.")
    except Exception as e:
        print("❌ Failed to send test email:", e)

if __name__ == "__main__":
    send_test_email()

