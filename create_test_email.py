from email.message import EmailMessage

message = EmailMessage()

message["From"] = "Microsoft Support <support@attacker-example.com>"
message["To"] = "Alice <alice@example.com>"
message["Reply-To"] = "security@fake-login.example.net"
message["Return-Path"] = "<bounce@attacker-example.com>"
message["Authentication-Results"] = (
    "mail.example.com; "
    "spf=fail smtp.mailfrom=attacker-example.com; "
    "dkim=fail header.d=attacker-example.com; "
    "dmarc=fail header.from=attacker-example.com"
)
message["Subject"] = "Urgent Account Verification"

message.set_content(
    """Hello,

This is a simulated phishing email for Lab 05.

Visit https://example.com/test

Regards,
Security Team
"""
)

with open("safe_test.txt", "rb") as attachment:
    message.add_attachment(
        attachment.read(),
        maintype="text",
        subtype="plain",
        filename="safe_test.txt"
    )

with open("samples/test_with_attachment.eml", "wb") as output:
    output.write(bytes(message))

print("Test email created successfully.")