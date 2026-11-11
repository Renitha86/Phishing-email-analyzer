from email.message import EmailMessage
import os


os.makedirs("samples", exist_ok=True)


def create_email(
    filename,
    sender,
    subject,
    body,
    reply_to=None,
    auth_results=None
):
    message = EmailMessage()

    message["From"] = sender
    message["To"] = "analyst@example.com"
    message["Subject"] = subject

    if reply_to:
        message["Reply-To"] = reply_to

    if auth_results:
        message["Authentication-Results"] = auth_results

    message.set_content(body)

    path = os.path.join("samples", filename)

    with open(path, "wb") as file:
        file.write(bytes(message))


# ============================================================
# LEGITIMATE EMAILS
# ============================================================

create_email(
    "legit_01.eml",
    "Alice <alice@example.com>",
    "Weekly Team Meeting",
    """Hello,

The weekly team meeting is scheduled for tomorrow at 10 AM.

Regards,
Alice
"""
)

create_email(
    "legit_02.eml",
    "HR Team <hr@example.com>",
    "Training Schedule",
    """Hello,

The cybersecurity training schedule has been updated.

Please review the schedule on the internal portal.

Regards,
HR Team
"""
)

create_email(
    "legit_03.eml",
    "Library <library@example.com>",
    "Book Return Reminder",
    """Hello,

This is a reminder that your borrowed books are due next week.

Thank you,
Library Team
"""
)

create_email(
    "legit_04.eml",
    "IT Support <it@example.com>",
    "System Maintenance Notice",
    """Hello,

Scheduled maintenance will take place this weekend.

No action is required from users.

Regards,
IT Support
"""
)

create_email(
    "legit_05.eml",
    "Professor <professor@example.com>",
    "Assignment Update",
    """Hello,

The assignment submission deadline has been updated.

Please check the course portal for details.

Regards,
Professor
"""
)


# ============================================================
# SIMULATED PHISHING EMAILS
# ============================================================

phishing_auth = (
    "mail.example.com; "
    "spf=fail smtp.mailfrom=attacker.example.net; "
    "dkim=fail header.d=attacker.example.net; "
    "dmarc=fail header.from=attacker.example.net"
)


create_email(
    "phishing_01.eml",
    "Microsoft Support <attacker.example.net>",
    "Urgent Account Verification",
    """Your account requires immediate verification.

Visit https://example.com/test to continue.

This is a simulated phishing test.
""",
    reply_to="security@fake-login.example.net",
    auth_results=phishing_auth
)

create_email(
    "phishing_02.eml",
    "Bank Security <attacker.example.net>",
    "Account Security Alert",
    """Your account requires security verification.

Visit https://example.com/verify immediately.

This is a simulated phishing test.
""",
    reply_to="security@fake-login.example.net",
    auth_results=phishing_auth
)

create_email(
    "phishing_03.eml",
    "Cloud Admin <attacker.example.net>",
    "Password Expiration Notice",
    """Your password is scheduled to expire.

Visit https://example.com/password to update it.

This is a simulated phishing test.
""",
    reply_to="admin@fake-login.example.net",
    auth_results=phishing_auth
)

create_email(
    "phishing_04.eml",
    "Security Team <attacker.example.net>",
    "Suspicious Login Detected",
    """A suspicious login was detected.

Visit https://example.com/security to review the activity.

This is a simulated phishing test.
""",
    reply_to="security@fake-login.example.net",
    auth_results=phishing_auth
)

create_email(
    "phishing_05.eml",
    "Payroll Department <attacker.example.net>",
    "Payroll Verification Required",
    """Your payroll information requires verification.

Visit https://example.com/payroll to continue.

This is a simulated phishing test.
""",
    reply_to="payroll@fake-login.example.net",
    auth_results=phishing_auth
)


print("10 test emails created successfully.")