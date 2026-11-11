from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
import os
import base64
import hashlib
import csv

import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/urls"

def parse_email(file_path):
    """Parse an .eml file and return the email message object."""
    with open(file_path, "rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    return message


def get_domain(email_address):
    """Extract the domain from an email address."""
    if "@" in email_address:
        return email_address.split("@")[-1].lower()
    return ""


def check_display_name_spoof(message):
    """
    Check whether the visible sender name appears to impersonate
    a different organization/domain.
    """
    from_header = message.get("From", "")
    display_name, email_address = parseaddr(from_header)

    if not display_name or not email_address:
        return False

    sender_domain = get_domain(email_address)

    # Check whether the display name contains an email-like domain
    # different from the actual sender domain.
    domains_in_name = re.findall(
        r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        display_name
    )

    for domain in domains_in_name:
        if domain.lower() != sender_domain:
            return True

    return False


def check_reply_to_mismatch(message):
    """Check whether Reply-To uses a different domain from From."""
    from_header = message.get("From", "")
    reply_to = message.get("Reply-To", "")

    if not from_header or not reply_to:
        return False

    _, from_email = parseaddr(from_header)
    _, reply_email = parseaddr(reply_to)

    from_domain = get_domain(from_email)
    reply_domain = get_domain(reply_email)

    return (
        bool(from_domain)
        and bool(reply_domain)
        and from_domain != reply_domain
    )


def parse_authentication_results(message):
    """Extract SPF, DKIM and DMARC results."""
    auth_header = message.get("Authentication-Results", "")

    results = {
        "SPF": "unknown",
        "DKIM": "unknown",
        "DMARC": "unknown"
    }

    if not auth_header:
        return results

    auth_lower = auth_header.lower()

    for method in results:
        pattern = rf"{method.lower()}\s*=\s*(pass|fail|softfail|neutral|none)"
        match = re.search(pattern, auth_lower)

        if match:
            results[method] = match.group(1)

    return results

def extract_email_body(message):
    """Extract plain-text and HTML content from the email."""
    body_parts = []

    if message.is_multipart():
        for part in message.walk():

            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        if message.get_content_type() in ["text/plain", "text/html"]:
            try:
                body_parts.append(message.get_content())
            except Exception:
                pass

    return "\n".join(body_parts)


def extract_urls(message):
    """Extract URLs from the email body."""
    from urlextract import URLExtract

    body = extract_email_body(message)

    extractor = URLExtract()
    urls = extractor.find_urls(body)

    return list(dict.fromkeys(urls))

def check_url_virustotal(url):
    """Check a URL against VirusTotal."""

    if not VT_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        # VirusTotal identifies URLs using a URL-safe base64 ID.
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        return {
            "status": "error",
            "message": f"VirusTotal returned HTTP {response.status_code}"
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }

def extract_attachments(message):
    """Extract attachment metadata and calculate SHA-256 hashes."""

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if filename:
            payload = part.get_payload(decode=True)

            if payload is None:
                continue

            sha256_hash = hashlib.sha256(payload).hexdigest()

            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": sha256_hash
            })

    return attachments

def check_hash_virustotal(sha256_hash):
    """Check an attachment SHA-256 hash against VirusTotal."""

    if not VT_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        elif response.status_code == 404:
            return {
                "status": "not_found",
                "message": "Hash not found in VirusTotal"
            }

        else:
            return {
                "status": "error",
                "message": f"VirusTotal returned HTTP {response.status_code}"
            }

    except requests.RequestException as error:

        return {
            "status": "error",
            "message": str(error)
        }

def analyze_reputation(message):
    """Analyze URLs and attachments and return indicators."""

    indicators = []

    # -------------------------
    # URL analysis
    # -------------------------

    urls = extract_urls(message)
    url_results = []

    for url in urls:

        reputation = check_url_virustotal(url)

        url_results.append({
            "url": url,
            "reputation": reputation
        })

        if reputation["status"] == "success":

            if reputation["malicious"] > 0:

                indicators.append({
                    "indicator": "Malicious URL",
                    "score": 30
                })

    # -------------------------
    # Attachment analysis
    # -------------------------

    attachments = extract_attachments(message)
    attachment_results = []

    for attachment in attachments:

        reputation = check_hash_virustotal(
            attachment["sha256"]
        )

        attachment_results.append({
            "attachment": attachment,
            "reputation": reputation
        })

        if reputation["status"] == "success":

            if reputation["malicious"] > 0:

                indicators.append({
                    "indicator": "Malicious attachment",
                    "score": 40
                })

    return indicators, url_results, attachment_results

def analyze_email(message):
    """Perform complete phishing analysis."""

    # Header analysis
    header_indicators, auth_results = analyze_headers(message)

    # URL and attachment analysis
    reputation_indicators, url_results, attachment_results = (
        analyze_reputation(message)
    )

    # Combine all indicators
    indicators = header_indicators + reputation_indicators

    # Calculate final score
    score, verdict = calculate_risk_score(indicators)

    return {
        "indicators": indicators,
        "auth_results": auth_results,
        "url_results": url_results,
        "attachment_results": attachment_results,
        "risk_score": score,
        "verdict": verdict
    }

def generate_html_report(file_path, message, results):
    """Generate a human-readable HTML report."""

    filename = os.path.basename(file_path)
    report_name = os.path.splitext(filename)[0] + ".html"
    report_path = os.path.join("output", report_name)

    os.makedirs("output", exist_ok=True)

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phishing Email Analysis Report</title>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            line-height: 1.5;
        }}

        h1 {{
            margin-bottom: 5px;
        }}

        h2 {{
            margin-top: 30px;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 10px;
        }}

        th, td {{
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
        }}

        th {{
            background: #f2f2f2;
        }}

        .score {{
            font-size: 24px;
            font-weight: bold;
        }}

        .indicator {{
            color: #b00020;
        }}
    </style>
</head>

<body>

<h1>Phishing Email Analysis Report</h1>

<p><strong>File:</strong> {filename}</p>

<h2>Sender Details</h2>

<table>
<tr>
    <th>Field</th>
    <th>Value</th>
</tr>

<tr>
    <td>From</td>
    <td>{message.get("From", "Not available")}</td>
</tr>

<tr>
    <td>Reply-To</td>
    <td>{message.get("Reply-To", "Not available")}</td>
</tr>

<tr>
    <td>Return-Path</td>
    <td>{message.get("Return-Path", "Not available")}</td>
</tr>

<tr>
    <td>Subject</td>
    <td>{message.get("Subject", "Not available")}</td>
</tr>

</table>


<h2>Authentication Results</h2>

<table>

<tr>
    <th>Authentication Method</th>
    <th>Result</th>
</tr>

<tr>
    <td>SPF</td>
    <td>{results["auth_results"]["SPF"]}</td>
</tr>

<tr>
    <td>DKIM</td>
    <td>{results["auth_results"]["DKIM"]}</td>
</tr>

<tr>
    <td>DMARC</td>
    <td>{results["auth_results"]["DMARC"]}</td>
</tr>

</table>


<h2>Detected Indicators</h2>

<table>

<tr>
    <th>Indicator</th>
    <th>Score</th>
</tr>
"""

    if results["indicators"]:

        for indicator in results["indicators"]:

            html += f"""
<tr>
    <td class="indicator">
        {indicator["indicator"]}
    </td>

    <td>
        +{indicator["score"]}
    </td>
</tr>
"""

    else:

        html += """
<tr>
    <td colspan="2">No suspicious indicators detected.</td>
</tr>
"""


    html += """
</table>


<h2>URLs</h2>

<table>

<tr>
    <th>URL</th>
    <th>Malicious</th>
    <th>Suspicious</th>
    <th>Harmless</th>
    <th>Undetected</th>
</tr>
"""

    if results["url_results"]:

        for result in results["url_results"]:

            url = result["url"]
            reputation = result["reputation"]

            if reputation["status"] == "success":

                html += f"""
<tr>
    <td>{url}</td>
    <td>{reputation["malicious"]}</td>
    <td>{reputation["suspicious"]}</td>
    <td>{reputation["harmless"]}</td>
    <td>{reputation["undetected"]}</td>
</tr>
"""

            else:

                html += f"""
<tr>
    <td>{url}</td>
    <td colspan="4">
        {reputation.get("message", "Unknown")}
    </td>
</tr>
"""

    else:

        html += """
<tr>
    <td colspan="5">No URLs extracted.</td>
</tr>
"""


    html += """
</table>


<h2>Attachments</h2>

<table>

<tr>
    <th>Filename</th>
    <th>Type</th>
    <th>Size</th>
    <th>SHA-256</th>
    <th>VirusTotal</th>
</tr>
"""

    if results["attachment_results"]:

        for result in results["attachment_results"]:

            attachment = result["attachment"]
            reputation = result["reputation"]

            if reputation["status"] == "success":

                vt_result = (
                    f'Malicious: {reputation["malicious"]}, '
                    f'Suspicious: {reputation["suspicious"]}'
                )

            else:

                vt_result = reputation.get(
                    "message",
                    "Unknown"
                )

            html += f"""
<tr>
    <td>{attachment["filename"]}</td>
    <td>{attachment["content_type"]}</td>
    <td>{attachment["size"]} bytes</td>
    <td>{attachment["sha256"]}</td>
    <td>{vt_result}</td>
</tr>
"""

    else:

        html += """
<tr>
    <td colspan="5">No attachments detected.</td>
</tr>
"""


    html += f"""
</table>


<h2>Final Assessment</h2>

<p class="score">
Risk Score: {results["risk_score"]}/100
</p>

<p>
<strong>Verdict:</strong> {results["verdict"]}
</p>

</body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as report:

        report.write(html)

    return report_path

def process_all_emails():
    """Analyze every .eml file in samples/ and create reports + CSV."""

    os.makedirs("output", exist_ok=True)

    summary = []

    for filename in os.listdir("samples"):

        if not filename.lower().endswith(".eml"):
            continue

        file_path = os.path.join("samples", filename)

        print("\n" + "=" * 60)
        print("Analyzing:", filename)
        print("=" * 60)

        try:
            message = parse_email(file_path)

            results = analyze_email(message)

            report_path = generate_html_report(
                file_path,
                message,
                results
            )

            summary.append({
                "filename": filename,
                "sender": message.get("From", "Not available"),
                "risk_score": results["risk_score"],
                "verdict": results["verdict"]
            })

            print("Risk Score:", results["risk_score"])
            print("Verdict:", results["verdict"])
            print("Report:", report_path)

        except Exception as error:

            print("ERROR:", error)


    # Sort highest risk first
    summary.sort(
        key=lambda item: item["risk_score"],
        reverse=True
    )

    csv_path = os.path.join(
        "output",
        "summary.csv"
    )

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "filename",
                "sender",
                "risk_score",
                "verdict"
            ]
        )

        writer.writeheader()
        writer.writerows(summary)

    print("\n" + "=" * 60)
    print("BATCH ANALYSIS COMPLETE")
    print("=" * 60)

    print("Emails analyzed:", len(summary))
    print("Summary CSV:", csv_path)

def calculate_risk_score(indicators):
    """Calculate total risk score and determine verdict."""

    score = sum(indicator["score"] for indicator in indicators)

    # Cap score at 100
    score = min(score, 100)

    if score <= 29:
        verdict = "Low"
    elif score <= 59:
        verdict = "Medium"
    elif score <= 79:
        verdict = "High"
    else:
        verdict = "Critical"

    return score, verdict
   
def analyze_headers(message):
    """Analyze email headers for phishing indicators."""

    indicators = []

    # Display-name spoof
    if check_display_name_spoof(message):
        indicators.append({
            "indicator": "Display-name spoof",
            "score": 20
        })

    # Reply-To mismatch
    if check_reply_to_mismatch(message):
        indicators.append({
            "indicator": "Reply-To mismatch",
            "score": 15
        })

    # Authentication results
    auth_results = parse_authentication_results(message)

    for method in ["SPF", "DKIM", "DMARC"]:
        if auth_results[method] == "fail":
            indicators.append({
                "indicator": f"{method} failure",
                "score": 20
            })

    return indicators, auth_results


def print_analysis(message, indicators, auth_results):
    """Display the header analysis."""

    print("\n" + "=" * 50)
    print("EMAIL HEADER ANALYSIS")
    print("=" * 50)

    print("From:", message.get("From", "Not available"))
    print("Reply-To:", message.get("Reply-To", "Not available"))
    print("Return-Path:", message.get("Return-Path", "Not available"))

    received_headers = message.get_all("Received", [])

    print("Received headers:", len(received_headers))

    print("\nAuthentication Results:")
    print("SPF:", auth_results["SPF"])
    print("DKIM:", auth_results["DKIM"])
    print("DMARC:", auth_results["DMARC"])
    urls = extract_urls(message)

    print("\nExtracted URLs:")

    if urls:
        for url in urls:
            print("-", url)

            reputation = check_url_virustotal(url)

            if reputation["status"] == "success":
                print(
                    "  VirusTotal:",
                    f"malicious={reputation['malicious']},",
                    f"suspicious={reputation['suspicious']},",
                    f"harmless={reputation['harmless']},",
                    f"undetected={reputation['undetected']}"
                )
            else:
                print(
                    "  VirusTotal:",
                    reputation["message"]
                )

    else:
        print("- None")

    attachments = extract_attachments(message)

    print("\nAttachments:")

    if attachments:

        for attachment in attachments:

            print("-", attachment["filename"])
            print("  Type:", attachment["content_type"])
            print("  Size:", attachment["size"], "bytes")
            print("  SHA-256:", attachment["sha256"])

            reputation = check_hash_virustotal(
                attachment["sha256"]
            )

            if reputation["status"] == "success":

                print(
                    "  VirusTotal:",
                    f"malicious={reputation['malicious']},",
                    f"suspicious={reputation['suspicious']},",
                    f"harmless={reputation['harmless']},",
                    f"undetected={reputation['undetected']}"
                )

            else:

                print(
                    "  VirusTotal:",
                    reputation["message"]
                )

    else:

        print("- None")

    print("\nDetected Indicators:")

    if indicators:
        for indicator in indicators:
            print(
                f"- {indicator['indicator']} "
                f"(+{indicator['score']})"
            )
    else:
        print("- None")


if __name__ == "__main__":

    file_path = "samples/test_with_attachment.eml"
    process_all_emails()

   