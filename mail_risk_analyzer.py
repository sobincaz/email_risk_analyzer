#!/usr/bin/env python3
"""
Mail Risk Analyzer
------------------
Analyze a raw .eml email for common phishing indicators.

Usage:
    pip install reportlab
    python mail_risk_analyzer.py suspicious_email.eml
    python mail_risk_analyzer.py suspicious_email.eml --report my_report.pdf

This is a heuristic screening tool, not a replacement for a mail gateway,
antivirus, or manual security review. It does not follow links or download files.
"""

import argparse
import re
import sys
from collections import defaultdict
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape
from urllib.parse import urlparse

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import mm
except ImportError:
    print("Missing dependency: reportlab. Install it with: pip install reportlab")
    sys.exit(1)


URGENT_PHRASES = [
    "urgent", "immediately", "act now", "verify your account",
    "account suspended", "account will be closed", "payment failed",
    "within 24 hours", "password expires", "unusual activity",
    "click here", "confirm your identity", "limited time",
]
SUSPICIOUS_TLDS = {".zip", ".top", ".xyz", ".click", ".work", ".country", ".gq"}
URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")


def clean_text(value):
    return unescape(str(value or "")).replace("\r", " ").replace("\n", " ").strip()


def get_body(message):
    """Return readable text/plain and text/html body content."""
    parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    payload = part.get_content()
                except Exception:
                    raw = part.get_payload(decode=True) or b""
                    payload = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
                if part.get_content_type() == "text/html":
                    payload = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", str(payload))
                    payload = re.sub(r"(?s)<[^>]+>", " ", str(payload))
                parts.append(str(payload))
    else:
        try:
            payload = message.get_content()
        except Exception:
            raw = message.get_payload(decode=True) or b""
            payload = raw.decode(message.get_content_charset() or "utf-8", errors="replace")
        if message.get_content_type() == "text/html":
            payload = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", str(payload))
            payload = re.sub(r"(?s)<[^>]+>", " ", str(payload))
        parts.append(str(payload))
    return "\n".join(parts)


def extract_domain(address):
    address = parseaddr(address or "")[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def analyze_email(path):
    with open(path, "rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    body = get_body(message)
    headers = {key.lower(): message.get_all(key, []) for key in message.keys()}
    findings = []
    score = 0

    def flag(points, label, detail):
        nonlocal score
        score += points
        findings.append((points, label, detail))

    # Header inspection
    from_value = clean_text(message.get("From", ""))
    reply_to = clean_text(message.get("Reply-To", ""))
    return_path = clean_text(message.get("Return-Path", ""))
    from_domain = extract_domain(from_value)
    reply_domain = extract_domain(reply_to)
    return_domain = extract_domain(return_path)

    received = message.get_all("Received", [])
    auth_results = message.get_all("Authentication-Results", [])
    received_spf = message.get_all("Received-SPF", [])
    dkim_headers = message.get_all("DKIM-Signature", [])

    if not received:
        flag(5, "No Received header", "No Received trace was found. Some exported or crafted messages may omit it.")
    if not auth_results and not received_spf:
        flag(10, "No SPF authentication result", "No Authentication-Results or Received-SPF header was found.")
    if auth_results or received_spf:
        auth_text = " ".join(map(str, auth_results + received_spf)).lower()
        if re.search(r"\bspf\s*=\s*fail\b|\bspf=fail\b", auth_text):
            flag(25, "SPF failed", "An authentication header reports SPF failure.")
        elif re.search(r"\bspf\s*=\s*softfail\b|\bspf=softfail\b", auth_text):
            flag(12, "SPF softfail", "An authentication header reports SPF softfail.")
        elif re.search(r"\bspf\s*=\s*none\b|\bspf=none\b", auth_text):
            flag(8, "SPF missing", "An authentication header reports no SPF policy/result.")
        if re.search(r"\bdkim\s*=\s*fail\b|\bdkim=fail\b", auth_text):
            flag(25, "DKIM failed", "An authentication header reports DKIM failure.")
        elif re.search(r"\bdkim\s*=\s*none\b|\bdkim=none\b", auth_text):
            flag(8, "DKIM missing", "An authentication header reports no DKIM signature/result.")
        if re.search(r"\bdmarc\s*=\s*fail\b|\bdmarc=fail\b", auth_text):
            flag(25, "DMARC failed", "An authentication header reports DMARC failure.")

    if not dkim_headers:
        # Absence alone is a weaker signal because some legitimate senders do not sign.
        flag(4, "No DKIM-Signature header", "No DKIM-Signature header was present; this alone does not prove phishing.")

    if reply_domain and from_domain and reply_domain != from_domain:
        flag(18, "Reply-To domain mismatch",
             f"From domain is {from_domain}, but Reply-To domain is {reply_domain}.")
    if return_domain and from_domain and return_domain != from_domain:
        flag(12, "Return-Path domain mismatch",
             f"From domain is {from_domain}, but Return-Path domain is {return_domain}.")

    # Body and link inspection
    lower_body = body.lower()
    matched_urgent = sorted({phrase for phrase in URGENT_PHRASES if phrase in lower_body})
    if matched_urgent:
        flag(min(20, 5 + 3 * len(matched_urgent)), "Urgent/action language",
             "Found: " + ", ".join(matched_urgent))

    urls = URL_RE.findall(body)
    parsed_urls = []
    for raw_url in urls:
        candidate = raw_url.rstrip(".,);!?]")
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        if host:
            parsed_urls.append((candidate, host))

    if not parsed_urls and re.search(r"(?i)\b(click|visit|open)\b", body):
        flag(3, "Call to visit a link", "The message asks the reader to visit/click, but no plain URL was extracted.")

    for url, host in parsed_urls:
        if host.startswith("xn--") or ".xn--" in host:
            flag(15, "Internationalized/punycode domain",
                 f"URL uses a punycode hostname: {host}")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flag(8, "Unusual top-level domain", f"URL hostname uses a commonly abused TLD: {host}")
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            flag(15, "IP address in URL", f"Link points directly to an IP address: {host}")
        if "@" in urlparse(url).netloc:
            flag(15, "Misleading URL user-info", f"URL contains an @ sign in its authority section: {url}")

    # Compare visible email addresses in the body with the sender domain.
    body_addresses = EMAIL_RE.findall(body)
    external_addresses = sorted({
        extract_domain(addr) for addr in body_addresses
        if extract_domain(addr) and from_domain and extract_domain(addr) != from_domain
    })
    if external_addresses:
        flag(5, "Different email domains in body",
             "Body contains email addresses on other domains: " + ", ".join(external_addresses))

    # Lightweight lookalike checks: a sender domain that visually contains a known brand
    # with extra characters is a clue, not proof. No live brand database is used.
    common_brands = ("paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank")
    if from_domain:
        for brand in common_brands:
            if brand in from_domain and from_domain not in (brand + ".com", brand + ".co.uk"):
                flag(10, "Possible brand-lookalike sender domain",
                     f"Sender domain '{from_domain}' contains the brand term '{brand}'.")
                break

    score = min(score, 100)
    if score >= 60:
        verdict = "HIGH RISK — likely phishing"
    elif score >= 30:
        verdict = "MEDIUM RISK — suspicious; verify independently"
    else:
        verdict = "LOWER RISK — no strong indicators detected"

    return {
        "subject": clean_text(message.get("Subject", "(No subject)")),
        "from": from_value or "(Unknown)",
        "to": clean_text(message.get("To", "(Unknown)")),
        "date": clean_text(message.get("Date", "(Unknown)")),
        "from_domain": from_domain or "(Unknown)",
        "reply_to": reply_to or "(Not provided)",
        "return_path": return_path or "(Not provided)",
        "received_count": len(received),
        "spf_headers": [clean_text(x) for x in received_spf],
        "auth_results": [clean_text(x) for x in auth_results],
        "dkim_count": len(dkim_headers),
        "urls": parsed_urls,
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def create_pdf(result, output_path):
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER, textColor=colors.HexColor("#17365D")))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    story = [
        Paragraph("Email Security / Phishing Analysis Report", styles["ReportTitle"]),
        Spacer(1, 6 * mm),
        Paragraph("<b>Assessment:</b> " + result["verdict"], styles["Heading2"]),
        Paragraph(f"<b>Risk score:</b> {result['score']} / 100", styles["BodyText"]),
        Spacer(1, 4 * mm),
        Paragraph("1. Message details", styles["Heading2"]),
    ]
    details = [
        ["Field", "Value"],
        ["Subject", result["subject"]],
        ["From", result["from"]],
        ["To", result["to"]],
        ["Date", result["date"]],
        ["Sender domain", result["from_domain"]],
        ["Reply-To", result["reply_to"]],
        ["Return-Path", result["return_path"]],
    ]
    table = Table([[Paragraph(str(c), styles["Small"]) for c in row] for row in details], colWidths=[38 * mm, 130 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [table, Spacer(1, 4 * mm), Paragraph("2. Header authentication review", styles["Heading2"])]
    header_lines = [
        f"Received headers: {result['received_count']}",
        f"DKIM-Signature headers: {result['dkim_count']}",
        "Received-SPF: " + ("; ".join(result["spf_headers"]) if result["spf_headers"] else "Not present"),
        "Authentication-Results: " + ("; ".join(result["auth_results"]) if result["auth_results"] else "Not present"),
    ]
    story.extend(Paragraph("• " + line, styles["BodyText"]) for line in header_lines)
    story += [Spacer(1, 3 * mm), Paragraph("3. Links found in message body", styles["Heading2"])]
    if result["urls"]:
        for url, host in result["urls"]:
            story.append(Paragraph(f"• {url} (host: {host})", styles["Small"]))
    else:
        story.append(Paragraph("No plain-text web links were extracted.", styles["BodyText"]))
    story += [Spacer(1, 3 * mm), Paragraph("4. Findings", styles["Heading2"])]
    if result["findings"]:
        rows = [["Points", "Indicator", "Evidence"]]
        rows += [[str(p), label, detail] for p, label, detail in result["findings"]]
        finding_table = Table(
            [[Paragraph(str(c), styles["Small"]) for c in row] for row in rows],
            colWidths=[16 * mm, 48 * mm, 104 * mm], repeatRows=1
        )
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FCE4D6")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(finding_table)
    else:
        story.append(Paragraph("No indicators were triggered by the configured checks.", styles["BodyText"]))
    story += [
        Spacer(1, 4 * mm),
        Paragraph("5. Recommended action", styles["Heading2"]),
        Paragraph(
            "Do not click links, open unexpected attachments, or provide credentials based only on this email. "
            "Verify requests using a known official website or phone number. Ask the mail administrator to "
            "review full authentication results and message routing when necessary.",
            styles["BodyText"]
        ),
        Spacer(1, 3 * mm),
        Paragraph(
            "<b>Method and limitation:</b> This report uses rule-based indicators and a capped 0–100 score. "
            "SPF/DKIM/DMARC results are read from headers; the script does not independently validate DNS, "
            "cryptographic signatures, sender identity, or destination websites. Missing headers are not "
            "proof of phishing, and a low score does not guarantee safety.",
            styles["Small"]
        ),
    ]
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm)
    doc.build(story)


def main():
    parser = argparse.ArgumentParser(description="Scan a raw .eml email for phishing indicators.")
    parser.add_argument("email_file", help="Path to a raw email file (.eml)")
    parser.add_argument("--report", default="phishing_analysis_report.pdf",
                        help="Output PDF report filename (default: phishing_analysis_report.pdf)")
    args = parser.parse_args()

    try:
        result = analyze_email(args.email_file)
        create_pdf(result, args.report)
    except FileNotFoundError:
        print(f"Error: file not found: {args.email_file}")
        sys.exit(1)
    except Exception as exc:
        print(f"Analysis failed: {exc}")
        sys.exit(1)

    print("\n========== EMAIL SECURITY ANALYSIS ==========")
    print("Subject :", result["subject"])
    print("From    :", result["from"])
    print("Risk    :", f"{result['score']}/100")
    print("Verdict :", result["verdict"])
    print("\nFindings:")
    if result["findings"]:
        for points, label, detail in result["findings"]:
            print(f"  [+{points}] {label}: {detail}")
    else:
        print("  No configured indicators detected.")
    print(f"\nPDF report saved to: {args.report}")


if __name__ == "__main__":
    main()
