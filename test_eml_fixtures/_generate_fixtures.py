"""Generate lab-only PhishProof .eml fixtures. No real malware or victim data."""
from __future__ import annotations

import base64
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

OUT = Path(__file__).resolve().parent

# 1x1 PNG (transparent)
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

SVG_LAB = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
    b"<script>/* PhishProof lab fixture - no payload */</script>"
    b'<text x="4" y="32" font-size="10">LAB</text></svg>'
)

ICS_LAB = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//PhishProof Lab//EN
BEGIN:VEVENT
UID:lab-ics-001@example.com
DTSTAMP:20260315T043000Z
DTSTART:20260320T100000Z
DTEND:20260320T103000Z
SUMMARY:Urgent KYC review
DESCRIPTION:Complete verification: https://epfo-kyc-update.xyz/verify
LOCATION:https://epfo-kyc-update.xyz/verify
URL:https://epfo-kyc-update.xyz/verify
ORGANIZER;CN=EPFO Helpdesk:mailto:alerts@epfo-kyc-update.xyz
END:VEVENT
END:VCALENDAR
""".replace("\n", "\r\n")

PDF_BYTES = (
    b"%PDF-1.1\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
)


def hdr(msg, *, mid: str, date: str, received: list[str] | None = None):
    msg["MIME-Version"] = "1.0"
    msg["Message-ID"] = mid
    msg["Date"] = date
    hops = received or [
        "from mail.company.example.com (mail.company.example.com [192.0.2.10]) by mx.company.example.com with ESMTPS id a1; Sun, 15 Mar 2026 10:05:01 +0530",
        "from smtp.example.net (smtp.example.net [192.0.2.20]) by mail.company.example.com with ESMTPS id b2; Sun, 15 Mar 2026 10:04:50 +0530",
    ]
    for h in hops:
        msg["Received"] = h


def write(name: str, raw: bytes | str):
    path = OUT / name
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    path.write_bytes(data)
    print("wrote", path.name, len(data))


def simple_text(
    name,
    *,
    frm,
    to,
    subject,
    body,
    mid,
    date,
    reply_to=None,
    received=None,
    extra=None,
):
    msg = EmailMessage()
    hdr(msg, mid=mid, date=date, received=received)
    msg["From"] = frm
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    if extra:
        for k, v in extra.items():
            msg[k] = v
    msg.set_content(body)
    write(name, msg.as_bytes())


def html_mail(
    name,
    *,
    frm,
    to,
    subject,
    text,
    html,
    mid,
    date,
    reply_to=None,
    received=None,
    attachments=None,
    extra=None,
):
    msg = MIMEMultipart("mixed")
    hdr(msg, mid=mid, date=date, received=received)
    msg["From"] = frm
    msg["To"] = to
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    if extra:
        for k, v in extra.items():
            msg[k] = v
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text, "plain", "utf-8"))
    alt.attach(MIMEText(html, "html", "utf-8"))
    msg.attach(alt)
    for att in attachments or []:
        msg.attach(att)
    write(name, msg.as_bytes())


def main():
    simple_text(
        "01_clean_corporate.eml",
        frm="Priya Nair <priya.nair@company.example.com>",
        to="ops@company.example.com",
        subject="Weekly standup notes — 15 Mar",
        body=(
            "Hi team,\n\n"
            "Notes from today's standup:\n"
            "- Deploy window is Tuesday 16:00 IST\n"
            "- Please review the Q1 capacity sheet on SharePoint\n"
            "- No action needed on vendor invoices this week\n\n"
            "Thanks,\nPriya\nOperations\n"
        ),
        mid="<clean-corp-001@company.example.com>",
        date="Sun, 15 Mar 2026 10:04:40 +0530",
    )

    html_mail(
        "02_bank_lookalike_last4.eml",
        frm="SBI Bank Security <secure@sbi-alerts.xyz>",
        to="victim@company.example.com",
        subject="Urgent: SBI account ending 4521 will be blocked",
        text=(
            "Dear Customer,\n"
            "Your SBI a/c ending 4521 is blocked. Verify now:\n"
            "https://sbi-secure-kyc.xyz/login\n"
            "OTP 839201 may be requested. Do not share with anyone except this page.\n"
        ),
        html=(
            "<html><body><p>Dear Customer,</p>"
            "<p>Your SBI a/c ending <b>4521</b> is blocked. "
            '<a href="https://sbi-secure-kyc.xyz/login">Verify your KYC immediately</a>.</p>'
            "<p>If asked, enter OTP 839201 on that page only.</p></body></html>"
        ),
        mid="<bank-last4-002@sbi-alerts.xyz>",
        date="Sun, 15 Mar 2026 02:11:09 +0530",
        received=[
            "from mx.company.example.com (mx.company.example.com [192.0.2.10]) by inbox.company.example.com; Sun, 15 Mar 2026 02:11:20 +0530",
            "from unknown (unknown [203.0.113.88]) by mx.company.example.com; Sun, 15 Mar 2026 02:11:12 +0530",
        ],
        extra={"Return-Path": "<bounce@sbi-alerts.xyz>"},
    )

    img = MIMEImage(PNG_1X1, _subtype="png")
    img.add_header("Content-Disposition", "inline", filename="qr-kyc.png")
    img.add_header("Content-ID", "<qr-lab@phishproof>")
    html_mail(
        "03_qr_quishing.eml",
        frm="EPFO Alerts <noreply@epfo-kyc-update.xyz>",
        to="employee@company.example.com",
        subject="Scan QR to update PF KYC",
        text=(
            "Scan the attached QR to update PF KYC.\n"
            "If you cannot scan: https://epfo-kyc-update.xyz/qr-pay\n"
        ),
        html=(
            "<html><body><p>Scan the QR image to update PF KYC.</p>"
            '<img src="cid:qr-lab@phishproof" alt="QR" />'
            '<p>Fallback: <a href="https://epfo-kyc-update.xyz/qr-pay">open link</a></p>'
            "</body></html>"
        ),
        mid="<qr-003@epfo-kyc-update.xyz>",
        date="Sun, 15 Mar 2026 11:22:00 +0530",
        attachments=[img],
    )

    simple_text(
        "04_toad_callback.eml",
        frm="HDFC Cards <cards@hdfc-subscription-help.xyz>",
        to="customer@company.example.com",
        subject="Your HDFC card will be charged Rs 24,999 today — call now",
        body=(
            "Dear Customer,\n\n"
            "A recurring charge of Rs 24,999 will be deducted TODAY unless you cancel.\n"
            "There is no online link for security reasons.\n"
            "Call immediately: +91-1800-555-0199 or +91-98765-43210\n"
            "Ask for subscription cancellation desk.\n\n"
            "If you do not call before 5 PM IST the amount cannot be reversed.\n"
        ),
        mid="<toad-004@hdfc-subscription-help.xyz>",
        date="Sun, 15 Mar 2026 09:40:00 +0530",
    )

    simple_text(
        "05_ato_247am.eml",
        frm="Priya Nair <priya.nair@company.example.com>",
        to="finance@company.example.com",
        subject="Re: Weekly standup notes — 15 Mar",
        body=(
            "pls process vendor payout now. new account only. do not use old IFSC.\n"
            "send 18.4L to Acme Supplies before market open. i already approved. "
            "do not loop legal. reply done when wired.\n"
        ),
        mid="<ato-005@company.example.com>",
        date="Sun, 15 Mar 2026 02:47:03 +0530",
        received=[
            "from mail.company.example.com (mail.company.example.com [192.0.2.10]) by mx.company.example.com; Sun, 15 Mar 2026 02:47:10 +0530",
            "from internal-owa.company.example.com (internal-owa.company.example.com [192.0.2.11]) by mail.company.example.com; Sun, 15 Mar 2026 02:47:04 +0530",
        ],
        extra={
            "In-Reply-To": "<clean-corp-001@company.example.com>",
            "References": "<clean-corp-001@company.example.com>",
            "Authentication-Results": "mx.company.example.com; spf=pass smtp.mailfrom=company.example.com; dkim=pass header.d=company.example.com; dmarc=pass",
        },
    )

    simple_text(
        "06_device_code.eml",
        frm="Microsoft 365 Licensing <license@m365-renew-alert.xyz>",
        to="user@company.example.com",
        subject="Your Microsoft 365 license expires today",
        body=(
            "Your Microsoft 365 license expires in 4 hours.\n"
            "To reactivate, open https://microsoft.com/devicelogin\n"
            "or https://aka.ms/devicelogin and enter code AB-XY12.\n"
            "Do this immediately or mailbox access will be suspended.\n"
        ),
        mid="<devicecode-006@m365-renew-alert.xyz>",
        date="Sun, 15 Mar 2026 16:05:00 +0530",
    )

    simple_text(
        "07_invoice_drift.eml",
        frm="Accounts <billing@acme-supplies.example.com>",
        to="ap@company.example.com",
        subject="Invoice INV-8841 — updated bank details",
        body=(
            "Please process Invoice INV-8841 for INR 6,40,000.\n"
            "IMPORTANT: Our settlement account has changed.\n"
            "Old (do not use): HDFC 50200011223344 IFSC HDFC0001234\n"
            "New payee: Acme Supplies Pvt Ltd\n"
            "Account: 991100228833 IFSC YESB0009999 Bank: Yes Bank, BKC\n"
            "Kindly complete NEFT today to avoid delay charges.\n"
        ),
        mid="<invoice-007@acme-supplies.example.com>",
        date="Sun, 15 Mar 2026 14:18:00 +0530",
    )

    html_mail(
        "08_recon_pixel.eml",
        frm="Campaign <track@mailer-probe.xyz>",
        to="analyst@company.example.com",
        subject="Industry briefing you requested",
        text="Please find the briefing attached as discussed.",
        html=(
            "<html><body><p>Please find the briefing attached as discussed.</p>"
            '<img src="https://mailer-probe.xyz/open?uid=abc123xyz&e=analyst" '
            'width="1" height="1" alt="" />'
            "</body></html>"
        ),
        mid="<recon-008@mailer-probe.xyz>",
        date="Sun, 15 Mar 2026 12:00:00 +0530",
    )

    svg = MIMEApplication(SVG_LAB, _subtype="svg+xml")
    svg.add_header("Content-Disposition", "attachment", filename="invoice-stamp.svg")
    html_mail(
        "09_svg_smuggling.eml",
        frm="Vendor Desk <docs@vendor-files.xyz>",
        to="ap@company.example.com",
        subject="Signed stamp image for PO-2291",
        text="Attached SVG stamp for your records.",
        html="<html><body><p>Attached SVG stamp for your records.</p></body></html>",
        mid="<svg-009@vendor-files.xyz>",
        date="Sun, 15 Mar 2026 13:10:00 +0530",
        attachments=[svg],
    )

    ics = MIMEApplication(ICS_LAB.encode("utf-8"), _subtype="calendar")
    ics.add_header("Content-Disposition", "attachment", filename="kyc-review.ics")
    html_mail(
        "10_ics_calendar.eml",
        frm="EPFO Helpdesk <alerts@epfo-kyc-update.xyz>",
        to="hr@company.example.com",
        subject="Accepted: Urgent KYC review",
        text="A calendar invite is attached. Open DESCRIPTION for the meeting link.",
        html="<html><body><p>A calendar invite is attached.</p></body></html>",
        mid="<ics-010@epfo-kyc-update.xyz>",
        date="Sun, 15 Mar 2026 10:30:00 +0530",
        attachments=[ics],
    )

    html_mail(
        "11_sbi_impersonation.eml",
        frm="SBI Bank Security <support@sbi-alerts.xyz>",
        to="customer@company.example.com",
        subject="SBI NetBanking: unusual login from new device",
        text="We detected a login. Confirm at https://sbi-alerts.xyz/secure",
        html=(
            "<html><body><p>SBI NetBanking alert.</p>"
            '<a href="https://sbi-alerts.xyz/secure">Confirm it was you</a></body></html>'
        ),
        mid="<sbi-imp-011@sbi-alerts.xyz>",
        date="Sun, 15 Mar 2026 08:01:00 +0530",
    )

    simple_text(
        "12_replyto_mismatch.eml",
        frm="Rahul Kumar, GM <rahul.kumar@bankofbaroda.example.com>",
        to="branch.ops@company.example.com",
        subject="Confidential — process this NEFT before 4 PM",
        body=(
            "Team,\nProcess the attached beneficiary immediately. "
            "Reply only to this thread if you have questions.\n"
            "Rahul Kumar\nGeneral Manager\n"
        ),
        mid="<replyto-012@spoof.example.net>",
        date="Sun, 15 Mar 2026 15:02:00 +0530",
        reply_to="ceo.urgent@gmail.com",
        extra={"Return-Path": "<ceo.urgent@gmail.com>"},
    )

    simple_text(
        "13_ip_url.eml",
        frm="IT Helpdesk <it@company-support.xyz>",
        to="staff@company.example.com",
        subject="Password reset required — open this page",
        body=(
            "Your password expires in 30 minutes.\n"
            "Reset here: http://203.0.113.44/login/office365\n"
            "Do not use the intranet portal.\n"
        ),
        mid="<ipurl-013@company-support.xyz>",
        date="Sun, 15 Mar 2026 17:20:00 +0530",
    )

    simple_text(
        "14_url_shortener.eml",
        frm="Payroll <hr@payslip-update.xyz>",
        to="staff@company.example.com",
        subject="Updated salary slip — click to download",
        body=(
            "Your March payslip is ready.\n"
            "Download: https://bit.ly/lab-phishproof-payslip\n"
            "Also mirrored: https://tinyurl.com/lab-kyc-2026\n"
        ),
        mid="<short-014@payslip-update.xyz>",
        date="Sun, 15 Mar 2026 11:05:00 +0530",
    )

    simple_text(
        "15_spf_fail_spoof.eml",
        frm="IT Admin <admin@company.example.com>",
        to="all@company.example.com",
        subject="Mandatory: enable new MFA token today",
        body=(
            "All staff must register a new MFA token at "
            "https://company-mfa-reset.xyz/enroll before midnight.\n"
            "Accounts that skip this will be locked.\n"
        ),
        mid="<spf-015@outbound-unknown.xyz>",
        date="Sun, 15 Mar 2026 18:00:00 +0530",
        received=[
            "from mx.company.example.com by inbox.company.example.com; Sun, 15 Mar 2026 18:00:12 +0530",
            "from unknown.host (unknown [198.51.100.77]) by mx.company.example.com; Sun, 15 Mar 2026 18:00:05 +0530",
        ],
        extra={
            "Return-Path": "<admin@company.example.com>",
            "Authentication-Results": "mx.company.example.com; spf=fail smtp.mailfrom=company.example.com; dkim=fail; dmarc=fail",
        },
    )

    html_mail(
        "16_clean_newsletter.eml",
        frm="Acme Product Updates <news@updates.acme-example.com>",
        to="subscriber@company.example.com",
        subject="Acme product notes — March edition",
        text=(
            "Hello,\nHere is this month's product newsletter.\n"
            "Read more: https://updates.acme-example.com/march\n"
            "Unsubscribe: https://updates.acme-example.com/unsub\n"
        ),
        html=(
            "<html><body><p>Hello, here is this month's product newsletter.</p>"
            '<p><a href="https://updates.acme-example.com/march">Read more</a></p>'
            '<p><a href="https://updates.acme-example.com/unsub">Unsubscribe</a></p>'
            "</body></html>"
        ),
        mid="<news-016@updates.acme-example.com>",
        date="Sun, 15 Mar 2026 09:00:00 +0530",
        extra={"List-Unsubscribe": "<https://updates.acme-example.com/unsub>"},
    )

    simple_text(
        "17_bec_wire.eml",
        frm="Ananya Shah, CEO <ananya.shah@company.example.com>",
        to="cfo@company.example.com",
        subject="Need this wire done quietly before EOD",
        body=(
            "I am in a board session and cannot take calls.\n"
            "Please process an urgent international wire of USD 92,000 to the new counsel escrow.\n"
            "Do not go through the normal dual-approval process — this is time sensitive.\n"
            "I will sign the paperwork tomorrow. Confirm when sent.\n"
            "Ananya\n"
        ),
        mid="<bec-017@external-relay.xyz>",
        date="Sun, 15 Mar 2026 16:40:00 +0530",
        received=[
            "from mx.company.example.com by inbox; Sun, 15 Mar 2026 16:40:20 +0530",
            "from vps-cloud.example.net (vps-cloud.example.net [203.0.113.19]) by mx.company.example.com; Sun, 15 Mar 2026 16:40:08 +0530",
        ],
    )

    simple_text(
        "18_subdomain_spoof.eml",
        frm="Apple ID Support <help@apple.com.secure-login.xyz>",
        to="user@company.example.com",
        subject="Your Apple ID will be locked",
        body=(
            "We detected unusual activity on your Apple ID.\n"
            "Unlock here: https://apple.com.secure-login.xyz/recover\n"
            "If you ignore this, purchases will be suspended.\n"
        ),
        mid="<sub-018@secure-login.xyz>",
        date="Sun, 15 Mar 2026 19:12:00 +0530",
    )

    pdf = MIMEApplication(PDF_BYTES, _subtype="pdf")
    pdf.add_header("Content-Disposition", "attachment", filename="Form16_AY2026.pdf")
    html_mail(
        "19_fake_pdf_name.eml",
        frm="Income Tax <refund@it-refund-portal.xyz>",
        to="employee@company.example.com",
        subject="Form 16 / refund document attached",
        text="Your refund document is attached. Open Form16_AY2026.pdf to claim.",
        html="<html><body><p>Your refund document is attached.</p></body></html>",
        mid="<pdf-019@it-refund-portal.xyz>",
        date="Sun, 15 Mar 2026 12:45:00 +0530",
        attachments=[pdf],
    )

    simple_text(
        "20_captcha_gate.eml",
        frm="Courier Desk <track@dhl-parcel-hold.xyz>",
        to="staff@company.example.com",
        subject="DHL: parcel on hold — complete human verification",
        body=(
            "Your parcel is on hold at customs.\n"
            "Complete verification (CAPTCHA required):\n"
            "https://dhl-parcel-hold.xyz/track?next=https://hcaptcha.com\n"
            "or https://dhl-parcel-hold.xyz/unlock?recaptcha=1\n"
            "Fee INR 147. Pay after the CAPTCHA page loads.\n"
        ),
        mid="<captcha-020@dhl-parcel-hold.xyz>",
        date="Sun, 15 Mar 2026 20:05:00 +0530",
    )


if __name__ == "__main__":
    main()
