# PhishProof lab `.eml` fixtures

Synthetic test mail only. Fake domains (`.xyz`, `example.com`), fake last-4 `4521`, fake OTP `839201`. **Do not send these to real people or real banks.**

**Folder:** `E:\SIH\test_eml_fixtures\`  
**Copy (if present):** `D:\SMTP_NEW_PROJECT\test_eml_fixtures\`

## How to use

1. SOC / Model Lab: upload the `.eml` file.
2. Or drop into the gateway ingest / mailbox compose path.
3. Privacy check on **02**: UI/report should show `[ACCT_LAST4]` / `[OTP]`, not `4521` / `839201`.

Expected verdicts assume PhishProof detectors from `PHISHPROOF_COMPLETE_FINAL.md`. Heuristic-only builds may differ.

| File | Scenario | Expected (approx.) |
|---|---|---|
| `01_clean_corporate.eml` | Internal standup notes | `PASS` |
| `02_bank_lookalike_last4.eml` | SBI display name + `sbi-alerts.xyz` + last-4 + OTP | `HARD_BLOCK` |
| `03_qr_quishing.eml` | QR-style image + EPFO lure URL | `BLOCK` |
| `04_toad_callback.eml` | Urgency + phone, no link | `QUARANTINE` |
| `05_ato_247am.eml` | Trusted Priya reply at 02:47 IST, style drift | `HUMAN_REVIEW` |
| `06_device_code.eml` | `microsoft.com/devicelogin` + code `AB-XY12` | `QUARANTINE` / `BLOCK` |
| `07_invoice_drift.eml` | Vendor invoice, changed IFSC/account | `QUARANTINE` / `BLOCK` |
| `08_recon_pixel.eml` | 1×1 tracking image | `SOFT_PASS` / `QUARANTINE` |
| `09_svg_smuggling.eml` | SVG with `<script>` (lab comment only) | `BLOCK` / `QUARANTINE` |
| `10_ics_calendar.eml` | `.ics` with phishing URL in DESCRIPTION | `BLOCK` |
| `11_sbi_impersonation.eml` | Display-name SBI vs `sbi-alerts.xyz` | `HARD_BLOCK` |
| `12_replyto_mismatch.eml` | GM From + `Reply-To: gmail.com` | `QUARANTINE` / `BLOCK` |
| `13_ip_url.eml` | `http://203.0.113.44/login/office365` | `BLOCK` |
| `14_url_shortener.eml` | bit.ly / tinyurl payslip | `QUARANTINE` / `BLOCK` |
| `15_spf_fail_spoof.eml` | Claims `@company.example.com`, SPF/DKIM/DMARC fail | `HARD_BLOCK` / `BLOCK` |
| `16_clean_newsletter.eml` | Legitimate list mail + unsubscribe | `PASS` / `SOFT_PASS` |
| `17_bec_wire.eml` | CEO voice, wire, skip dual-approval, no link | `QUARANTINE` / `HUMAN_REVIEW` |
| `18_subdomain_spoof.eml` | `apple.com.secure-login.xyz` | `BLOCK` |
| `19_fake_pdf_name.eml` | Harmless tiny PDF named Form16 | `QUARANTINE` / `SOFT_PASS` (name + domain) |
| `20_captcha_gate.eml` | Parcel lure + hCaptcha/reCAPTCHA in URL | `BLOCK` / `QUARANTINE` |

Regenerate: `python _generate_fixtures.py`
