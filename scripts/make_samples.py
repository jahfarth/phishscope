"""Regenerate the synthetic .eml corpus in samples/.

Every sample is fabricated: reserved domains (example.com / .example /
.invalid per RFC 2606+), fake addresses, no real payloads. Safe to commit,
safe to open. Run from the repo root:  python scripts/make_samples.py
"""

from email.message import EmailMessage
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def eml(filename, subject, from_hdr, to, reply_to=None, return_path=None,
        auth="", received=None, text="", html=None, attachments=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_hdr
    msg["To"] = to
    msg["Date"] = "Fri, 06 Nov 2026 09:00:00 +0530"
    msg["Message-ID"] = f"<{filename}@samples.phishscope>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = f"<{return_path}>"
    if auth:
        msg["Authentication-Results"] = auth
    for i, hop in enumerate(received or []):
        msg["Received"] = hop  # EmailMessage allows duplicates for this header
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for fname in attachments or []:
        msg.add_attachment(b"synthetic placeholder - not a real file",
                           maintype="application", subtype="octet-stream",
                           filename=fname)
    (SAMPLES / filename).write_bytes(bytes(msg))
    print(f"wrote {filename}")


GOOD_AUTH = ("mx.example.com; spf=pass smtp.mailfrom={rp}; "
             "dkim=pass header.d={d}; dmarc=pass header.from={d}")
BAD_AUTH = ("mx.example.com; spf=fail smtp.mailfrom={rp}; "
            "dkim=fail header.d={d}; dmarc=fail header.from={d}")
SOFT_AUTH = ("mx.example.com; spf=softfail smtp.mailfrom={rp}; "
             "dkim=none; dmarc=none")


def main():
    SAMPLES.mkdir(exist_ok=True)
    for old in SAMPLES.glob("*.eml"):
        old.unlink()

    # ---------------- phishing ----------------
    eml("phishing_01_paylookalike.eml",
        "URGENT: Your account has been suspended - verify within 24 hours",
        "PayPal Security <security@paypa1-secure.example>",
        "victim@example.com",
        reply_to="payments@paypa1-billing.example",
        return_path="bounce@paypa1-secure.example",
        auth=BAD_AUTH.format(rp="paypa1-secure.example", d="paypa1-secure.example"),
        received=["from mail.paypa1-secure.example (203.0.113.44) by mx.example.com"],
        text=("Dear customer,\n\nWe detected unusual sign-in activity on your account. "
              "Your account has been suspended. Verify your account immediately or it "
              "will be closed within 24 hours.\n\nConfirm your password and billing "
              "information here:\nhttps://paypa1-secure.example/verify?session=9f2\n\n"
              "PayPal Security Team"))

    eml("phishing_02_credharvest.eml",
        "Unusual sign-in attempt - action required",
        "Microsoft Account Team <no-reply@microsoft-alerts.example>",
        "victim@example.com",
        return_path="bounce@microsoft-alerts.example",
        auth=BAD_AUTH.format(rp="mailhost.example", d="microsoft-alerts.example"),
        text=("We blocked an unusual sign-in to your Microsoft account from "
              "Moscow, Russia. If this was not you, verify your identity now:\n\n"
              "https://microsoft-alerts.example/signin/verify\n\n"
              "You will need your login and one-time password.\n\nMicrosoft"))

    eml("phishing_03_macrodoc.eml",
        "Invoice INV-2026-4471 due - FINAL NOTICE",
        "Accounts Receivable <billing@acme-supplies.example>",
        "finance@example.com",
        reply_to="collections@fastpay-settle.example",
        auth=SOFT_AUTH.format(rp="acme-supplies.example", d="acme-supplies.example"),
        text=("Final notice: invoice INV-2026-4471 for $4,290.00 is overdue. "
              "Open the attached document and follow the payment link to avoid "
              "late fees.\nhttps://fastpay-settle.example/pay/inv-2026-4471"),
        attachments=["INV-2026-4471.pdf.exe"])

    eml("phishing_04_iplink.eml",
        "Your package could not be delivered",
        "DHL Express <tracking@dhl-dispatch.example>",
        "victim@example.com",
        auth=BAD_AUTH.format(rp="dhl-dispatch.example", d="dhl-dispatch.example"),
        text=("Your parcel is on hold. Confirm your address and pay the $1.99 "
              "redelivery fee here:\nhttp://198.51.100.77/dhl/redelivery.php\n"
              "This offer expires today."))

    eml("phishing_05_shortener.eml",
        "You have (1) pending document",
        "DocuSign <dse@docusign-eu.example>",
        "victim@example.com",
        auth=SOFT_AUTH.format(rp="docusign-eu.example", d="docusign-eu.example"),
        html=('<html><body><p>A document is waiting for your signature.</p>'
              '<p><a href="https://bit.ly/3xK9mQ2">Review document</a></p></body></html>'),
        text="A document is waiting: https://bit.ly/3xK9mQ2")

    eml("phishing_06_userinfo.eml",
        "Password expiry notice",
        "IT Helpdesk <helpdesk@company-it.example>",
        "victim@example.com",
        auth=BAD_AUTH.format(rp="company-it.example", d="company-it.example"),
        text=("Your password expires today. Keep your current password by "
              "logging in here:\nhttps://portal.company.example@evil-login.example/keep\n"
              "IT Helpdesk"))

    eml("phishing_07_caps.eml",
        "FINAL WARNING YOUR ACCOUNT WILL BE CLOSED",
        "Netflix Billing <billing@netfl1x-pay.example>",
        "victim@example.com",
        auth=BAD_AUTH.format(rp="netfl1x-pay.example", d="netfl1x-pay.example"),
        text=("We were unable to charge your card. Update your payment method "
              "immediately or lose access:\nhttps://netfl1x-pay.example/billing\n"
              "Enter your card number and security code."))

    eml("phishing_08_punycode.eml",
        "Apple ID receipt - purchase confirmation",
        "Apple <no-reply@xn--pple-43d.example>",
        "victim@example.com",
        reply_to="refunds@apple-billing.example",
        auth=SOFT_AUTH.format(rp="xn--pple-43d.example", d="xn--pple-43d.example"),
        text=("Thank you for your purchase of $99.99. If you did not authorise "
              "this, cancel within 24 hours or the charge is final:\n"
              "https://xn--pple-43d.example/cancel\n"
              "You will need your card number to confirm the refund.\nApple Support"))

    eml("phishing_09_ceofraud.eml",
        "Quick favor - are you at your desk?",
        "Rajesh Menon <rajesh.menon@company-executives.example>",
        "victim@example.com",
        reply_to="rajesh.menon.director@gmail.example",
        auth=SOFT_AUTH.format(rp="company-executives.example", d="company-executives.example"),
        text=("I am in a meeting and need you to urgently purchase 5x $100 "
              "gift cards for a client. Reply with the codes. Act now - "
              "I need them within the hour."))

    eml("phishing_10_crypto.eml",
        "Your withdrawal is pending - verify wallet",
        "Coinbase Support <support@coinbase-verify.example>",
        "victim@example.com",
        auth=BAD_AUTH.format(rp="coinbase-verify.example", d="coinbase-verify.example"),
        text=("A withdrawal of 1.42 BTC is pending. Verify your identity to "
              "release the funds:\nhttps://coinbase-verify.example/wallet/confirm\n"
              "You will be asked for your login and security code."))

    # ---------------- legitimate ----------------
    eml("legit_01_newsletter.eml",
        "Your weekly digest: 5 new posts",
        "Dev Weekly <newsletter@devweekly.example>",
        "victim@example.com",
        return_path="bounces@devweekly.example",
        auth=GOOD_AUTH.format(rp="devweekly.example", d="devweekly.example"),
        received=["from mail.devweekly.example (192.0.2.10) by mx.example.com"],
        text=("Hi! Here are this week's top posts:\n"
              "- https://devweekly.example/posts/101\n"
              "- https://devweekly.example/posts/102\n"
              "Unsubscribe: https://devweekly.example/unsub"))

    eml("legit_02_invoice.eml",
        "Your receipt for order #4471",
        "ACME Store <orders@acme.example>",
        "victim@example.com",
        return_path="orders@acme.example",
        auth=GOOD_AUTH.format(rp="acme.example", d="acme.example"),
        text=("Thanks for your order! Total: $49.99.\n"
              "Track it here: https://acme.example/orders/4471\n"
              "Your invoice PDF is attached."),
        attachments=["invoice-4471.pdf"])

    eml("legit_03_meeting.eml",
        "Re: Sprint planning moved to 3pm",
        "Priya Sharma <priya.sharma@corp.example>",
        "victim@example.com",
        auth=GOOD_AUTH.format(rp="corp.example", d="corp.example"),
        received=["from mail.corp.example (192.0.2.20) by mx.example.com",
                  "from relay.corp.example (192.0.2.21) by mail.corp.example"],
        text=("Hi,\n\nSprint planning moved to 3pm in room 4B. "
              "Agenda: https://corp.example/wiki/sprint-22\n\nThanks,\nPriya"))

    eml("legit_04_alert.eml",
        "New sign-in to your account",
        "Example Mail <no-reply@examplemail.example>",
        "victim@example.com",
        return_path="no-reply@examplemail.example",
        auth=GOOD_AUTH.format(rp="examplemail.example", d="examplemail.example"),
        text=("Hi,\n\nWe noticed a new sign-in from Chrome on Windows at "
              "9:02 AM IST. This was you, so no action is needed.\n"
              "Review devices: https://examplemail.example/security/devices"))

    eml("legit_05_bank.eml",
        "Your October statement is ready",
        "First Example Bank <statements@firstexamplebank.example>",
        "victim@example.com",
        auth=GOOD_AUTH.format(rp="firstexamplebank.example", d="firstexamplebank.example"),
        text=("Your October e-statement is ready in online banking. "
              "Sign in at https://firstexamplebank.example/login to view it.\n"
              "We never ask for passwords by email."))

    eml("legit_06_github.eml",
        "[sentinelx] Pull request merged",
        "GitHub <notifications@github.example>",
        "victim@example.com",
        auth=GOOD_AUTH.format(rp="github.example", d="github.example"),
        received=["from smtp.github.example (192.0.2.30) by mx.example.com"],
        text=("Pull request #14 was merged into main.\n"
              "View it: https://github.example/jahfarth/sentinelx/pull/14"))


if __name__ == "__main__":
    main()
