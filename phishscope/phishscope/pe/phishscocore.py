"""Core .eml parsing and indicator extraction.

Everything here is stdlib-only so the analyser runs anywhere Python 3.9+
runs. All network intelligence (who owns a domain, live DNS) is out of
scope on purpose: PhishScope is a *static* triage tool, safe to run on
hostile samples.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>'\")\]]+", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

# Brands most commonly impersonated in phishing lures. Matching is done on
# the registrable label only, never on arbitrary substrings of the address.
BRANDS = (
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "dhl", "fedex", "ups",
    "coinbase", "binance", "irs", "chase", "wellsfargo", "dropbox",
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".jar", ".msi", ".dll", ".com", ".pif", ".hta", ".cpl",
    ".iso", ".img", ".wsf",
}

# Homoglyph folding for lookalike detection: paypa1 -> paypal, micr0soft -> microsoft
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a",
                            "5": "s", "7": "t", "8": "b", "@": "a"})

URGENCY_PHRASES = (
    "urgent", "immediately", "within 24 hours", "within 48 hours",
    "account suspended", "account has been suspended", "account will be closed",
    "unusual sign-in", "unusual activity", "verify your account",
    "final notice", "last warning", "act now", "limited time",
    "expires today", "suspended", "locked", "on hold",
)

CREDENTIAL_PHRASES = (
    "confirm your password", "verify your identity", "update your payment",
    "login", "log in", "credentials", "social security", "ssn",
    "bank account", "one-time password", "otp", "security code", "gift card",
    "confirm your identity", "billing information", "card number",
)


def levenshtein(a: str, b: str) -> int:
    """Small iterative Levenshtein distance (no numpy needed)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_label(domain: str) -> str:
    """Best-effort registrable label (second-level) of a hostname.

    Deliberately naive: co.uk-style suffixes are not special-cased because
    triage only needs a stable comparison key, not a perfect PSL match.
    """
    domain = (domain or "").strip(".").lower()
    if not domain:
        return ""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


@dataclass
class AuthResults:
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    raw: str = ""


@dataclass
class EmailArtifact:
    """A parsed email plus every indicator the rest of the pipeline needs."""
    path: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    auth: AuthResults = field(default_factory=AuthResults)
    received: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    url_domains: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    num_recipients: int = 0

    # ---- derived indicators -------------------------------------------------
    @property
    def from_label(self) -> str:
        return registered_label(self.from_domain)

    def domain_is_ip(self, domain: str) -> bool:
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    @property
    def ip_urls(self) -> list:
        return [u for u in self.urls if self.domain_is_ip(urlparse(u).hostname or "")]

    @property
    def shortener_urls(self) -> list:
        return [u for u in self.urls if (urlparse(u).hostname or "").lower() in URL_SHORTENERS]

    @property
    def punycode_urls(self) -> list:
        return [u for u in self.urls if "xn--" in (urlparse(u).hostname or "").lower()]

    @property
    def at_urls(self) -> list:
        """URLs carrying userinfo (https://trusted.com@evil.example/) - a classic cloaking trick."""
        return [u for u in self.urls if "@" in (urlparse(u).netloc or "")]

    @property
    def mismatched_url_domains(self) -> list:
        fl = self.from_label
        return sorted({registered_label(d) for d in self.url_domains
                       if fl and registered_label(d) and registered_label(d) != fl})

    @property
    def dangerous_attachments(self) -> list:
        return [f for f in self.attachments
                if any(f.lower().endswith(ext) for ext in DANGEROUS_EXTS)]

    @property
    def double_ext_attachments(self) -> list:
        out = []
        for f in self.attachments:
            name = f.lower()
            for ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".jpg", ".png", ".txt"):
                if any(name.endswith(ext + d) for d in DANGEROUS_EXTS):
                    out.append(f)
                    break
        return out

    @property
    def urgency_hits(self) -> int:
        text = (self.subject + " " + self.body_text).lower()
        return sum(text.count(p) for p in URGENCY_PHRASES)

    @property
    def credential_hits(self) -> int:
        text = self.body_text.lower()
        return sum(text.count(p) for p in CREDENTIAL_PHRASES)

    @property
    def caps_subject(self) -> bool:
        letters = [c for c in self.subject if c.isalpha()]
        return len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7

    @property
    def display_name_spoof(self) -> Optional[str]:
        """Brand name in the display name but not in the sender domain."""
        name = self.from_name.lower()
        for brand in BRANDS:
            if brand in name and brand not in self.from_domain:
                return brand
        return None

    @property
    def lookalike_domain(self) -> Optional[str]:
        """Brand lookalike in the registrable label (paypa1, microsft, secure-paypal).

        Brands are matched on hyphen/dot-separated tokens or a close edit
        distance, never as bare substrings - "irs" inside "firstexamplebank"
        is not an IRS lure.
        """
        label = self.from_label
        if not label:
            return None
        tokens = [t for t in re.split(r"[^a-z0-9@]+", label) if t]
        folded = label.translate(HOMOGLYPHS)
        folded_tokens = [t.translate(HOMOGLYPHS) for t in tokens]
        for brand in BRANDS:
            if label == brand:
                return None
            if brand in tokens:
                return brand
            if folded_tokens != tokens and brand in folded_tokens:
                return brand
            if 0 < levenshtein(label, brand) <= 2:
                return brand
            if folded != label and any(0 < levenshtein(ft, brand) <= 1
                                       for ft in folded_tokens):
                return brand
        return None


def _domain_of(address: str) -> str:
    return address.split("@")[-1].strip().lower() if "@" in address else ""


def _parse_auth_results(headers) -> AuthResults:
    raw = " ".join(str(h) for h in headers) if headers else ""
    def grab(mech: str) -> str:
        m = re.search(rf"{mech}=(\w+)", raw, re.IGNORECASE)
        return m.group(1).lower() if m else "none"
    return AuthResults(spf=grab("spf"), dkim=grab("dkim"), dmarc=grab("dmarc"), raw=raw)


def parse_eml(path) -> EmailArtifact:
    """Parse a .eml file into an EmailArtifact."""
    path = Path(path)
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_to = getaddresses(msg.get_all("Reply-To", []))
    return_path = str(msg.get("Return-Path", "")).strip("<>")
    to_cc = getaddresses(msg.get_all("To", []) + msg.get_all("Cc", []))

    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        if disp == "attachment":
            fname = part.get_filename()
            if fname:
                attachments.append(fname)
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            text_parts.append(content)
        elif ctype == "text/html":
            html_parts.append(content)

    body_html = "\n".join(html_parts)
    body_text = "\n".join(text_parts)
    # URLs are hunted in the raw HTML too: phishing links often live only in hrefs.
    urls = URL_RE.findall(body_text) + URL_RE.findall(body_html)
    urls = [u.rstrip(".,;:!?") for u in urls]
    if not body_text and body_html:
        body_text = TAG_RE.sub(" ", body_html)

    url_domains = sorted({(urlparse(u).hostname or "").lower() for u in urls if urlparse(u).hostname})

    return EmailArtifact(
        path=str(path),
        subject=str(msg.get("Subject", "")),
        from_name=from_name,
        from_addr=from_addr,
        from_domain=_domain_of(from_addr),
        reply_to_domain=_domain_of(reply_to[0][1]) if reply_to else "",
        return_path_domain=_domain_of(return_path),
        auth=_parse_auth_results(msg.get_all("Authentication-Results")),
        received=[str(h) for h in msg.get_all("Received", [])],
        urls=urls,
        url_domains=url_domains,
        attachments=attachments,
        body_text=body_text,
        body_html=body_html,
        num_recipients=len(to_cc),
    )
