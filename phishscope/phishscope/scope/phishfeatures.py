"""Feature vector construction shared by the rule engine and the ML model.

FEATURE_NAMES is the single source of truth for model input order - the
trainer, the bundled model JSON and inference all read it from here, so
they can never drift apart.
"""

from __future__ import annotations

from .core import EmailArtifact
from .rules import _auth_fail

FEATURE_NAMES = [
    "spf_fail", "spf_softfail", "dkim_fail", "dkim_missing",
    "dmarc_fail", "dmarc_missing",
    "reply_to_mismatch", "return_path_mismatch",
    "display_name_spoof", "lookalike_domain",
    "num_urls", "num_url_domains",
    "has_shortener", "has_ip_url", "has_punycode", "has_at_url",
    "url_from_mismatch",
    "urgency_hits", "credential_hits",
    "num_attachments", "dangerous_attachment", "double_ext_attachment",
    "num_hops", "caps_subject",
]


def feature_vector(a: EmailArtifact) -> dict:
    return {
        "spf_fail": float(_auth_fail(a.auth.spf)),
        "spf_softfail": float(a.auth.spf in ("softfail", "neutral")),
        "dkim_fail": float(_auth_fail(a.auth.dkim)),
        "dkim_missing": float(a.auth.dkim in ("none", "")),
        "dmarc_fail": float(_auth_fail(a.auth.dmarc)),
        "dmarc_missing": float(a.auth.dmarc in ("none", "")),
        "reply_to_mismatch": float(bool(a.reply_to_domain) and a.reply_to_domain != a.from_domain),
        "return_path_mismatch": float(bool(a.return_path_domain) and a.return_path_domain != a.from_domain),
        "display_name_spoof": float(bool(a.display_name_spoof)),
        "lookalike_domain": float(bool(a.lookalike_domain)),
        "num_urls": float(len(a.urls)),
        "num_url_domains": float(len(a.url_domains)),
        "has_shortener": float(bool(a.shortener_urls)),
        "has_ip_url": float(bool(a.ip_urls)),
        "has_punycode": float(bool(a.punycode_urls)),
        "has_at_url": float(bool(a.at_urls)),
        "url_from_mismatch": float(min(1.0, len(a.mismatched_url_domains) / 2.0)),
        "urgency_hits": float(min(a.urgency_hits, 6)),
        "credential_hits": float(min(a.credential_hits, 5)),
        "num_attachments": float(len(a.attachments)),
        "dangerous_attachment": float(bool(a.dangerous_attachments)),
        "double_ext_attachment": float(bool(a.double_ext_attachments)),
        "num_hops": float(len(a.received)),
        "caps_subject": float(a.caps_subject),
    }
