"""Weighted red-flag rule engine.

Each rule maps to something a SOC analyst checks during L1 triage. Weights
are additive and capped at 100; anything >= 65 is called phishing, >= 35
suspicious. Every hit carries an analyst-readable reason string so the
report never says "score 72" without saying *why*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List

from .core import EmailArtifact


@dataclass
class RuleHit:
    rule_id: str
    title: str
    weight: int
    detail: str


@dataclass
class Rule:
    rule_id: str
    title: str
    weight: int
    check: Callable[[EmailArtifact], str]  # returns detail string, or "" when clean


def _auth_fail(result: str) -> bool:
    return result in ("fail", "hardfail", "permerror")


RULES: List[Rule] = [
    Rule("AUTH-001", "SPF fail", 25,
         lambda a: "SPF returned fail - sending host is not authorised for the From domain"
         if _auth_fail(a.auth.spf) else ""),
    Rule("AUTH-002", "SPF softfail / neutral", 8,
         lambda a: f"SPF returned {a.auth.spf} - weak sender policy"
         if a.auth.spf in ("softfail", "neutral") else ""),
    Rule("AUTH-003", "DKIM fail", 20,
         lambda a: "DKIM signature verification failed - message may have been tampered with or forged"
         if _auth_fail(a.auth.dkim) else ""),
    Rule("AUTH-004", "DMARC fail", 25,
         lambda a: "DMARC alignment failed - the visible From domain is not authenticated"
         if _auth_fail(a.auth.dmarc) else ""),
    Rule("AUTH-005", "No DKIM signature", 5,
         lambda a: "message carries no DKIM signature - nothing proves the sender"
         if a.auth.dkim in ("none", "") else ""),
    Rule("AUTH-006", "No DMARC result", 5,
         lambda a: "no DMARC policy result - domain may be unprotected or forged"
         if a.auth.dmarc in ("none", "") else ""),
    Rule("HDR-001", "From / Reply-To domain mismatch", 12,
         lambda a: f"replies would go to '{a.reply_to_domain}', not '{a.from_domain}'"
         if a.reply_to_domain and a.reply_to_domain != a.from_domain else ""),
    Rule("HDR-002", "Return-Path domain mismatch", 10,
         lambda a: f"bounces go to '{a.return_path_domain}', not '{a.from_domain}'"
         if a.return_path_domain and a.return_path_domain != a.from_domain else ""),
    Rule("HDR-003", "Display-name brand spoofing", 18,
         lambda a: f"display name claims '{a.display_name_spoof}' but mail comes from '{a.from_domain}'"
         if a.display_name_spoof else ""),
    Rule("HDR-004", "Lookalike sender domain", 20,
         lambda a: f"sender domain '{a.from_domain}' impersonates '{a.lookalike_domain}'"
         if a.lookalike_domain else ""),
    Rule("HDR-005", "Punycode (IDN) sender domain", 20,
         lambda a: f"sender domain '{a.from_domain}' is internationalised - homoglyph risk"
         if "xn--" in a.from_domain else ""),
    Rule("URL-001", "IP-literal URL", 15,
         lambda a: f"{len(a.ip_urls)} link(s) point at raw IPs: {', '.join(a.ip_urls[:3])}"
         if a.ip_urls else ""),
    Rule("URL-002", "URL shortener", 8,
         lambda a: f"{len(a.shortener_urls)} shortened link(s) hide the real destination"
         if a.shortener_urls else ""),
    Rule("URL-003", "Punycode URL", 15,
         lambda a: "internationalised (punycode) hostname - common in homoglyph attacks"
         if a.punycode_urls else ""),
    Rule("URL-004", "Links point off sender domain", 10,
         lambda a: f"links resolve to {', '.join(a.mismatched_url_domains[:4])}"
         if len(a.mismatched_url_domains) >= 1 else ""),
    Rule("URL-005", "Userinfo-cloaked URL", 12,
         lambda a: "URL uses 'user@host' cloaking to hide the real host"
         if a.at_urls else ""),
    Rule("BODY-001", "Urgency / pressure language", 10,
         lambda a: f"{a.urgency_hits} urgency phrase(s) - pressure is the oldest phish trick"
         if a.urgency_hits >= 2 else ""),
    Rule("BODY-002", "Credential-harvesting language", 12,
         lambda a: f"{a.credential_hits} phrase(s) asking for passwords / payment / identity data"
         if a.credential_hits >= 1 else ""),
    Rule("ATT-001", "Dangerous attachment type", 20,
         lambda a: f"executable attachment(s): {', '.join(a.dangerous_attachments)}"
         if a.dangerous_attachments else ""),
    Rule("ATT-002", "Double-extension attachment", 18,
         lambda a: f"double-extension file(s) masquerading as documents: {', '.join(a.double_ext_attachments)}"
         if a.double_ext_attachments else ""),
    Rule("RCV-001", "Excessive Received hops", 5,
         lambda a: f"{len(a.received)} hops - unusually long delivery chain"
         if len(a.received) > 6 else ""),
    Rule("SUBJ-001", "Shouting (all-caps) subject", 5,
         lambda a: "subject is mostly uppercase"
         if a.caps_subject else ""),
]

PHISHING_THRESHOLD = 65
SUSPICIOUS_THRESHOLD = 35


def evaluate(artifact: EmailArtifact) -> tuple:
    """Return (score 0-100, list of RuleHit)."""
    hits = []
    for rule in RULES:
        detail = rule.check(artifact)
        if detail:
            hits.append(RuleHit(rule.rule_id, rule.title, rule.weight, detail))
    score = min(100, sum(h.weight for h in hits))
    return score, hits
