"""Verdict assembly and rendering."""

from __future__ import annotations

from .core import EmailArtifact
from .features import feature_vector
from .model import PhishModel
from .rules import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD, evaluate


def analyze(artifact: EmailArtifact, model: PhishModel = None) -> dict:
    """Fuse the rule engine and the ML model into one verdict."""
    rule_score, hits = evaluate(artifact)
    fv = feature_vector(artifact)
    ml_prob, reasons = None, []
    if model is not None:
        ml_prob = model.predict_proba(fv)
        reasons = model.explain(fv)

    # Fusion: the rule engine is the auditable backbone and its score is
    # the floor; the ML probability can only raise it, catching suspicious
    # feature *combinations* no single rule names.
    if ml_prob is None:
        final = float(rule_score)
    else:
        final = max(float(rule_score), 0.55 * rule_score + 45.0 * ml_prob)
    final = round(min(100.0, final), 1)

    if final >= PHISHING_THRESHOLD:
        verdict = "phishing"
    elif final >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "file": artifact.path,
        "subject": artifact.subject,
        "from": artifact.from_addr,
        "verdict": verdict,
        "score": final,
        "rule_score": rule_score,
        "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
        "rule_hits": [
            {"id": h.rule_id, "title": h.title, "weight": h.weight, "detail": h.detail}
            for h in hits
        ],
        "ml_reasons": [
            {"feature": name, "contribution": c,
             "direction": "towards phishing" if c > 0 else "towards clean"}
            for name, c in reasons if abs(c) > 0.05
        ],
        "iocs": {
            "urls": artifact.urls,
            "url_domains": artifact.url_domains,
            "attachments": artifact.attachments,
        },
        "auth": {
            "spf": artifact.auth.spf,
            "dkim": artifact.auth.dkim,
            "dmarc": artifact.auth.dmarc,
        },
    }


def render_text(report: dict) -> str:
    lines = []
    badge = {"phishing": "[PHISHING]", "suspicious": "[SUSPICIOUS]", "clean": "[CLEAN]"}[report["verdict"]]
    lines.append(f"{badge}  score {report['score']}/100   {report['file']}")
    lines.append(f"  Subject: {report['subject']}")
    lines.append(f"  From:    {report['from']}")
    auth = report["auth"]
    lines.append(f"  Auth:    SPF={auth['spf']}  DKIM={auth['dkim']}  DMARC={auth['dmarc']}")
    if report["ml_probability"] is not None:
        lines.append(f"  Scores:  rules={report['rule_score']}/100  ml={report['ml_probability']:.0%} phishing")
    else:
        lines.append(f"  Scores:  rules={report['rule_score']}/100  (no ML model loaded)")
    if report["rule_hits"]:
        lines.append("  Red flags:")
        for h in report["rule_hits"]:
            lines.append(f"    +{h['weight']:>2}  [{h['id']}] {h['title']} - {h['detail']}")
    if report["ml_reasons"]:
        lines.append("  ML reasons (linear-SHAP contributions):")
        for r in report["ml_reasons"][:5]:
            lines.append(f"    {r['contribution']:+.2f}  {r['feature']}  ({r['direction']})")
    if report["iocs"]["url_domains"]:
        lines.append("  IOCs:")
        for d in report["iocs"]["url_domains"]:
            lines.append(f"    domain: {d}")
        for a in report["iocs"]["attachments"]:
            lines.append(f"    attachment: {a}")
    return "\n".join(lines)
