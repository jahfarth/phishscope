"""End-to-end and unit tests for PhishScope.

Run:  pytest -q
The sample corpus is the contract: every phishing_*.eml must be called
phishing or suspicious, and no legit_*.eml may be called phishing.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishscope.core import levenshtein, parse_eml, registered_label  # noqa: E402
from phishscope.features import FEATURE_NAMES, feature_vector  # noqa: E402
from phishscope.model import PhishModel, generate_synthetic_dataset  # noqa: E402
from phishscope.report import analyze  # noqa: E402
from phishscope.rules import evaluate  # noqa: E402

SAMPLES = ROOT / "samples"
PHISHING = sorted(SAMPLES.glob("phishing_*.eml"))
LEGIT = sorted(SAMPLES.glob("legit_*.eml"))


@pytest.fixture(scope="session")
def model():
    return PhishModel.train(n=2000, seed=7)


# ---------- corpus contract -------------------------------------------------

def test_corpus_exists():
    assert len(PHISHING) == 10
    assert len(LEGIT) == 6


@pytest.mark.parametrize("path", PHISHING, ids=lambda p: p.name)
def test_phishing_samples_flagged(path, model):
    rep = analyze(parse_eml(path), model)
    assert rep["verdict"] in ("phishing", "suspicious"), rep


@pytest.mark.parametrize("path", LEGIT, ids=lambda p: p.name)
def test_legit_samples_not_phishing(path, model):
    rep = analyze(parse_eml(path), model)
    assert rep["verdict"] != "phishing", rep
    assert rep["score"] < 65


def test_phishing_majority_called_phishing(model):
    verdicts = [analyze(parse_eml(p), model)["verdict"] for p in PHISHING]
    assert verdicts.count("phishing") >= 8, verdicts


# ---------- parsing -----------------------------------------------------------

def test_parse_headers():
    a = parse_eml(SAMPLES / "phishing_01_paylookalike.eml")
    assert "suspended" in a.subject.lower()
    assert a.from_domain == "paypa1-secure.example"
    assert a.reply_to_domain == "paypa1-billing.example"
    assert a.auth.spf == "fail"
    assert a.auth.dkim == "fail"
    assert a.auth.dmarc == "fail"


def test_parse_urls_and_domains():
    a = parse_eml(SAMPLES / "phishing_01_paylookalike.eml")
    assert "https://paypa1-secure.example/verify?session=9f2" in a.urls
    assert "paypa1-secure.example" in a.url_domains


def test_parse_html_only_urls():
    a = parse_eml(SAMPLES / "phishing_05_shortener.eml")
    assert "https://bit.ly/3xK9mQ2" in a.urls
    assert "bit.ly" in a.url_domains


def test_parse_attachment():
    a = parse_eml(SAMPLES / "phishing_03_macrodoc.eml")
    assert a.attachments == ["INV-2026-4471.pdf.exe"]


# ---------- indicators ---------------------------------------------------------

def test_ip_url_detected():
    a = parse_eml(SAMPLES / "phishing_04_iplink.eml")
    assert a.ip_urls and "198.51.100.77" in a.ip_urls[0]


def test_userinfo_cloak_detected():
    a = parse_eml(SAMPLES / "phishing_06_userinfo.eml")
    assert a.at_urls


def test_punycode_detected():
    a = parse_eml(SAMPLES / "phishing_08_punycode.eml")
    assert a.punycode_urls


def test_double_extension_detected():
    a = parse_eml(SAMPLES / "phishing_03_macrodoc.eml")
    assert "INV-2026-4471.pdf.exe" in a.double_ext_attachments
    assert "INV-2026-4471.pdf.exe" in a.dangerous_attachments


def test_display_name_spoof_detected():
    a = parse_eml(SAMPLES / "phishing_01_paylookalike.eml")
    assert a.display_name_spoof == "paypal"


def test_lookalike_homoglyph_detected():
    a = parse_eml(SAMPLES / "phishing_07_caps.eml")
    assert a.lookalike_domain == "netflix"


def test_no_false_lookalike_on_clean_domain():
    a = parse_eml(SAMPLES / "legit_05_bank.eml")
    assert a.lookalike_domain is None
    assert a.display_name_spoof is None


def test_caps_subject_detected():
    a = parse_eml(SAMPLES / "phishing_07_caps.eml")
    assert a.caps_subject


def test_urgency_scored():
    a = parse_eml(SAMPLES / "phishing_01_paylookalike.eml")
    assert a.urgency_hits >= 2


# ---------- helpers -------------------------------------------------------------

def test_registered_label():
    assert registered_label("mail.paypa1-secure.example") == "paypa1-secure"
    assert registered_label("example.com") == "example"
    assert registered_label("") == ""


def test_levenshtein():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypa1", "paypal") == 1
    assert levenshtein("microsft", "microsoft") == 1
    assert levenshtein("abc", "xyz") == 3


# ---------- rules -----------------------------------------------------------------

def test_rules_fire_on_bad_auth():
    a = parse_eml(SAMPLES / "phishing_01_paylookalike.eml")
    score, hits = evaluate(a)
    ids = {h.rule_id for h in hits}
    assert {"AUTH-001", "AUTH-003", "AUTH-004"} <= ids
    assert score >= 65


def test_rules_quiet_on_clean_mail():
    a = parse_eml(SAMPLES / "legit_03_meeting.eml")
    score, hits = evaluate(a)
    assert score < 35


# ---------- ML model ------------------------------------------------------------------

def test_feature_vector_covers_all_names():
    fv = feature_vector(parse_eml(SAMPLES / "phishing_01_paylookalike.eml"))
    assert set(fv) == set(FEATURE_NAMES)


def test_synthetic_dataset_shapes():
    X, y = generate_synthetic_dataset(n=200, seed=1)
    assert len(X) == len(y) == 200
    assert all(len(row) == len(FEATURE_NAMES) for row in X)


def test_model_accuracy_on_synthetic(model):
    assert model.metrics["accuracy"] >= 0.90
    assert model.metrics["precision"] >= 0.90


def test_model_scores_phish_above_legit(model):
    phish = analyze(parse_eml(SAMPLES / "phishing_01_paylookalike.eml"), model)
    legit = analyze(parse_eml(SAMPLES / "legit_03_meeting.eml"), model)
    assert phish["ml_probability"] > legit["ml_probability"]
    assert phish["ml_probability"] > 0.5


def test_explain_gives_reasons(model):
    rep = analyze(parse_eml(SAMPLES / "phishing_01_paylookalike.eml"), model)
    assert rep["ml_reasons"]
    top = rep["ml_reasons"][0]
    assert top["contribution"] != 0
    assert top["direction"] in ("towards phishing", "towards clean")


def test_model_roundtrip(model, tmp_path):
    out = tmp_path / "m.json"
    model.save(out)
    loaded = PhishModel.load(out)
    fv = feature_vector(parse_eml(SAMPLES / "phishing_01_paylookalike.eml"))
    assert loaded.predict_proba(fv) == pytest.approx(model.predict_proba(fv))
    assert loaded.weights == model.weights


def test_bundled_model_loads_and_is_current():
    bundled = PhishModel.load()
    fv = feature_vector(parse_eml(SAMPLES / "phishing_02_credharvest.eml"))
    assert 0.0 <= bundled.predict_proba(fv) <= 1.0


# ---------- CLI --------------------------------------------------------------------

def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "phishscope", *args],
                          cwd=ROOT, capture_output=True, text=True)


def test_cli_analyze_text_output():
    r = run_cli("analyze", str(SAMPLES / "phishing_04_iplink.eml"))
    assert r.returncode == 1  # phishing found -> exit 1
    assert "[PHISHING]" in r.stdout
    assert "Red flags:" in r.stdout


def test_cli_json_output_parses():
    r = run_cli("analyze", "--json", str(SAMPLES / "legit_01_newsletter.eml"))
    assert r.returncode == 0
    rep = json.loads(r.stdout)
    assert rep["verdict"] == "clean"
    assert "iocs" in rep


def test_cli_scan_directory():
    r = run_cli("scan", str(SAMPLES), "--json")
    reports = json.loads(r.stdout)
    assert len(reports) == len(PHISHING) + len(LEGIT)


def test_cli_no_ml_mode():
    r = run_cli("analyze", "--no-ml", str(SAMPLES / "phishing_01_paylookalike.eml"))
    assert "ml=" not in r.stdout
