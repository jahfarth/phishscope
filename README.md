# PhishScope

**Static phishing email triage for the command line** - drop in `.eml` files, get a verdict, the red flags behind it, the indicators of compromise, and an explainable ML score in under 2 ms per email.

Built as a SOC analyst (L1) portfolio project: it automates the first 5 minutes of every phishing ticket.

![CI](https://github.com/jahfarth/phishscope/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## What it does

| Stage | Details |
|---|---|
| **Parse** | `.eml` headers, Received chain, plain + HTML bodies, attachments (stdlib `email` only - no rendering, no network, safe on hostile samples) |
| **Authenticate** | SPF / DKIM / DMARC results from `Authentication-Results`, Return-Path and Reply-To alignment |
| **Extract IOCs** | URLs, domains, IP-literal links, punycode hosts, userinfo-cloaked links (`https://real.com@evil/`), shorteners, dangerous and double-extension attachments |
| **Score (rules)** | 19 weighted red-flag rules (lookalike domains, display-name spoofing, urgency language, BEC patterns...) - every hit carries an analyst-readable reason |
| **Score (ML)** | Logistic regression over 24 features; exact linear-SHAP contributions printed per verdict, so the model is never a black box |
| **Report** | Analyst summary or JSON for piping into a SIEM / case tool |

## Results on the bundled corpus

Numbers from `pytest -q` and a scan of `samples/` (10 synthetic phishing + 6 legitimate emails):

- **10 / 10 phishing emails flagged** - 8 called `phishing`, 2 called `suspicious`
- **0 / 6 legitimate emails false-positived**
- **46 automated tests**, all passing
- ML model: **97.8% accuracy / 97.5% precision / 98.0% recall** on an 800-sample held-out synthetic test set (seed 42)
- **~1.7 ms mean analysis time per email** (M-series laptop, single process)

## Quick start

```bash
git clone https://github.com/jahfarth/phishscope.git
cd phishscope
pip install -r requirements.txt   # scikit-learn is only needed for training; analysis is stdlib-only

python -m phishscope analyze samples/phishing_01_paylookalike.eml
python -m phishscope scan samples/            # whole directory
python -m phishscope analyze --json mail.eml  # machine-readable
python -m phishscope analyze --no-ml mail.eml # rule engine only
```

Example output:

```
[PHISHING]  score 100.0/100   samples/phishing_01_paylookalike.eml
  Subject: URGENT: Your account has been suspended - verify within 24 hours
  From:    security@paypa1-secure.example
  Auth:    SPF=fail  DKIM=fail  DMARC=fail
  Scores:  rules=100/100  ml=100% phishing
  Red flags:
    +25  [AUTH-001] SPF fail - sending host is not authorised for the From domain
    +25  [AUTH-004] DMARC fail - the visible From domain is not authenticated
    +20  [HDR-004] Lookalike sender domain - 'paypa1-secure.example' impersonates 'paypal'
    +18  [HDR-003] Display-name brand spoofing - display name claims 'paypal'
    ...
  ML reasons (linear-SHAP contributions):
    +2.35  urgency_hits  (towards phishing)
    +1.15  spf_fail      (towards phishing)
  IOCs:
    domain: paypa1-secure.example
```

## Verdicts and scoring

Rule weights sum to a 0-100 score; the ML probability (0-1) can only *raise* it:

`score = max(rule_score, 0.55 * rule_score + 45 * ml_probability)`

| Score | Verdict |
|---|---|
| >= 65 | **phishing** |
| 35-64 | **suspicious** - queue for an analyst |
| < 35 | **clean** |

Exit code is `1` when any analysed file is phishing, so it drops straight into scripts and CI gates.

## Why logistic regression (and why it ships as JSON)

For a linear model the exact SHAP value of every feature is `coef_i * (x_i - mean_i) / std_i` - no approximation, no explainability library, fully auditable. The trained model is stored as plain JSON (`phishscope/models/default_model.json`), so:

- **inference needs zero dependencies** - the analyser runs on stdlib Python alone
- training is reproducible: `python -m phishscope train` regenerates the model from synthetic, seeded data (4,000 samples generated in-repo - no external dataset download)

## The sample corpus

`samples/` holds 16 synthetic emails covering the common L1 phish families: lookalike domains, credential harvesting, macro/executable lures, IP-literal links, URL shorteners, userinfo cloaking, punycode homoglyphs, CEO fraud/BEC, and crypto wallet scams, plus 6 legitimate counterparts.

Everything is fabricated with reserved domains (`example.com`, `.example`) and placeholder attachment bytes - no live malware, nothing unsafe to open. Regenerate with `python scripts/make_samples.py`.

## Project layout

```
phishscope/
  core.py       parsing + indicator extraction (stdlib only)
  rules.py      19 weighted red-flag rules with reason strings
  features.py   24-feature vector shared by rules and ML
  model.py      logistic regression: train / JSON save-load / linear-SHAP explain
  report.py     verdict fusion + text/JSON rendering
  cli.py        analyze / scan / train commands
samples/        synthetic .eml corpus (safe)
tests/          46 pytest tests - the corpus verdicts are the contract
scripts/        corpus generator
```

## Roadmap

- [ ] Live DNS checks (SPF/DKIM/DMARC from the wire, not just headers) behind an `--online` flag
- [ ] URL reputation lookups (urlhaus / PhishTank) behind `--online`
- [ ] WHOIS domain-age signal for lookalike domains
- [ ] HTML screenshot-free link preview extraction

## Disclaimer

PhishScope is a triage aid, not a verdict of law: it ranks and explains, an analyst decides. The ML model is trained on synthetic data - treat its score as a prior, never as sole evidence.

## License

MIT - see [LICENSE](LICENSE).
