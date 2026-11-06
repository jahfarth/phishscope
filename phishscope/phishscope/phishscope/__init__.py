"""PhishScope - phishing email triage for the command line.

Parses .eml files, checks authentication headers (SPF / DKIM / DMARC),
extracts indicators of compromise, scores red flags with a weighted rule
engine, and layers a logistic-regression model on top whose per-feature
contributions explain every verdict.
"""

__version__ = "1.0.0"
