# TrustShield ML Datasets

This directory contains benchmark and training datasets for TrustShield's URL classification subsystem.

## `sample_urls.csv`

A curated, balanced synthetic benchmark dataset containing 60 URLs for model prototyping, smoke testing, and unit verification.

### Structure
- `url`: Target URL string.
- `label`: Binary classification target:
  - `0`: Benign / Legitimate URL (30 samples)
  - `1`: Phishing / Malicious URL (30 samples)

### Composition
- **Benign (Class 0)**:
  - High-authority domains (Google, Wikipedia, GitHub, MDN, Python.org, AWS, Apple, etc.)
  - Diverse path depths, HTTPS protocols, standard query strings, and clean host structures.
- **Phishing (Class 1)**:
  - Brand spoofing in subdomains (`paypal-security-update.account-verification.xyz`)
  - Direct IP addresses and unusual ports (`http://192.168.1.100:8080/paypal/login.php`)
  - Abusive / cheap TLDs (`.xyz`, `.top`, `.cam`, `.loan`, `.buzz`, `.club`, `.work`)
  - Hex obfuscation and percent encoding (`login%20verify%2Eupdate%2Ecam`)
  - Punycode homoglyphs (`https://xn--pple-43d.com/login`)
  - Deceptive path patterns containing brand TLDs (`/paypal.com/signin/confirm.php`)
