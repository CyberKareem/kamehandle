# kamehandle.py ⚡️
Generate likely username + email handle permutations from full names.

Built for practical, legitimate use cases like:
- onboarding/account provisioning checks
- directory cleanup & account matching
- defensive OSINT **with authorization and scope**

> Ethical use: Do not use this tool for phishing, harassment, or unauthorized targeting.

---

## Features
- Input: a single `"Firstname Lastname"` or a file with one name per line
- Output: usernames, emails, or both
- Export: `.txt` or `.csv`
- Supports multiple email domains (repeat `--domain`)
- Better normalization for real names (apostrophes, hyphens, accents) via `--ascii`
- Optional max length enforcement (`--max-length`)
- Optional numeric suffixes (`--add-numbers 1-50`)
- Presets for “common vs wide” generation (`--profile common|wide|minimal`)
- No external dependencies

---

## Requirements
- Python 3.9+

---

## Quick Start

### 1) Usernames for one person
```bash
python3 kamehandle.py --name "John Doe" --mode usernames
