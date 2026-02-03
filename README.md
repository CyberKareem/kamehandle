# kamehandle.py ⚡️
Generate likely username + email handle permutations from full names.

**Why?**
Because “john.doe”, “jdoe”, “doe.john”, etc. keep showing up everywhere — and it’s handy for:
- IT/service desk onboarding checks
- Directory cleanup & account matching
- Defensive OSINT (blue team / SOC) when you already have legitimate scope

> Ethical use: This tool is for legitimate, authorized purposes. Don’t use it for phishing, harassment, or unauthorized targeting.

---

## Features
- Input: a single `"Firstname Lastname"` or a file of names
- Output: usernames, emails, or both
- Export: `.txt` or `.csv`
- Supports multiple email domains (repeat `--domain`)

---

## Requirements
- Python 3.9+ (works on Linux/macOS/Windows)

No external dependencies.

---

## Usage

### 1) Single name → usernames
```bash
python3 kamehandle.py --name "John Doe" --mode usernames
