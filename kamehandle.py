## `kamehandle.py`

#```python
#!/usr/bin/env python3
"""
kamehandle.py
Generate likely username/email handle permutations from names.

Ethical use note:
- Intended for legitimate IT/admin tasks, account provisioning checks, and defensive OSINT WITH authorization.
- Do not use for phishing, harassment, or unauthorized targeting.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import unicodedata
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional


# ----------------------------
# Helpers: normalization
# ----------------------------

def normalize_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def to_ascii(s: str) -> str:
    """
    Remove accents/diacritics (José -> Jose) and normalize smart quotes.
    """
    s = s.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    norm = unicodedata.normalize("NFKD", s)
    return norm.encode("ascii", "ignore").decode("ascii")


def clean_token(token: str, ascii_mode: bool) -> str:
    """
    Clean name tokens (first/last) by removing punctuation and keeping alphanumerics only.
    """
    token = normalize_spaces(token)
    if ascii_mode:
        token = to_ascii(token)
    token = token.lower()
    # remove anything that's not alphanumeric
    token = re.sub(r"[^a-z0-9]+", "", token)
    return token


def apply_case(s: str, case_mode: str) -> str:
    if case_mode == "lower":
        return s.lower()
    if case_mode == "upper":
        return s.upper()
    return s  # original


# ----------------------------
# Parsing names
# ----------------------------

def split_name(full_name: str, ascii_mode: bool) -> Dict[str, str]:
    """
    Splits a full name into first / middle(s) / last.
    Rules:
      - first token = first name
      - last token = last name
      - anything between = middle names
    """
    full_name = normalize_spaces(full_name)
    if ascii_mode:
        full_name = to_ascii(full_name)

    parts = full_name.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Name must include at least first and last: '{full_name}'")

    raw_first = parts[0]
    raw_last = parts[-1]
    raw_middles = parts[1:-1]

    first = clean_token(raw_first, ascii_mode)
    last = clean_token(raw_last, ascii_mode)
    middles = [clean_token(x, ascii_mode) for x in raw_middles if clean_token(x, ascii_mode)]

    if not first or not last:
        raise ValueError(f"Could not parse first/last after normalization: '{full_name}'")

    middle = "".join(middles) if middles else ""
    fi = first[0]
    li = last[0]
    mi = middles[0][0] if middles else ""

    return {
        "full": full_name,
        "first": first,
        "last": last,
        "middle": middle,
        "fi": fi,
        "li": li,
        "mi": mi,
    }


# ----------------------------
# Generation logic
# ----------------------------

def base_username_candidates(tokens: Dict[str, str]) -> List[str]:
    """
    Return ordered candidates: most likely first.
    """
    f = tokens["first"]
    l = tokens["last"]
    fi = tokens["fi"]
    li = tokens["li"]
    mi = tokens["mi"]

    # ordered: common enterprise styles first
    candidates = [
        f"{f}.{l}",
        f"{f}_{l}",
        f"{f}{l}",
        f"{fi}{l}",
        f"{f}{li}",
        f"{fi}.{l}",
        f"{fi}_{l}",
        f"{l}.{f}",
        f"{l}_{f}",
        f"{l}{fi}",
        f"{f}-{l}",
        f"{l}-{f}",
        f"{f}.{li}",
        f"{fi}{l}{li}",  # sometimes used when collisions happen
    ]

    # middle initial patterns (if available)
    if mi:
        candidates.extend([
            f"{f}.{mi}.{l}",
            f"{f}{mi}{l}",
            f"{fi}{mi}{l}",
            f"{fi}{mi}.{l}",
        ])

    return candidates


def profile_filter(candidates: List[str], profile: str) -> List[str]:
    """
    Reduce/expand candidate set based on a preset.
    """
    if profile == "wide":
        return candidates

    if profile == "minimal":
        # tight top set
        keep = {
            # common top variants
            0, 1, 2, 3, 4, 5, 7
        }
        return [c for i, c in enumerate(candidates) if i in keep]

    # "common"
    # Keep the most common / realistic ones, skip some rarer ones
    keep = []
    for i, c in enumerate(candidates):
        # drop uncommon collision patterns except a couple
        if c.endswith(".") or c.startswith("."):
            continue
        keep.append(c)
    # limit to a reasonable number
    return keep[:20]


def sanitize_handle(handle: str) -> str:
    """
    Keep only letters/digits/_/./- ; collapse repeated separators; trim ends.
    """
    h = handle.strip()
    h = re.sub(r"[^\w\.-]+", "", h)
    h = re.sub(r"\.{2,}", ".", h)
    h = re.sub(r"_{2,}", "_", h)
    h = re.sub(r"-{2,}", "-", h)
    h = h.strip("._-")
    return h


def enforce_max_length(handles: List[str], max_len: Optional[int]) -> List[str]:
    if not max_len:
        return handles
    return [h for h in handles if len(h) <= max_len]


def add_numeric_suffixes(handles: List[str], add_numbers: Optional[Tuple[int, int]], max_len: Optional[int]) -> List[str]:
    """
    Add suffix numbers: handle1..handleN
    """
    if not add_numbers:
        return handles

    start, end = add_numbers
    out: List[str] = []
    seen: Set[str] = set()

    # keep original first
    for h in handles:
        if h not in seen:
            seen.add(h)
            out.append(h)

    for h in handles:
        for n in range(start, end + 1):
            cand = f"{h}{n}"
            if max_len and len(cand) > max_len:
                continue
            if cand not in seen:
                seen.add(cand)
                out.append(cand)

    return out


def generate_usernames(
    full_name: str,
    case_mode: str,
    ascii_mode: bool,
    profile: str,
    max_per_name: Optional[int],
    max_length: Optional[int],
    add_numbers: Optional[Tuple[int, int]],
) -> List[str]:
    tokens = split_name(full_name, ascii_mode)
    candidates = base_username_candidates(tokens)
    candidates = profile_filter(candidates, profile)

    cleaned: List[str] = []
    seen: Set[str] = set()

    for c in candidates:
        c = sanitize_handle(c)
        if not c:
            continue
        c = apply_case(c, case_mode)
        if max_length and len(c) > max_length:
            continue
        if c not in seen:
            seen.add(c)
            cleaned.append(c)
        if max_per_name and len(cleaned) >= max_per_name:
            break

    # numeric suffixes (optional) AFTER initial list
    cleaned = add_numeric_suffixes(cleaned, add_numbers, max_length)

    # optional max_per_name re-apply if needed
    if max_per_name:
        cleaned = cleaned[:max_per_name]

    return cleaned


def generate_emails(
    full_name: str,
    domains: List[str],
    case_mode: str,
    ascii_mode: bool,
    profile: str,
    max_per_name: Optional[int],
    max_length: Optional[int],
    add_numbers: Optional[Tuple[int, int]],
) -> List[str]:
    if not domains:
        raise ValueError("Emails mode requires at least one --domain (e.g. --domain example.com)")

    usernames = generate_usernames(
        full_name=full_name,
        case_mode=case_mode,
        ascii_mode=ascii_mode,
        profile=profile,
        max_per_name=max_per_name,
        max_length=max_length,
        add_numbers=add_numbers,
    )

    emails: List[str] = []
    seen: Set[str] = set()

    for u in usernames:
        for d in domains:
            d = d.strip().lstrip("@")
            email = f"{u}@{d}"
            if email not in seen:
                seen.add(email)
                emails.append(email)

    return emails


# ----------------------------
# IO
# ----------------------------

def read_names_from_file(path: str) -> List[str]:
    names: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = normalize_spaces(line)
            if not line or line.startswith("#"):
                continue
            names.append(line)
    return names


def default_output_name(mode: str, fmt: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"kamehandle_{mode}_{ts}.{fmt}"


def write_txt(out_path: str, rows: List[Dict[str, str]]) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(r["value"] + "\n")


def write_csv(out_path: str, rows: List[Dict[str, str]]) -> None:
    fieldnames = ["full_name", "type", "value", "domain"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def parse_number_range(s: str) -> Tuple[int, int]:
    """
    Parse '1-50' or '5-5' into (1,50).
    """
    s = s.strip()
    m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", s)
    if not m:
        raise ValueError("Invalid --add-numbers format. Use like: 1-50")
    a = int(m.group(1))
    b = int(m.group(2))
    if a < 0 or b < 0 or b < a:
        raise ValueError("Invalid --add-numbers range. Example: 1-50")
    return a, b


# ----------------------------
# Main
# ----------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate likely username/email permutations from names."
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--name", help='Single name, e.g. "John Doe"')
    input_group.add_argument("--names-file", help="Path to a text file with one full name per line")

    parser.add_argument(
        "--mode",
        choices=["usernames", "emails", "both"],
        default="usernames",
        help="What to generate",
    )
    parser.add_argument(
        "--domain",
        action="append",
        default=[],
        help="Email domain (repeatable). Example: --domain company.com",
    )
    parser.add_argument(
        "--case",
        choices=["lower", "original", "upper"],
        default="lower",
        help="Output casing",
    )
    parser.add_argument(
        "--format",
        choices=["txt", "csv"],
        default="txt",
        help="Output file format",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output filename (default: auto-generated in current directory)",
    )
    parser.add_argument(
        "--max-per-name",
        type=int,
        default=None,
        help="Limit number of generated variants per name (optional)",
    )
    parser.add_argument(
        "--ascii",
        action="store_true",
        help="Normalize accents and smart quotes (José -> jose, O’Neil -> oneil)",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=None,
        help="Enforce maximum username length (filters out longer handles)",
    )
    parser.add_argument(
        "--add-numbers",
        type=str,
        default=None,
        help="Append numeric suffixes like '1-50' (generates jdoe1..jdoe50)",
    )
    parser.add_argument(
        "--profile",
        choices=["minimal", "common", "wide"],
        default="common",
        help="Preset amount of patterns to generate",
    )

    args = parser.parse_args()

    names: List[str]
    if args.name:
        names = [args.name]
    else:
        names = read_names_from_file(args.names_file)

    add_numbers_range: Optional[Tuple[int, int]] = None
    if args.add_numbers:
        try:
            add_numbers_range = parse_number_range(args.add_numbers)
        except ValueError as e:
            print(f"[!] {e}")
            return 2

    mode = args.mode
    fmt = args.format

    out_path = args.output if args.output else default_output_name(mode, fmt)

    rows: List[Dict[str, str]] = []

    for n in names:
        n = normalize_spaces(n)
        try:
            if mode in ("usernames", "both"):
                for u in generate_usernames(
                    full_name=n,
                    case_mode=args.case,
                    ascii_mode=args.ascii,
                    profile=args.profile,
                    max_per_name=args.max_per_name,
                    max_length=args.max_length,
                    add_numbers=add_numbers_range,
                ):
                    rows.append({"full_name": n, "type": "username", "value": u, "domain": ""})

            if mode in ("emails", "both"):
                for e in generate_emails(
                    full_name=n,
                    domains=args.domain,
                    case_mode=args.case,
                    ascii_mode=args.ascii,
                    profile=args.profile,
                    max_per_name=args.max_per_name,
                    max_length=args.max_length,
                    add_numbers=add_numbers_range,
                ):
                    dom = e.split("@", 1)[1] if "@" in e else ""
                    rows.append({"full_name": n, "type": "email", "value": e, "domain": dom})

        except ValueError as ve:
            print(f"[!] Skipping '{n}': {ve}")

    if not rows:
        print("[!] No output generated.")
        return 2

    if fmt == "txt":
        write_txt(out_path, rows)
    else:
        write_csv(out_path, rows)

    print(f"[+] Saved {len(rows)} results to: {os.path.abspath(out_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
