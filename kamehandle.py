#!/usr/bin/env python3
"""
kamehandle.py
Generate likely username/email handle permutations from names.

Ethical use note:
- Intended for legitimate IT/admin tasks, account provisioning checks, and defensive OSINT.
- Do not use for phishing, harassment, or unauthorized targeting.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
from datetime import datetime
from typing import Iterable, List, Dict, Set, Tuple


def normalize_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def split_name(full_name: str) -> Dict[str, str]:
    """
    Splits a full name into first / middle(s) / last.
    Rules:
      - first token = first name
      - last token = last name
      - anything between = middle names
    """
    full_name = normalize_spaces(full_name)
    parts = full_name.split(" ")

    if len(parts) < 2:
        raise ValueError(f"Name must include at least first and last: '{full_name}'")

    first = parts[0]
    last = parts[-1]
    middles = parts[1:-1]

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


def apply_case(s: str, case_mode: str) -> str:
    if case_mode == "lower":
        return s.lower()
    if case_mode == "upper":
        return s.upper()
    return s  # "original"


def username_patterns(tokens: Dict[str, str]) -> List[str]:
    f = tokens["first"]
    l = tokens["last"]
    fi = tokens["fi"]
    li = tokens["li"]
    mi = tokens["mi"]

    # If you want fewer/more patterns, edit this list.
    patterns = [
        f"{f}{li}",          # johnd
        f"{fi}{l}",          # jdoe
        f"{f}{l}",           # johndoe
        f"{f}.{l}",          # john.doe
        f"{l}.{f}",          # doe.john
        f"{f}_{l}",          # john_doe
        f"{fi}.{l}",         # j.doe
        f"{f}.{li}",         # john.d
        f"{fi}_{l}",         # j_doe
        f"{f}-{l}",          # john-doe
        f"{l}-{f}",          # doe-john
        f"{l}_{f}",          # doe_john
        f"{l}{fi}",          # doej
        f"{fi}{l}{li}",      # jdoed (sometimes used)
        f"{f}{l}{li}",       # johndoed (sometimes used)
        f"{fi}{mi}{l}" if mi else "",      # jmd (with middle initial) -> jmdoe
        f"{f}{mi}{l}" if mi else "",       # johnmdoe
        f"{f}.{mi}.{l}" if mi else "",     # john.m.doe
        f"{fi}{mi}.{l}" if mi else "",     # jm.doe
    ]

    # Remove empties while preserving order
    return [p for p in patterns if p]


def generate_usernames(full_name: str, case_mode: str, max_per_name: int | None) -> List[str]:
    tokens = split_name(full_name)
    candidates = username_patterns(tokens)

    # Normalize: keep allowed chars, collapse repeated separators
    cleaned: List[str] = []
    seen: Set[str] = set()

    for c in candidates:
        c = apply_case(c, case_mode)

        # Basic cleanup rules
        c = c.strip()
        c = re.sub(r"[^\w\.-]+", "", c)      # keep letters/digits/_/./-
        c = re.sub(r"\.{2,}", ".", c)        # no ".."
        c = re.sub(r"_{2,}", "_", c)         # no "__"
        c = re.sub(r"-{2,}", "-", c)         # no "--"
        c = c.strip("._-")                   # trim separators ends

        if not c:
            continue

        if c not in seen:
            seen.add(c)
            cleaned.append(c)

        if max_per_name and len(cleaned) >= max_per_name:
            break

    return cleaned


def generate_emails(full_name: str, domains: List[str], case_mode: str, max_per_name: int | None) -> List[str]:
    if not domains:
        raise ValueError("Emails mode requires at least one --domain (e.g. --domain example.com)")

    usernames = generate_usernames(full_name, case_mode, max_per_name)
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
        help="Email domain (repeatable). Required for emails/both. مثال: --domain company.com",
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

    args = parser.parse_args()

    names: List[str]
    if args.name:
        names = [args.name]
    else:
        names = read_names_from_file(args.names_file)

    mode = args.mode
    fmt = args.format

    if args.output:
        out_path = args.output
    else:
        out_path = default_output_name(mode, fmt)

    rows: List[Dict[str, str]] = []

    for n in names:
        n = normalize_spaces(n)
        try:
            if mode in ("usernames", "both"):
                for u in generate_usernames(n, args.case, args.max_per_name):
                    rows.append({"full_name": n, "type": "username", "value": u, "domain": ""})

            if mode in ("emails", "both"):
                for e in generate_emails(n, args.domain, args.case, args.max_per_name):
                    # domain is included for CSV visibility
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
