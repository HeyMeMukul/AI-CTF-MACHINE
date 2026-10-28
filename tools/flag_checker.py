#!/usr/bin/env python3
"""flag_checker.py — answer-format gate (syntax only; not correctness proof).

Usage:
  python3 tools/flag_checker.py --file challenges/CHAL-001/flag.txt [--format picoCTF]
  python3 tools/flag_checker.py --text "output blob" [--format auto]
  python3 tools/flag_checker.py --file answer.txt --regex '^ANSWER-[A-Z0-9]{8}$'
  echo "$out" | python3 tools/flag_checker.py --stdin

Exit 0 = expected format matched (prints match length only, never the answer).
Exit 1 = no match. Formats: auto|picoCTF|HTB|THM|flag|CTF.
Use --regex for challenge-specific formats. A format match is NOT proof that
the answer is correct; confirm with a clean solve or challenge oracle.
"""
import argparse, re, sys

PATTERNS = {
    "picoCTF": re.compile(r"picoCTF\{[^}\n]{1,200}\}"),
    "HTB": re.compile(r"HTB\{[^}\n]{1,200}\}"),
    "THM": re.compile(r"THM\{[^}\n]{1,200}\}"),
    "flag": re.compile(r"flag\{[^}\n]{1,200}\}"),
    "FLAG": re.compile(r"FLAG\{[^}\n]{1,200}\}"),
    "CTF": re.compile(r"CTF\{[^}\n]{1,200}\}"),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=None)
    ap.add_argument("--text", default=None)
    ap.add_argument("--stdin", action="store_true")
    selector = ap.add_mutually_exclusive_group()
    selector.add_argument("--format", choices=("auto", *PATTERNS.keys()), default="auto")
    selector.add_argument("--regex", action="append", dest="custom_regex",
                          help="challenge-specific answer-format regex (repeatable); match only, not correctness")
    selector.add_argument("--regex-file", default=None,
                          help="local file containing one challenge-specific regex per non-comment line")
    a = ap.parse_args()
    if a.file:
        data = open(a.file, errors="ignore").read()
    elif a.stdin:
        data = sys.stdin.read()
    else:
        data = a.text or ""
    if a.custom_regex:
        try:
            pats = [re.compile(pattern) for pattern in a.custom_regex]
        except re.error as e:
            ap.error(f"invalid --regex: {e}")
    elif a.regex_file:
        try:
            expressions = [line.strip() for line in open(a.regex_file, errors="ignore")
                           if line.strip() and not line.lstrip().startswith("#")]
            pats = [re.compile(pattern) for pattern in expressions]
        except (OSError, re.error) as e:
            ap.error(f"cannot read/compile --regex-file: {e}")
    else:
        pats = PATTERNS.values() if a.format == "auto" else [PATTERNS[a.format]]
    for p in pats:
        m = p.search(data)
        if m:
            print(f"MATCH format_ok len={len(m.group(0))}")
            return 0
    print("NO-MATCH")
    return 1

if __name__ == "__main__":
    sys.exit(main())
