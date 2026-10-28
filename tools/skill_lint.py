#!/usr/bin/env python3
"""skill_lint.py — enforces SKILL_CONTRACT.md on skills/ (ported from bug-bounty skill_lint).

Usage: python3 tools/skill_lint.py [skills-dir]
Checks per SKILL.md: frontmatter (name/description/category/phase), Mental Model,
5 gated phases each ending with a Reasoning Checkpoint, tool table, decision content,
SUMMARY.md presence (~20-60 lines), no concrete flag values.
Exit 0 = all pass, 1 = failures (listed). Warnings do not fail.
"""
import os, re, sys

if "--help" in sys.argv:
    print("usage: skill_lint.py [skills-dir]  (enforces SKILL_CONTRACT + SUMMARY length + no-flag rule)")
    sys.exit(0)
BASE = sys.argv[1] if len(sys.argv) > 1 else "skills"
SKIP = {"_shared"}
FLAG_VAL = re.compile(r"(picoCTF|HTB|THM)\{[A-Za-z0-9_\-!@#$%^&*]{4,}\}")

fails, warns = [], []

def check(skill_dir):
    name = os.path.basename(skill_dir)
    sk = os.path.join(skill_dir, "SKILL.md")
    su = os.path.join(skill_dir, "SUMMARY.md")
    if not os.path.isfile(sk):
        fails.append(f"{name}: missing SKILL.md"); return
    text = open(sk, errors="ignore").read()
    front = ""
    if text.startswith("---"):
        parts = text.split("---")
        front = parts[1] if len(parts) > 1 else ""
    for field in ("name:", "description:", "category:", "phase:"):
        if field not in front:
            fails.append(f"{name}: frontmatter missing {field}")
    if "## Mental Model" not in text and "## Mental model" not in text and "Mental Model" not in text:
        fails.append(f"{name}: missing Mental Model section")
    cps = len(re.findall(r"Reasoning Checkpoint", text))
    if cps < 5:
        fails.append(f"{name}: only {cps} Reasoning Checkpoints (need >=5, one per gated phase)")
    for kw in ("Baseline", "Negative", "Validation"):
        if kw.lower() not in text.lower():
            warns.append(f"{name}: no '{kw}' section found")
    if "```" not in text and "|" not in text:
        warns.append(f"{name}: no code blocks or tables (tool commands expected)")
    m = FLAG_VAL.search(text)
    if m:
        fails.append(f"{name}: concrete flag-like value found: {m.group(0)[:20]}... (technique-only!)")
    if not os.path.isfile(su):
        fails.append(f"{name}: missing SUMMARY.md"); return
    n = sum(1 for _ in open(su, errors="ignore"))
    if not (10 <= n <= 80):
        warns.append(f"{name}: SUMMARY.md is {n} lines (target ~40, dense quickref OK)")

def main():
    skills = sorted(d for d in os.listdir(BASE)
                    if os.path.isdir(os.path.join(BASE, d)) and d not in SKIP
                    and os.path.isfile(os.path.join(BASE, d, "SKILL.md")))
    if not skills:
        print("no skills found"); return 1
    for s in skills:
        check(os.path.join(BASE, s))
    print(f"checked {len(skills)} skills: {len(fails)} failures, {len(warns)} warnings")
    for w in warns:
        print("WARN:", w)
    for f in fails:
        print("FAIL:", f)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
