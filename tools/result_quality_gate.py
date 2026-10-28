#!/usr/bin/env python3
"""result_quality_gate.py — Worker result gating (ported, CTF-adapted).

Usage:
  result_quality_gate.py results/result-NNN-*.md [...] [--validate-state] [--check-consistency] [--all]
    [--transcript <log>] [--flag-file <path>]
Exit 0=pass, 1=fail, 2=warnings-only. Worst wins. Never writes state.

Phase detect: surface.json→triage(0); recon sweep→recon(1); CP-*.profile→analysis(2);
EXP-→exploit(3); FLAG-/Validation→validate(4); writeup→writeup(5); else unknown (warn+skip).
All results require ## Status + a (CHAL|CP|EXP|FLAG)-XXX id.
Exploit results additionally require ## Evidence + ## Verdict with CONFIRMED|NEGATIVE|PARTIAL.
CONFIRMED additionally requires --flag-file passing flag_checker.py (decontamination:
no regex match on real output = no claim).
--transcript runs stall_detector.py (STALL → warning + printed action).
--validate-state checks state.json schema + status enums.
--check-consistency cross-checks counts vs EXP-*.confirmed.md / flag.txt / FLAG-*.validated.md (tolerance 1).
"""
import glob, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ID_RE = re.compile(r"\b(CHAL|CP|EXP|FLAG)-[A-Za-z0-9]+\b")
VERDICT_RE = re.compile(r"\b(CONFIRMED|NEGATIVE|PARTIAL)\b")
PHASE_KEYS = {
    0: ("surface.json", "triage"),
    1: ("recon", "recon"),
    2: ("CP-", "analysis"),
    3: ("EXP-", "exploit"),
    4: ("FLAG-", "validate"),
    5: ("writeup", "writeup"),
}

def detect_phase(text):
    if "surface.json" in text:
        return 0
    if "FLAG-" in text or "## Validation" in text:
        return 4
    if "EXP-" in text:
        return 3
    if "CP-" in text:
        return 2
    if re.search(r"recon|sweep|gobuster|ffuf|nuclei", text, re.I):
        return 1
    if "writeup" in text.lower():
        return 5
    return -1

def check_result(path, flag_file, transcript, flag_regex=None):
    errors, warns = [], []
    if not os.path.isfile(path):
        return [f"missing {path}"], []
    text = open(path, errors="ignore").read()
    if "## Status" not in text:
        errors.append("missing ## Status")
    if not ID_RE.search(text):
        errors.append("no CHAL/CP/EXP/FLAG id")
    ph = detect_phase(text)
    if ph == -1:
        warns.append("unknown phase — skipped deep checks")
        return errors, warns
    if ph == 3:
        if "## Evidence" not in text:
            errors.append("exploit result missing ## Evidence")
        if "## Verdict" not in text:
            errors.append("exploit result missing ## Verdict")
        m = VERDICT_RE.search(text)
        if not m:
            errors.append("verdict must be CONFIRMED|NEGATIVE|PARTIAL")
        elif m.group(1) == "CONFIRMED":
            if not flag_file or not os.path.isfile(flag_file):
                errors.append("CONFIRMED requires --flag-file <existing flag.txt>")
            else:
                checker = [sys.executable, os.path.join(ROOT, "tools", "flag_checker.py"),
                           "--file", flag_file]
                if flag_regex:
                    checker += ["--regex", flag_regex]
                r = subprocess.run(checker, capture_output=True, text=True)
                if r.returncode != 0:
                    errors.append(f"CONFIRMED but answer-format checker rejected {flag_file}")
                elif flag_regex:
                    warns.append("format check passed; this is syntax evidence only, not proof of challenge acceptance")
        if "NEGATIVE" in text and len(text) < 300:
            warns.append("NEGATIVE with thin evidence (<300 chars) — add commands + reason")
    if ph == 4 and "FLAG-" in text and "validated" not in text.lower():
        warns.append("validation result should reference the validated proof")
    if transcript:
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "stall_detector.py"),
                            "--log", transcript], capture_output=True, text=True)
        if r.returncode == 1:
            warns.append("stall_detector: STALL — " + (r.stdout.strip().splitlines() or [""])[-1])
    return errors, warns

def check_state_schema():
    errors, warns = [], []
    try:
        st = json.load(open(os.path.join(ROOT, "state.json")))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return [f"state.json unreadable: {e}"], []
    for k in ("competition", "challenges", "triage", "recon", "analysis",
              "exploiting", "validating", "writeups", "flags", "_concurrency", "_settings"):
        if k not in st:
            errors.append(f"state.json missing key {k}")
    for ph in ("triage", "recon", "analysis", "exploiting", "validating", "writeups"):
        s = st.get(ph, {}).get("status")
        if s not in ("not_started", "in_progress", "complete"):
            errors.append(f"{ph}.status invalid: {s}")
    if st.get("competition", {}).get("status") not in ("active", "paused", "complete"):
        errors.append("competition.status invalid")
    if "_attempt_log" not in st and st.get("exploiting", {}).get("attempts", 0) > 0:
        warns.append("attempts>0 but no _attempt_log — ledger out of sync")
    return errors, warns

def check_consistency():
    warns = []
    try:
        st = json.load(open(os.path.join(ROOT, "state.json")))
    except (FileNotFoundError, json.JSONDecodeError):
        return ["state.json unreadable"]
    conf_files = glob.glob(os.path.join(ROOT, "challenges", "*", "*", "exploits", "EXP-*.confirmed.md"))
    if abs(st.get("exploiting", {}).get("confirmed", 0) - len(conf_files)) > 1:
        warns.append(f"confirmed count {st.get('exploiting', {}).get('confirmed')} vs {len(conf_files)} files")
    val_files = glob.glob(os.path.join(ROOT, "challenges", "*", "*", "FLAG-*.validated.md"))
    if abs(st.get("validating", {}).get("validated_count", 0) - len(val_files)) > 1:
        warns.append("validated count vs FLAG-*.validated.md files differ")
    for f in st.get("flags", []):
        if not os.path.isfile(os.path.join(ROOT, f.get("flag_file", "NOPE"))):
            warns.append(f"flag file missing for {f.get('chal_id')}: {f.get('flag_file')}")
    return warns

def main():
    args, do_state, do_cons, transcript, flag_file, flag_regex = [], False, False, None, None, None
    it = iter(sys.argv[1:])
    for x in it:
        if x == "--validate-state":
            do_state = True
        elif x == "--check-consistency":
            do_cons = True
        elif x == "--all":
            do_state = do_cons = True
            args += glob.glob(os.path.join(ROOT, "results", "result-*.md"))
        elif x == "--transcript":
            transcript = next(it, None)
        elif x == "--flag-file":
            flag_file = next(it, None)
        elif x == "--flag-regex":
            flag_regex = next(it, None)
        else:
            args.append(x)
    if not args and not (do_state or do_cons) or "--help" in sys.argv:
        print("usage: result_quality_gate.py <result.md> [...] [--validate-state] [--check-consistency] [--all] [--transcript L] [--flag-file F] [--flag-regex REGEX]")
        return 0 if "--help" in sys.argv else 1
    worst, n_err, n_warn = 0, 0, 0
    for f in args:
        errs, warns = check_result(f, flag_file, transcript, flag_regex)
        for w in warns:
            print(f"WARN {f}: {w}"); n_warn += 1
        for e in errs:
            print(f"FAIL {f}: {e}"); n_err += 1
        if errs:
            worst = 1
        elif warns:
            worst = max(worst, 2)
        else:
            print(f"✓ {f} → PASS")
    if do_state:
        errs, warns = check_state_schema()
        for e in errs:
            print(f"FAIL state: {e}"); n_err += 1
        for w in warns:
            print(f"WARN state: {w}"); n_warn += 1
        worst = 1 if errs else max(worst, 2 if warns else 0)
    if do_cons:
        cw = check_consistency()
        for w in cw:
            print(f"WARN consistency: {w}"); n_warn += 1
        worst = max(worst, 2 if cw else 0)
    print(f"QUALITY GATE SUMMARY: {n_err} errors, {n_warn} warnings → "
          + ("✗ FAIL" if worst == 1 else "⚠ PASS WITH WARNINGS" if worst == 2 else "✓ PASS"))
    return worst

if __name__ == "__main__":
    sys.exit(main())
