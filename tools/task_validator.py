#!/usr/bin/env python3
"""task_validator.py — pre-dispatch task validation (ported, CTF-adapted).

Usage:
  task_validator.py tasks/task-NNN-*.md [...] | --all-pending
Exit 0=VALID (dispatch), 1=INVALID (do not dispatch), 2=valid-with-warnings.
Worst code wins. Never writes state.

Rules:
 1. Structure: ## Objective, ## Scope, ## Budget, ## Stop condition (error each).
 2. Skill refs skills/... must exist (error); mentioned surface.json / CP-*.profile.yaml
    must exist (surface=error, profile=error).
 3. Single-hypothesis: >1 distinct EXP-XXX → error (anti-bundle). Exploit task with
    no EXP id → warning. Hallucinated multi-observation claims
    ("Observation 2", "Step 4 result:") → error (anti-soliloquy: thought→1 action→wait obs).
 4. Dedup: EXP in testing.tested_exp_ids → error; exploits/EXP-*.{confirmed,negative,partial}.md
    exists → error; EXP attempts >= max_retries → error (budget exhausted → escalate).
 5. Timeout/stop wording (timeout/120s/stop condition) absent → warning.
"""
import glob, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXP_RE = re.compile(r"\bEXP-(\d{3})\b")
SKILL_RE = re.compile(r"skills/[A-Za-z0-9_.\-/]+SKILL\.md|skills/[A-Za-z0-9_\-/]+(?=[\s\n\"'])")
SURFACE_RE = re.compile(r"[\w\-/]*surface\.json")
PROFILE_RE = re.compile(r"[\w\-/]*CP-\d{3}\.profile\.yaml")
SOLILOQUY_RE = re.compile(r"(Observation\s+[2-9]|Step\s+[2-9]\s+result|as observed above.*exploit succeeded)", re.I)

def load_state():
    try:
        return json.load(open(os.path.join(ROOT, "state.json")))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def attempts_for(st, exp):
    return [e for e in st.get("_attempt_log", []) if e.get("exp_id") == exp]

def validate(path, st):
    errors, warns = [], []
    if not os.path.isfile(path):
        return [f"missing file {path}"], []
    text = open(path, errors="ignore").read()
    for sec in ("## Objective", "## Scope", "## Budget", "## Stop condition"):
        if sec not in text:
            errors.append(f"missing section {sec}")
    for ref in set(SKILL_RE.findall(text)):
        ref = ref if ref.endswith("SKILL.md") else ref.rstrip("/") + "/SKILL.md"
        if not os.path.isfile(os.path.join(ROOT, ref)):
            errors.append(f"skill ref missing: {ref}")
    for ref in set(SURFACE_RE.findall(text)):
        # Triage tasks PRODUCE surface.json — it is an output, not an input ref.
        if "triage" in os.path.basename(path).lower() or "skills/triage/" in text:
            continue
        if not os.path.isfile(ref if os.path.isabs(ref) else os.path.join(ROOT, ref)):
            errors.append(f"surface.json ref missing: {ref}")
    for ref in set(PROFILE_RE.findall(text)):
        if not os.path.isfile(ref if os.path.isabs(ref) else os.path.join(ROOT, ref)):
            errors.append(f"profile ref missing: {ref}")
    exps = sorted(set(EXP_RE.findall(text)))
    if len(exps) > 1:
        errors.append(f"multi-hypothesis task (EXP-{', EXP-'.join(exps)}) — split 1 hypothesis = 1 task")
    if "exploit" in os.path.basename(path).lower() and not exps:
        warns.append("exploit task with no EXP id")
    if SOLILOQUY_RE.search(text):
        errors.append("soliloquy markers found — task must not contain pre-written observations")
    tested = set(st.get("exploiting", {}).get("tested_exp_ids", []))
    maxr = st.get("_settings", {}).get("max_retries_per_hypothesis", 3)
    for e in exps:
        exp = f"EXP-{e}"
        if exp in tested:
            errors.append(f"{exp} already tested — dedup, do not re-dispatch")
        if any(glob.glob(os.path.join(ROOT, p)) for p in
               [f"challenges/*/*/exploits/{exp}.{v}.md" for v in ("confirmed", "negative", "partial")]):
            errors.append(f"{exp} already has a verdict artifact")
        n = len([x for x in attempts_for(st, exp) if x.get("verdict") != "confirmed"])
        if n >= maxr:
            errors.append(f"{exp} retry budget exhausted ({n}/{maxr}) — escalate, do not retry")
    if not re.search(r"(timeout|120s|stop condition|deadline)", text, re.I):
        warns.append("no timeout/stop wording — add 120s cap + stop condition")
    return errors, warns

def main():
    args = sys.argv[1:]
    if not args or args == ["--help"]:
        print("usage: task_validator.py <task.md> [...] | --all-pending")
        return 0
    files = sorted(glob.glob(os.path.join(ROOT, "tasks", "task-*.md"))) if args == ["--all-pending"] else args
    if not files:
        print("[INFO] no task files")
        return 0
    st = load_state()
    worst = 0
    for f in files:
        errs, warns = validate(f, st)
        for w in warns:
            print(f"⚠ {f}: {w}")
        for e in errs:
            print(f"✗ {f}: {e}")
        if errs:
            print(f"RESULT: {f} → INVALID"); worst = 1
        elif warns:
            print(f"RESULT: {f} → VALID WITH WARNINGS"); worst = max(worst, 2)
        else:
            print(f"✓ {f} → VALID")
    return worst

if __name__ == "__main__":
    sys.exit(main())
