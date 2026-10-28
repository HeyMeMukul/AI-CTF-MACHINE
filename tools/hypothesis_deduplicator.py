#!/usr/bin/env python3
"""hypothesis_deduplicator.py — cross-profile exploit-hypothesis dedup → EXPLOIT-PRIORITY.md.

Ported from bugbounty-ai-framework-improved (bug fixed: --mark-confirmed SAVES state).
Usage:
  hypothesis_deduplicator.py [--profiles-dir challenges] [--output challenges/EXPLOIT-PRIORITY.md]
    [--mark-confirmed EXP-XXX] [--dry-run]
Exit 0 always (informational), except 1 on unreadable state for --mark-confirmed.

Input: challenges/*/profiles/CP-*.profile.yaml with hypotheses_generated[]:
  {id, type, target, confidence, rationale, suggested_skill}
Score = CONFIDENCE{HIGH:3,MEDIUM:2,LOW:1} x IMPACT{flag-direct:4,leak:3,write:2,info:1,unknown:1}.
Group by (type, normalized target): keep top as unique, rest duplicate (score x0.2).
MAX_LOW_PER_PROFILE=3: excess LOW uniques → auto_low (score 0.1).
Sort: unique(0) → duplicate(1) → auto_low(2), then -score.
"""
import argparse, glob, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
IMPACT = {"flag-direct": 4, "leak": 3, "write": 2, "info": 1, "unknown": 1}
MAX_LOW_PER_PROFILE = 3

def parse_yaml(path):
    """Minimal YAML subset parser (no PyYAML dependency): top-level scalars + one list of maps."""
    data, cur, key = {}, None, None
    for raw in open(path, errors="ignore"):
        line = raw.rstrip("\n")
        if not line.strip() or line.strip().startswith("#"):
            continue
        m = re.match(r"^(\s*)-\s+(.*)$", line)
        if m and cur is not None:
            item, rest = {}, m.group(2)
            kv = re.match(r"(\w+):\s*(.*)$", rest)
            if kv:
                item[kv.group(1)] = kv.group(2).strip().strip("'\"")
            cur.append(item)
            key = cur
            if isinstance(key, list):
                pass
            last = cur[-1]
            data["_last"] = last
            continue
        m = re.match(r"^(\s*)(\w+):\s*(.*)$", line)
        if m:
            indent, k, v = len(m.group(1)), m.group(2), m.group(3).strip().strip("'\"")
            if indent == 0:
                if v == "" or v in ("|", ">"):
                    data[k] = []
                    cur = data[k]
                else:
                    data[k] = v
                    cur = None
            elif cur is not None and "_last" in data and isinstance(data["_last"], dict):
                data["_last"][k] = v
    data.pop("_last", None)
    return data

def impact_of(h):
    t = (h.get("impact") or h.get("type") or "unknown").lower()
    for k in IMPACT:
        if k in t:
            return IMPACT[k]
    if any(w in t for w in ("rce", "sqli", "ssti", "flag")):
        return 4
    if any(w in t for w in ("leak", "oracle", "lfi", "ssrf", "xxe")):
        return 3
    if any(w in t for w in ("write", "upload", "fmt", "overflow", "deser")):
        return 2
    return 1

def norm_target(t):
    t = (t or "").lower()
    t = re.sub(r"/\d+", "/{id}", t)
    t = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{4,}", "{uuid}", t)
    return t.split("(")[0].strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles-dir", default=os.path.join(ROOT, "challenges"))
    ap.add_argument("--output", default=os.path.join(ROOT, "challenges", "EXPLOIT-PRIORITY.md"))
    ap.add_argument("--mark-confirmed", default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.mark_confirmed:
        sp = os.path.join(ROOT, "state.json")
        try:
            st = json.load(open(sp))
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"ERROR: state unreadable: {e}")
            return 1
        tested = st.setdefault("exploiting", {}).setdefault("tested_exp_ids", [])
        if a.mark_confirmed not in tested:
            tested.append(a.mark_confirmed)
            json.dump(st, open(sp, "w"), indent=2)
            print(f"marked {a.mark_confirmed} tested (saved)")
        else:
            print(f"[INFO] {a.mark_confirmed} already tested")
        return 0

    hyps = []
    for prof in sorted(glob.glob(os.path.join(a.profiles_dir, "*", "*", "profiles", "CP-*.profile.yaml"))):
        try:
            d = parse_yaml(prof)
        except (OSError, ValueError) as e:
            print(f"WARN: skip {prof}: {e}", file=sys.stderr)
            continue
        for h in d.get("hypotheses_generated", []) or []:
            if not isinstance(h, dict) or "id" not in h:
                continue
            h["_profile"] = prof
            hyps.append(h)
    if not hyps:
        print("no hypotheses found in any CP-*.profile.yaml")
        return 0

    for h in hyps:
        h["_score"] = CONF.get(h.get("confidence", "LOW").upper(), 1) * impact_of(h)
        h["_key"] = ((h.get("type") or "?").lower(), norm_target(h.get("target")))
    groups = {}
    for h in hyps:
        groups.setdefault(h["_key"], []).append(h)
    for key, g in groups.items():
        g.sort(key=lambda h: -h["_score"])
        g[0]["_status"] = "unique"
        for d in g[1:]:
            d["_status"] = "duplicate"
            d["_score"] = round(d["_score"] * 0.2, 2)
    per_prof_low = {}
    for h in hyps:
        if h["_status"] == "unique" and h.get("confidence", "").upper() == "LOW":
            k = h["_profile"]
            per_prof_low[k] = per_prof_low.get(k, 0) + 1
            if per_prof_low[k] > MAX_LOW_PER_PROFILE:
                h["_status"] = "auto_low"
                h["_score"] = 0.1
    order = {"unique": 0, "duplicate": 1, "auto_low": 2}
    hyps.sort(key=lambda h: (order[h["_status"]], -h["_score"]))

    tested = set()
    try:
        tested = set(json.load(open(os.path.join(ROOT, "state.json"))).get("exploiting", {}).get("tested_exp_ids", []))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    lines = ["# EXPLOIT-PRIORITY", ""]
    cur_sec = None
    active = 0
    for h in hyps:
        if h["_status"] != cur_sec:
            cur_sec = h["_status"]
            lines += [f"## {cur_sec}", "", "|ID|Type|Target|Profile|Confidence|Priority|Notes|", "|---|---|---|---|---|---|---|"]
        note = "ALREADY-TESTED — skip" if h["id"] in tested else (h.get("rationale", "")[:60])
        if h["id"] not in tested and h["_status"] == "unique":
            active += 1
        lines.append(f"|{h['id']}|{h.get('type')}|{h.get('target')}|"
                     f"{os.path.basename(h['_profile'])}|{h.get('confidence')}|{h['_score']}|{note}|")
    lines += ["", f"Summary: {len(hyps)} total, {active} active-unique. Dispatch top unique first, 1 hypothesis = 1 task."]
    out = "\n".join(lines) + "\n"
    if a.dry_run:
        print(out)
    else:
        os.makedirs(os.path.dirname(a.output), exist_ok=True)
        open(a.output, "w").write(out)
        print(f"Loaded {len(set(h['_profile'] for h in hyps))} profiles / Extracted {len(hyps)} / "
              f"Written to {a.output} / Active {active}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
