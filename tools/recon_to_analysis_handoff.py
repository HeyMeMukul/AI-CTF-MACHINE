#!/usr/bin/env python3
"""recon_to_analysis_handoff.py — surface.json(s) → CHALLENGE-PRIORITY-LIST.md + target_inventory.json.

Ported from spider_to_mapping_handoff.py (CTF-adapted; auth/unauth + WAF dropped).
Usage:
  recon_to_analysis_handoff.py [--challenges-dir challenges] [--max-batch 3]
    [--output challenges/CHALLENGE-PRIORITY-LIST.md] [--json-output challenges/target_inventory.json]
Exit 1 if no surface.json found, else 0. Lead reads the .md (~100 lines), never raw files.

Score: confidence HIGH 5 / MEDIUM 3 / LOW 1; free-win signals +8; live service +3;
points/100 capped at +5. Tier >=12 T1-Critical, >=7 T2-High, >=3 T3-Medium, else T4-Low.
Batch groups of --max-batch (default = _settings.max_mapping_batch=3).
"""
import argparse, glob, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF_SCORE = {"HIGH": 5, "MEDIUM": 3, "LOW": 1}

def load_settings():
    try:
        return json.load(open(os.path.join(ROOT, "state.json"))).get("_settings", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenges-dir", default=os.path.join(ROOT, "challenges"))
    ap.add_argument("--max-batch", type=int, default=None)
    ap.add_argument("--output", default=os.path.join(ROOT, "challenges", "CHALLENGE-PRIORITY-LIST.md"))
    ap.add_argument("--json-output", default=os.path.join(ROOT, "challenges", "target_inventory.json"))
    a = ap.parse_args()
    if a.max_batch is None:
        a.max_batch = load_settings().get("max_mapping_batch", 3)

    surfaces = sorted(glob.glob(os.path.join(a.challenges_dir, "*", "*", "surface.json")))
    if not surfaces:
        print("ERROR: no surface.json found — run triage first")
        return 1
    items = []
    for sp in surfaces:
        try:
            s = json.load(open(sp))
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARN: skip {sp}: {e}", file=sys.stderr)
            continue
        score, reasons = 0, []
        c = CONF_SCORE.get(s.get("confidence", "LOW").upper(), 1)
        score += c
        reasons.append(f"confidence {s.get('confidence')} (+{c})")
        sigs = " ".join(s.get("signals", [])).lower()
        if "free" in sigs and "win" in sigs:
            score += 8
            reasons.append("free-win strings hit (+8)")
        if s.get("service"):
            score += 3
            reasons.append("live service (+3)")
        pts = min(5, (s.get("points") or 0) // 100)
        if pts:
            score += pts
            reasons.append(f"points {s.get('points')} (+{pts})")
        tier = "T1-Critical" if score >= 12 else "T2-High" if score >= 7 else "T3-Medium" if score >= 3 else "T4-Low"
        items.append({"chal": s.get("chal_id"), "category": s.get("category"),
                      "route": s.get("route"), "score": score, "tier": tier,
                      "reasons": "; ".join(reasons), "surface": sp})
    items.sort(key=lambda x: -x["score"])
    for i, it in enumerate(items):
        it["batch"] = i // a.max_batch + 1

    md = ["# CHALLENGE-PRIORITY-LIST", ""]
    cur = None
    for it in items:
        if it["batch"] != cur:
            cur = it["batch"]
            md += [f"## Batch {cur} (analyze: /analyze {', '.join(x['chal'] for x in items if x['batch'] == cur)})", "",
                   "|Challenge|Category|Route|Tier|Score|Reasons|", "|---|---|---|---|---|---|"]
        md.append(f"|{it['chal']}|{it['category']}|{it['route']}|{it['tier']}|{it['score']}|{it['reasons']}|")
    md += ["", f"Total {len(items)} challenges in {(len(items) + a.max_batch - 1) // a.max_batch} batches. "
               "Lead: dispatch batch-by-batch; Workers write CP-XXX.profile.yaml per target."]
    os.makedirs(os.path.dirname(a.output), exist_ok=True)
    open(a.output, "w").write("\n".join(md) + "\n")
    inv = {"challenges": items, "total": len(items), "max_batch": a.max_batch}
    open(a.json_output, "w").write(json.dumps(inv, indent=2))
    print(f"prioritized {len(items)} challenges → {a.output}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
