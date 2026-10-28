#!/usr/bin/env python3
"""bench.py — framework benchmark: unit + triage-accuracy + gate behavior.

Usage: python3 tools/bench.py [--only T1|T2|T3] [--keep-tmp]
Read-only vs real state (all outputs to /tmp/bench-*). Exit 0=all pass, 1=any fail.
Prints a scored table with per-test seconds (FST-style timing).
"""
import json, os, shutil, struct, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "eval", "fixtures")
TMP = tempfile.mkdtemp(prefix="bench-")
RESULTS = []

def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                       cwd=ROOT, **kw)
    return p.returncode, (p.stdout + p.stderr)[-3000:]

def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail[:160]))
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail[:100]}")

def setup_case(name, files):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    for rel, data in files.items():
        fp = os.path.join(d, rel)
        os.makedirs(os.path.dirname(fp) or d, exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(fp, mode) as f:
            f.write(data)
    return d

def triage_case(name, files, expect, extra=()):
    d = setup_case(name, files)
    if name == "pwn":
        src = os.path.join(FIX, "pwn", "vuln.c")
        shutil.copy(src, os.path.join(d, "vuln.c"))
        rc, _ = run(["gcc", "-o", os.path.join(d, "vuln"), os.path.join(d, "vuln.c")])
        if rc != 0:
            return check(f"triage:{name}", False, "gcc failed")
    if name == "rev":
        src = os.path.join(FIX, "rev", "check.c")
        shutil.copy(src, os.path.join(d, "check.c"))
        rc, _ = run(["gcc", "-o", os.path.join(d, "check"),
                     os.path.join(d, "check.c")])
        if rc != 0:
            return check(f"triage:{name}", False, "gcc failed")
    out = os.path.join(d, "surface.json")
    rc, txt = run(["python3", "tools/triage.py", "--given", d,
                   "--chal-id", "BENCH", "--out", out, *extra])
    cat = None
    for line in txt.splitlines():
        try:
            cat = json.loads(line).get("category")
            break
        except (ValueError, AttributeError):
            pass
    ok = cat == expect
    dom_ok = True
    if ok and os.path.isfile(out):
        dom_ok = json.load(open(out)).get("domain") == (expect if expect in
            ("web-ctf", "pwn", "rev", "crypto", "forensics", "stego", "misc-pyjail",
             "osint", "hardware", "blockchain", "mobile", "ai-ml") else "_inbox")
    check(f"triage:{name}", ok and dom_ok, f"got={cat} want={expect}")

def pcap_bytes():
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pkt = b"\x00" * 42
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return gh + rec

def t1_unit():
    t0 = time.time()
    rc, _ = run(["python3", "-m", "py_compile"] + sorted(
        [os.path.join("tools", f) for f in os.listdir(os.path.join(ROOT, "tools"))
         if f.endswith(".py")]))
    check("unit:py_compile", rc == 0)
    rc, _ = run(["python3", "tools/skill_lint.py"])
    check("unit:skill_lint", rc == 0)
    rc, _ = run(["python3", "tools/framework_lint.py", "--strict"])
    check("unit:framework_lint", rc == 0)
    rc, _ = run(["python3", "-m", "engine", "selftest"])
    check("engine:selftest", rc == 0)
    rc, _ = run(["bash", "-c", "echo 'picoCTF{x}' | python3 tools/flag_checker.py --stdin"])
    check("unit:flag_pos", rc == 0)
    rc, _ = run(["bash", "-c", "echo deadbeef | python3 tools/flag_checker.py --stdin"])
    check("unit:flag_neg", rc != 0)
    rc, _ = run(["python3", "tools/stall_detector.py", "--cmd-history", "nmap x|ffuf y"])
    check("unit:stall_continue", rc == 0)
    log = os.path.join(TMP, "stall.log")
    open(log, "w").write("Traceback x\nError y\nTraceback x\nError z\nTraceback x\ngive up\n")
    rc, _ = run(["python3", "tools/stall_detector.py", "--log", log,
                 "--cmd-history", "nmap x|nmap x|nmap x"])
    check("unit:stall_fires", rc == 1)
    rc, _ = run(["python3", "tools/new_challenge.py", "--domain", "web", "--chal", "CHAL-001"])
    check("unit:newchal_bad_domain", rc == 2)
    rc, _ = run(["python3", "tools/recon_to_analysis_handoff.py",
                 "--challenges-dir", os.path.join(TMP, "empty")])
    check("unit:handoff_empty", rc == 1)
    rc, out = run(["python3", "tools/hypothesis_deduplicator.py",
                   "--profiles-dir", os.path.join(TMP, "empty")])
    check("unit:dedup_empty", rc == 0 and "no hypotheses" in out)
    rc, _ = run(["./setup_ctf.sh", "--status"])
    check("unit:setup_status", rc == 0)
    rc, _ = run(["python3", "tools/browser_extract.py", "--list",
                 "--base-url", "https://example.com", "--dry-run"])
    check("unit:extract_dryrun", rc == 0)
    print(f"T1 done in {time.time()-t0:.1f}s")

def t2_triage():
    t0 = time.time()
    def cp(*parts):
        with open(os.path.join(FIX, *parts), "rb") as f:
            return f.read()
    triage_case("crypto", {"enc.py": cp("crypto", "enc.py"), "key.pub": cp("crypto", "key.pub")}, "crypto")
    triage_case("misc", {"jail.py": cp("misc", "jail.py")}, "misc-pyjail")
    triage_case("pwn", {}, "pwn")
    triage_case("rev", {}, "rev")
    triage_case("forensics-pcap", {"cap.pcap": pcap_bytes()}, "forensics")
    triage_case("forensics-disk", {"disk.img": b"\0" * 512}, "forensics")
    triage_case("stego", {"img.png": b""}, "stego")
    triage_case("web", {"index.html": b"<html></html>"}, "web-ctf",
                extra=("--url", "http://127.0.0.1:9"))
    triage_case("blockchain", {"vault.sol": cp("blockchain", "vault.sol")}, "blockchain")
    triage_case("mobile", {"app.apk": b""}, "mobile")
    triage_case("hardware", {"firmware.bin": b"UART115200\x00" * 64}, "hardware")
    triage_case("ai-ml", {"prompt.txt": cp("ai-ml", "prompt.txt")}, "ai-ml",
                extra=("--url", "http://127.0.0.1:9"))
    triage_case("osint", {"handle.txt": cp("osint", "handle.txt")}, "osint")
    print(f"T2 done in {time.time()-t0:.1f}s")

def t3_gates():
    t0 = time.time()
    bad = setup_case("badtask", {}) + "/task-bad.md"
    open(bad, "w").write("## Objective\ntest EXP-001 and EXP-002 together.\nObservation 2 shows pwned.\n")
    rc, _ = run(["python3", "tools/task_validator.py", bad])
    check("gate:validator_multi", rc == 1)
    rc, _ = run(["python3", "tools/task_validator.py",
                 "tasks/templates/example-task-001-triage.md"])
    check("gate:validator_template", rc == 0)
    flagf = os.path.join(TMP, "flag.txt")
    open(flagf, "w").write("picoCTF{bench}\n")
    good = setup_case("goodres", {}) + "/r.md"
    open(good, "w").write("# r\n## Status: done — EXP-001 BENCH\nChallenge: BENCH\n## Evidence\n- ran timeout 120 python3 solve.py, output matched format, baseline captured, probe confirmed leak shape.\n## Verdict: CONFIRMED\nFlag-File: X\n")
    rc, _ = run(["python3", "tools/result_quality_gate.py", good, "--flag-file", flagf])
    check("gate:confirmed", rc == 0)
    thin = setup_case("thinres", {}) + "/r.md"
    open(thin, "w").write("# r\n## Status: done — EXP-001 BENCH\n## Evidence\nnope.\n## Verdict: NEGATIVE\n")
    rc, _ = run(["python3", "tools/result_quality_gate.py", thin])
    check("gate:thin_warn", rc == 2)
    rc, _ = run(["python3", "tools/result_quality_gate.py", good])
    check("gate:noflag_fail", rc == 1)
    rc, _ = run(["python3", "tools/result_quality_gate.py", "--validate-state",
                 "--check-consistency"])
    check("gate:state_consistent", rc == 0)
    print(f"T3 done in {time.time()-t0:.1f}s")

def orphan_zip(path):
    """Craft zip with a TRUE orphan: two local headers, central lists only keep.txt."""
    import struct
    import zlib

    def local(name, body):
        comp = zlib.compress(body, 6)
        raw = comp[2:-4]  # strip zlib header/trailer for raw deflate
        lh = (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 8, 0, 0, 0,
                                          len(raw), len(body), len(name), 0)
              + name + raw)
        return lh, (name, len(raw), len(body))

    def central(name, csize, usize, lho):
        return (b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0, 8,
                                            0, 0, 0, 0, csize, usize,
                                            len(name), 0, 0, 0, 0, lho) + name)

    lh1, _ = local(b"gone.txt", b"FLAG{bench_orphan_000}\n")  # orphan: no central
    lh2, (nm2, cs2, us2) = local(b"keep.txt", b"nothing\n")
    cd = central(nm2, cs2, us2, len(lh1))
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(cd),
                                      len(lh1) + len(lh2), 0)
    open(path, "wb").write(lh1 + lh2 + cd + eocd)

def t4_livetools():
    t0 = time.time()
    import shutil as _sh
    bak = os.path.join(TMP, "state.bak.json")
    _sh.copy(os.path.join(ROOT, "state.json"), bak)
    try:
        oz = os.path.join(TMP, "orphan.zip")
        orphan_zip(oz)
        rc, out = run(["python3", "tools/zip_forensics.py", oz, "--carve-dir",
                       os.path.join(TMP, "carve"), "--json"])
        ok = rc == 0 and "orphan-entry" in out and "flag-shaped" in out
        check("live:zip_orphan", ok, out.splitlines()[0][:80] if out else "")
        rc, out = run(["python3", "tools/answer_forge.py", "--chal", "CHAL-BENCH",
                       "--evidence", "username=testuser", "--evidence", "kind=handle"])
        check("live:forge_evidence", rc == 0)
        rc, out = run(["python3", "tools/answer_forge.py", "--chal", "CHAL-BENCH", "--propose"])
        check("live:forge_propose", rc == 0 and "FLAG{testuser}" in out)
        for i in range(5):
            run(["python3", "tools/answer_forge.py", "--chal", "CHAL-BENCH",
                 "--tried", f"FLAG{{guess{i}}}", "--verdict", "rejected"])
        rc, out = run(["python3", "tools/answer_forge.py", "--chal", "CHAL-BENCH",
                       "--tried", "FLAG{one-more}", "--verdict", "rejected"])
        check("live:forge_cap", rc == 3 and "STOP" in out)
        rc, out = run(["python3", "tools/state_manager.py", "submits", "CHAL-BENCH"])
        check("live:submit_ledger", rc == 0 and "guess0" in out)
        for tool in ("session_check", "submit", "instance", "btabs", "answer_forge"):
            rc, _ = run(["python3", f"tools/{tool}.py", "--help"])
            check(f"live:help_{tool}", rc == 0)
        rc, _ = run(["python3", "-c", "import json;json.load(open('opencode.json'))"])
        check("live:opencode_valid", rc == 0)
        rc, out = run(["python3", "tools/rag_lookup.py", "--query", "tcache poison safe-linking",
                       "--domain", "pwn", "--top", "3"])
        check("live:rag_tfidf", rc == 0 and "rel=" in out)
        rc, out = run(["python3", "tools/model_router.py", "--check"])
        check("live:router_honest", rc in (0, 1) and ("UNCONFIGURED" in out or "OK:" in out))
        rc, out = run(["python3", "tools/race.py", "--chal", "CHAL-BENCH",
                       "--plan", os.path.join(TMP, "race.json"), "--lanes", "3"])
        ok = rc == 0
        try:
            plans = json.load(open(os.path.join(TMP, "race.json")))
            ok = ok and len(plans) == 3 and plans[0]["angle"] != plans[1]["angle"]
        except (OSError, ValueError, KeyError):
            ok = False
        check("live:race_plan", ok)
        rc, _ = run(["python3", "tools/race.py", "--chal", "CHAL-BENCH",
                     "--bus-note", "bench probe", "--from", "bench"])
        check("live:race_bus", rc == 0)
        rc, _ = run(["python3", "tools/mcp_doctor.py"])
        check("live:doctor_backends", rc == 0)
        for tool in ("rev_ghidra", "session_run", "race", "rag_lookup", "model_router"):
            rc, _ = run(["python3", f"tools/{tool}.py", "--help"])
            check(f"live:help_{tool}", rc == 0)
    finally:
        _sh.copy(bak, os.path.join(ROOT, "state.json"))
    print(f"T4 done in {time.time()-t0:.1f}s")

def main():
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else "T1T2T3T4"
    t0 = time.time()
    if "T1" in only:
        t1_unit()
    if "T2" in only:
        t2_triage()
    if "T3" in only:
        t3_gates()
    if "T4" in only:
        t4_livetools()
    npass = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"\nBENCH: {npass}/{len(RESULTS)} pass in {time.time()-t0:.1f}s")
    for name, ok, detail in RESULTS:
        if not ok:
            print(f"  FAILED: {name} {detail}")
    if "--keep-tmp" not in sys.argv:
        shutil.rmtree(TMP, ignore_errors=True)
    for junk in (os.path.join(ROOT, "results", "bus", "CHAL-BENCH.jsonl"),):
        try:
            os.remove(junk)
        except OSError:
            pass
    return 0 if npass == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
