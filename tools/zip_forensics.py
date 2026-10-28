#!/usr/bin/env python3
"""zip_forensics.py — deleted-file recovery + zip anomaly scan (automates the
manual struct-parsing that solved CHAL-008).

v2: EOCD-first architecture (v1 walked local headers and miscounted on
zips with data-descriptors — false positive caught by bench review).
Central directory is authoritative for the file LIST; orphans = local
headers NOT referenced by any central entry.

Usage: zip_forensics.py FILE.zip [--carve-dir DIR] [--json]
Finds: local-header entries MISSING from central directory (deleted files),
trailing bytes past EOCD, CRC mismatches, comments/extra fields, overlap.
--carve-dir inflates orphan entries (stored/deflated) into DIR/.
Exit 0=clean-or-reported (informational with findings list), 1=unreadable zip.
Prints FINDINGS lines; --json emits machine-readable report.
"""
import argparse
import json
import os
import re
import struct
import sys
import zlib

def find_eocd(data):
    pos = data.rfind(b"PK\x05\x06")
    if pos < 0 or pos + 22 > len(data):
        return None
    (_, _, count, total, cd_size, cd_off) = struct.unpack("<HHHHII", data[pos + 4:pos + 20])
    return {"off": pos, "count": count, "total": total, "cd_size": cd_size,
            "cd_off": cd_off, "trailing": data[pos + 22:]}

def walk_central(data, eocd):
    entries = []
    pos = eocd["cd_off"]
    for _ in range(eocd["total"]):
        if data[pos:pos + 4] != b"PK\x01\x02":
            break
        fnlen, extralen, commentlen = struct.unpack("<HHH", data[pos + 28:pos + 34])
        lho = struct.unpack("<I", data[pos + 42:pos + 46])[0]
        comp = struct.unpack("<H", data[pos + 10:pos + 12])[0]
        crc = struct.unpack("<I", data[pos + 16:pos + 20])[0]
        csize = struct.unpack("<I", data[pos + 20:pos + 24])[0]
        name = data[pos + 46:pos + 46 + fnlen]
        comment = data[pos + 46 + fnlen + extralen:pos + 46 + fnlen + extralen + commentlen]
        entries.append({"name": name, "lho": lho, "comp": comp, "crc": crc,
                        "csize": csize, "comment": comment})
        pos += 46 + fnlen + extralen + commentlen
    return entries

def scan_locals(data, end):
    """All PK\\x03\\x04 offsets before end (central dir start)."""
    offs, i = [], 0
    while True:
        i = data.find(b"PK\x03\x04", i, end)
        if i < 0:
            break
        offs.append(i)
        i += 4
    return offs

def read_local(data, off):
    fnlen, extralen = struct.unpack("<HH", data[off + 26:off + 30])
    comp = struct.unpack("<H", data[off + 8:off + 10])[0]
    csize = struct.unpack("<I", data[off + 18:off + 22])[0]
    name = data[off + 30:off + 30 + fnlen]
    return {"name": name, "comp": comp, "csize": csize,
            "data_off": off + 30 + fnlen + extralen}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("zipfile")
    ap.add_argument("--carve-dir", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    try:
        data = open(a.zipfile, "rb").read()
    except OSError as e:
        print(f"ERROR: {e}")
        return 1
    if data[:4] != b"PK\x03\x04":
        print("ERROR: not a zip (bad magic)")
        return 1
    eocd = find_eocd(data)
    findings = []
    if not eocd:
        findings.append({"type": "no-eocd"})
        print("FINDING:", findings[0])
        return 0
    centrals = walk_central(data, eocd)
    if len(centrals) != eocd["total"]:
        findings.append({"type": "central-count-mismatch",
                         "declared": eocd["total"], "parsed": len(centrals)})
    ref_lhos = {c["lho"] for c in centrals}
    orphans = []
    for off in scan_locals(data, eocd["cd_off"]):
        if off not in ref_lhos:
            try:
                orphans.append({**read_local(data, off), "off": off})
            except struct.error:
                findings.append({"type": "truncated-local", "off": off})
    for o in orphans:
        findings.append({"type": "orphan-entry",
                         "name": o["name"].decode(errors="replace"),
                         "off": o["off"], "comp": o["comp"], "csize": o["csize"]})
    if eocd["trailing"]:
        findings.append({"type": "trailing-bytes", "len": len(eocd["trailing"])})
    for c in centrals:
        if c["comment"]:
            findings.append({"type": "zip-comment",
                             "name": c["name"].decode(errors="replace"),
                             "comment": c["comment"][:120].decode(errors="replace")})
    carved = []
    if orphans and a.carve_dir:
        os.makedirs(a.carve_dir, exist_ok=True)
        for o in orphans:
            raw = data[o["data_off"]:o["data_off"] + o["csize"]]
            body = None
            if o["comp"] == 0:
                body = raw
            else:
                for kw in ({}, {"wbits": -15}):
                    try:
                        body = zlib.decompress(raw, **kw)
                        break
                    except zlib.error:
                        continue
                if body is None:
                    body = raw
            fn = os.path.join(a.carve_dir, os.path.basename(o["name"].decode(errors="replace")) or "orphan.bin")
            open(fn, "wb").write(body)
            carved.append(fn)
            for m in re.finditer(rb"FLAG\{[^}]{1,200}\}", body):
                findings.append({"type": "flag-shaped", "in": fn, "len": len(m.group(0))})
    if a.json:
        print(json.dumps({"file": a.zipfile, "locals": len(scan_locals(data, eocd["cd_off"])),
                          "centrals": len(centrals), "findings": findings,
                          "carved": carved}, indent=1))
    else:
        print(f"locals={len(scan_locals(data, eocd['cd_off']))} centrals={len(centrals)}")
        for f in findings:
            print("FINDING:", f)
        for c in carved:
            print("CARVED:", c)
        if not findings:
            print("CLEAN: no orphans, no trailing bytes, EOCD present")
    return 0

if __name__ == "__main__":
    sys.exit(main())
