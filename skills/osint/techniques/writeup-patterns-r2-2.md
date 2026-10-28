# OSINT R2 Patterns — Identity / Metadata / Chain Methods (W46–W55)

> Methods-only. Fictional CTF targets. Each pattern: signals → steps →
> commands → pitfalls → 2–3 R2 source URLs (all in
> `knowledge/writeups_mined/osint_manifest_r2.md`, zero R1 overlap).

### W46 — Credential-reuse + provided-dump join (fictional only)
- Signals: persona email + prior secret; vault/file unlock inside challenge scope.
- Steps: 1) breach-wordlist build from persona hints 2) join against PROVIDED dump 3) type-identify hash 4) bounded offline crack (≤120s) 5) use ONLY in challenge artifact.
- Commands: `grep -Ff emails.txt provided_breach.csv` ; `hashid -m '<hex>'` ; `john --wordlist=rebuilt.txt item.hash`
- Pitfalls: live-breach APIs (never); rockyou-first ignores hint constraints.
- Sources: https://github.com/DivyanshuProjects/CTF-TRYHACKME-HACKTHEBOX-writeup/blob/main/TryHackMe%20-%20OhSINT.md ; https://github.com/Saqlain143/Osint-KeebarSecurityGroup ; https://tmc222.medium.com/patriot-ctf-2025-challenge-writeups-4aff5aa64220

### W47 — Sockpuppet-graph follower/following walk
- Signals: starter profile, quiet bio; asks hidden watcher/bio find.
- Steps: 1) follower list walk 2) following-list walk 3) interaction-time filter (decoys postdate event) 4) watcher-bio read 5) platform search sweep for same bio.
- Commands: quoted-handle + platform search; archive check for deleted shares.
- Pitfalls: player-planted decoys (check timestamps); display-name vs handle confusion.
- Sources: https://0xdarkeagle.medium.com/uiuctf-2025-dc58015f02ea ; https://medium.com/@pr0fan4xa/uiuctf-2025-writeup-98f7426b56e4 ; https://osintteam.blog/osint-writeups-mist-cyber-drill-2025-2d1e398a4672

### W48 — Snowflake/ID-epoch timestamp math
- Signals: long numeric IDs in chat/CDN links; asks start/upload times.
- Steps: 1) split channel-ID vs file-ID 2) epoch convert `(id>>22)+1420070400000` 3) first-index (create) vs file-branch (upload) semantics 4) unfurl cross-check.
- Commands: `python3 -c "print((ID>>22)+1420070400000)"` ; unfurl parse.
- Pitfalls: channel-create ≠ first-message; CDN expiry params are NOT timestamps.
- Sources: https://github.com/sdpslu/hackthebox-writeup/blob/main/Categories/Sherlocks/Constellation/README.md ; https://dimitrisper.xyz/posts/writeups/constellation ; https://medium.com/@nikitha7390/scriptctf-osint-challenges-writeup-69a58d96737d

### W49 — Search-URL session-token timeline
- Signals: pasted search-engine URLs from two sessions; asks query order/times.
- Steps: 1) split `q` (final) vs `oq`/`typed` per link 2) session/time tokens decode 3) order both sessions 4) align against file-event times.
- Commands: URL-decode params; unfurl session branches; timeline table.
- Pitfalls: params rotate over time; single-token dating without corroboration.
- Sources: https://github.com/sdpslu/hackthebox-writeup/blob/main/Categories/Sherlocks/Constellation/README.md ; https://dimitrisper.xyz/posts/writeups/constellation ; https://0xdarkeagle.medium.com/uiuctf-2025-dc58015f02ea

### W50 — Doc-property author + anomaly trio
- Signals: provided PDF/notice/image; asks author or "what is off".
- Steps: 1) `exiftool -a -G1` + `pdfinfo` 2) read author/title/producer/created 3) impossible-date = tamper signal 4) author-token → profile search (needs second source).
- Commands: `exiftool -a -G1 doc.pdf` ; `pdfinfo doc.pdf` ; `exiftool -Title -Author -Producer -CreateDate doc.pdf`
- Pitfalls: all fields forgeable; viewer-vs-embedded confusion.
- Sources: https://dimitrisper.xyz/posts/writeups/constellation ; https://github.com/sdpslu/hackthebox-writeup/blob/main/Categories/Sherlocks/Constellation/README.md ; https://osintteam.blog/crhc-ctf-2025-writeups-inferiorak-915c12e60a34

### W51 — Commit-message archaeology (deleted-file recovery)
- Signals: repo + "removed secret" style message; asks deleted content.
- Steps: 1) `git log --oneline --all` scan 2) isolate add/remove pair 3) `git show PRE_SHA:path` 4) token-type identify → in-scope verify.
- Commands: `git log --all --oneline -- '*secret*' '*env*' '*key*'` ; `git show <SHA>^:<path>` ; `git log -p -S 'token' --all | head`
- Pitfalls: squashed history loss; noreply/private address dead-ends.
- Sources: https://osintteam.blog/crhc-ctf-2025-writeups-inferiorak-915c12e60a34 ; https://medium.com/@nikitha7390/scriptctf-osint-challenges-writeup-69a58d96737d ; https://luisvazquez2.github.io/spartanCTF-2024/OSINT

### W52 — Seven-hop EXIF identity chain (single image → full persona)
- Signals: one challenge image; asks avatar + city + network + email + holiday + secret.
- Steps: 1) EXIF copyright/GPS dump 2) handle search → triple profiles 3) post network-ID → crowd-map city+SSID 4) code-profile email 5) blog holiday 6) page-source secret.
- Commands: `exiftool image.jpg` ; quoted-handle search; crowd-map BSSID query.
- Pitfalls: stopping at GPS (decorative); assuming SSID city without map-link click.
- Sources: https://ni5arga.com/blog/posts/OhSINT ; https://github.com/Runarok/tryhackme-writeups/blob/main/OhSINT.md ; https://github.com/DivyanshuProjects/CTF-TRYHACKME-HACKTHEBOX-writeup/blob/main/TryHackMe%20-%20OhSINT.md

### W53 — Blog author-archive + concealed-text secret
- Signals: persona blog; asks holiday + hidden secret.
- Steps: 1) author-archive open → travel-post read 2) page-source view 3) concealed-text (white/hidden) reveal 4) in-scope use only.
- Commands: view-source + find; `curl -s URL | grep -oiE '.{0,30}(pass|secret).{0,30}'`
- Pitfalls: rendered-text-only reading misses hidden rows; theme-change drift.
- Sources: https://github.com/Runarok/tryhackme-writeups/blob/main/OhSINT.md ; https://github.com/DivyanshuProjects/CTF-TRYHACKME-HACKTHEBOX-writeup/blob/main/TryHackMe%20-%20OhSINT.md ; https://github.com/achnouri/OhSINT-CTF-write-up

### W54 — Review-plant + commute-bound workplace lock
- Signals: staffer + venue/hotel hints; asks workplace from reviews.
- Steps: 1) commute-post read (ferry/short-ride cues) 2) terminal/area search 3) venue-list sweep 4) review-account match → workplace lock.
- Commands: quoted commute-phrase + town search; review-sort newest-first.
- Pitfalls: deleted-review staleness; chain venues with same name.
- Sources: https://osintteam.blog/osint-writeups-mist-cyber-drill-2025-2d1e398a4672 ; https://github.com/Saqlain143/Osint-KeebarSecurityGroup ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763

### W55 — Degraded-asset recovery (depix/HEIC/crop triage)
- Signals: pixelated/HEIC/cropped asset; asks hidden/org/venue field.
- Steps: 1) format-convert (HEIC→JPG) 2) crop-to-feature + reverse each crop 3) reconstruction-tool pass 4) facility-cue → official record.
- Commands: `exiftool -a -G1 asset.*` ; crop + reverse-search per crop.
- Pitfalls: upscaled-artifact hallucinations; single-crop verdicts.
- Sources: https://0xmanikmaya.medium.com/osint-industries-ctf-2025-write-ups-fb7ffc1079d7 ; https://osintteam.blog/crhc-ctf-2025-writeups-inferiorak-915c12e60a34 ; https://www.aristore.top/posts/DawgCTF2025
