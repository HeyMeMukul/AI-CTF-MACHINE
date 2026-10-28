# OSINT R2 Patterns — Money / Threat / Exam / Geo Discipline (W56–W65)

> Methods-only. Fictional CTF targets. Each pattern: signals → steps →
> commands → pitfalls → 2–3 R2 source URLs (all in
> `knowledge/writeups_mined/osint_manifest_r2.md`, zero R1 overlap).

### W56 — Ledger self-transfer message read
- Signals: chain address + demand note; asks hidden message/flow.
- Steps: 1) correct-network explorer → address tx list 2) spot self-transfer 3) input-data UTF-8 decode 4) cluster second address set.
- Commands: explorer address view; input-data decode tab.
- Pitfalls: wrong-network explorer (test vs main); internal-tx vs input-data confusion.
- Sources: https://github.com/tTargiel/CTF-Writeup-Huntress-2025 ; https://medium.com/@divyanshurds.kumar/ctf-osint-write-up-sakura-room-expanded-in-depth-15c7ebf66b84 ; https://github.com/codeluu/blockchain-osint

### W57 — Threat-intel IP→coven + malware→actor double pivot
- Signals: attack IP + victim-region reports; asks actor number + malware family.
- Steps: 1) IP → intel/blocklist history → coven records 2) victim-theme reports → malware-family search 3) vendor-analysis cross-read 4) both pivots must agree.
- Commands: quoted-IP + intel search; quoted-malware + vendor search.
- Pitfalls: shared-hosting IP collisions; family renames across vendors.
- Sources: https://blog.carsonshaffer.me/hack-the-box-cyber-apocalypse-ctf-2025-osint-writeup-c5ab878b700c ; https://thelastdanc3.medium.com/htb-cyber-apocalypse-2025-ctf-writeup-osint-challenges-dd09885055ce ; https://github.com/hackthebox/cyber-apocalypse-2025

### W58 — Multi-image exam orchestration (batch + per-row format)
- Signals: image bundle + question server; asks sequential answers in strict formats.
- Steps: 1) queue images in given order 2) per-image method (reverse/dork/graph) 3) per-row format note (truncate/separator/case) 4) never skip blocked rows — log and continue.
- Commands: per-image `exiftool` + reverse + quoted-dork; format-check script.
- Pitfalls: format drift between rows; one blocked image stalls the batch.
- Sources: https://ctftime.org/writeup/40679 ; https://medium.com/@0xT4D/writeup-for-osint-tasks-brunnerctf-2025-31f87f4db70f ; https://github.com/DownUnderCTF/Challenges_2025_Public

### W59 — Question-recovery (find-your-own-question)
- Signals: description-less board; asks to find BOTH question and answer.
- Steps: 1) board/task-list scan for unnamed rows 2) artifact-first triage (image/coord/text) 3) infer question from artifact + format rules 4) solve, then cross-check synthesis rows.
- Commands: board inventory list; artifact-type triage table.
- Pitfalls: solving the wrong inferred question; ignoring meta/synthesis rows.
- Sources: https://osintteam.blog/osint-writeups-mist-cyber-drill-2025-2d1e398a4672 ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763 ; https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/osint/yippee

### W60 — Rail video-frame → operator → speed-table chain
- Signals: seconds-long train clip; asks model + operator + speed.
- Steps: 1) frame-pair shortlist (logo frames) 2) model read → operator confirm 3) speed-table lookup 4) livery cross-check.
- Commands: `ffmpeg -i clip.mp4 -vf fps=4 f%03d.png` ; quoted model+operator search.
- Pitfalls: similar liveries across operators; heritage-unit one-offs.
- Sources: https://medium.com/@0xT4D/writeup-for-osint-tasks-brunnerctf-2025-31f87f4db70f ; https://medium.com/@alwingt.edu/osint-challenge-writeup-0cc8690d6d73 ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763

### W61 — Grid-square trial-budget discipline
- Signals: 3-word-address answer; district locked, exact square unknown.
- Steps: 1) stance-lock best square 2) trial 5–10 adjacent squares 3) log each trial 4) stop at first confirm; never brute-force blindly.
- Commands: grid app coordinate paste; trial log table.
- Pitfalls: camera square vs subject square; satellite-pin drift burns trials.
- Sources: https://medium.com/@0xT4D/writeup-for-osint-tasks-brunnerctf-2025-31f87f4db70f ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763 ; https://medium.com/@0xT4D/writeup-for-osint-tasks-securinets-friendly-ctf-2025-746bc1e1e3d3

### W62 — Night-photo venue lock (lamp + type filter)
- Signals: night scene, few cues; asks venue/place.
- Steps: 1) light-color + lamp-shape read 2) venue-type filter 3) signage/crowd second cue 4) daytime cross-image confirm.
- Commands: crop-enhance lamps/signs; quoted type+town search.
- Pitfalls: white-balance lies about colors; event lighting vs permanent fixtures.
- Sources: https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763 ; https://github.com/diver-osint-ctf/writeups/tree/main/diver2025 ; https://medium.com/@0xT4D/writeup-for-osint-tasks-brunnerctf-2025-31f87f4db70f

### W63 — Rules-channel acrostic + ID hunt
- Signals: community server + "read the rules" hints; asks hidden line/ID.
- Steps: 1) channel list scan incl. hidden rows 2) first-char-per-rule read 3) roster ID lookup 4) profile-field verify.
- Commands: channel inventory; ID-lookup in roster.
- Pitfalls: edited-rule drift; nickname vs username mismatch.
- Sources: https://medium.com/@bridget4/imf-ctf-2025-70c92d531834 ; https://medium.com/@0xT4D/writeup-for-osint-tasks-securinets-friendly-ctf-2025-746bc1e1e3d3 ; https://medium.com/@nikitha7390/scriptctf-osint-challenges-writeup-69a58d96737d

### W64 — Commute/travel-post geographic bound
- Signals: travel/holiday posts + short-commute cues; asks town/venue.
- Steps: 1) travel-post collect 2) commute-time bound (short ride = nearby) 3) terminal/area search 4) venue-list sweep → review confirm.
- Commands: quoted commute-phrase + town search; terminal-area maps walk.
- Pitfalls: vacation posts misread as home; relocated personas.
- Sources: https://github.com/Saqlain143/Osint-KeebarSecurityGroup ; https://github.com/DivyanshuProjects/CTF-TRYHACKME-HACKTHEBOX-writeup/blob/main/TryHackMe%20-%20OhSINT.md ; https://medium.com/@divyanshurds.kumar/ctf-osint-write-up-sakura-room-expanded-in-depth-15c7ebf66b84

### W65 — Edited-post + description-line find
- Signals: social page + "follow for clues" theme; asks hidden line.
- Steps: 1) multi-platform sweep (photo/video/text) 2) edit-history open 3) description-line read 4) roster-page cross-check for persona link.
- Commands: platform edit-history view; quoted-phrase verify.
- Pitfalls: scheduled-post edits overwrite history; fan reposts pollute search.
- Sources: https://thesaucese.github.io/vishwactf ; https://iamabhi747.github.io/vishwactf25-writeups/OSINT/osint ; https://hackmd.io/@f4n-n3r0/BJtp2JPsye
