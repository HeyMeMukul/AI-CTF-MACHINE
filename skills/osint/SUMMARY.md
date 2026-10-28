# OSINT CTF — Quickref (~40 lines)

1. Freeze seeds first: handles, emails, domains, images → `results/osint_seeds.txt`.
2. `file` + `exiftool -a -G1` every attachment before opening it.
3. `sherlock handle --print-found --timeout 10` then `maigret handle --timeout 5`; keep intersection.
4. `theHarvester -d example.com -b crtsh -l 50` passive first; multi: `-b bing,crtsh`.
5. `curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u`
6. `dig +short example.com; dig +short example.com TXT; whois example.com`
7. `exiftool -GPS* -c "%.6f" photo.jpg` → maps link `?query=LAT,LON`, log timestamp.
8. Dorks (Brave MCP): `site:example.com "handle"`, `filetype:pdf`, `inurl:admin`.
9. CDX exact: `?url=example.com&output=json&limit=10`; prefix: `url=example.com/*`.
10. CDX domain: `?url=example.com&matchType=domain&filter=statuscode:200&limit=50`
11. Fetch ≤2 captures: `/web/20200101000000/http://example.com/` → grep `flag{` locally.
12. GitHub MCP: `"<string>" in:file`, `"<handle>" in:message`, env hunt in challenge org.
13. Reverse image: TinEye/Google Lens upload; log image hash + hit URLs.
14. Breach concept: join PROVIDED dumps only — `grep -Ff emails.txt provided_breach.csv`.
15. Geo chain: language → plates → vegetation → sun → EXIF → maps; 3 clues min.
16. Negatives: perturbed handle, wrong-domain dork, empty CDX path must all MISS.
17. Gated step: ONE hop ≤120s, cache to disk, `sleep 2`, stop on 429/captcha.
18. OPSEC: passive only, fictional targets, no DMs/resets; sock-puppet only if allowed.
19. Evidence: every hop = URL + UTC + screenshot + tool version in `evidence.log`.
20. Validate: `solve.sh` re-runs dorks/URLs; expects `flag\{[^}]+\}`; cache is authoritative.
21. Blocked after 3 tries (auth/captcha/paywall) → alternate source, keep other work.
22. Unverified: `maigret --html`, theHarvester `-b` list — run `--help`/`-h` on-box.
23. Sherlock variants: `--csv`, `--site GitHub`, `--timeout 10` (default 60s).
24. Maigret variants: `-a` all sites, `--html` report, `--timeout 5` (default 30s).
25. theHarvester new flags: `--domain X --source google --limit 200 --file out`.
26. Availability API: `curl -s 'https://archive.org/wayback/available?url=example.com'`.
27. CDX filters: `&filter=statuscode:200`, `&collapse=urlkey`, `&fl=timestamp,original`.
28. 403 on CDX host/prefix for popular domains is expected → fall back to exact URLs.
29. `strings -n 6 blob | grep -Ei 'flag|ctf|@'` before any network query.
30. `hashid -m '<hex>'` when OSINT drops a hash (joined breach-file passwords).
31. Chain order: handle → bio → github → commit email → crt.sh → archive → geo.
32. Two-source rule: never promote a pivot on one hit; negatives must MISS.
33. Rate limits: cache, `sleep 2`, honor Retry-After; stop on CAPTCHA/login wall.
34. Sock-puppet: throwaway, isolated browser profile, full action log, rules-allowed only.
35. haveibeenpwned = concept note; use PROVIDED dumps, never submit real emails.
36. Pipeline: seeds(30s) → sherlock → maigret → crt.sh → dorks → CDX → github (120s each).
37. Handoff: ordered URL/dork/command list + raw captures + negative re-checks.
38. Scope: technique-only, fictional CTF personas, passive collection, no harassment.
39. Deleted recovery: live code → CDX exact → prefix → domain → 2nd archive → ≤2 fetches.
40. CDX noise cut: `&fl=timestamp,original,statuscode,digest` + `&from=2020&to=2026`.
41. Sock-puppet chains: normalize variants; SAME-PERSONA needs 2+ correlates (avatar/domain/email/time).
42. Sun/shadow: direction→azimuth, `tan(alt)=h/shadow`; calculator check at candidate lat/lon.
43. GPS→maps: lat/lon → satellite → 2+ features; pixels alone never HIGH.
44. Metadata chain: doc Author → handle → commit email → PROVIDED dump join → bounded crack.
45. Transport IDs: challenge files only — extract → triage → plot provided pts → one join; no live tracking.
46. Git archaeology: `branch -a` → `log --full-history` → ONE `-S` sweep → ONE SHA `git show`.
47. Orphans: `reflog` + `fsck --lost-found` + commit-by-SHA; record both SHAs on force-push.
48. Infra (in-scope only): favicon hash + headers + cert + crt.sh; no sweeps, no stuffing.
49. Chains: handle→archive→bio→coords; photo→EXIF→maps→street; doc→commit→dump.
50. Failures F1–F8: 429→jitter+rotate; 404→3 archives; collision→correlates; gap→sitemap+ctlogs.
51. Stale/gate/meta/drift: newest wins; gates→archive+stop; single headers stay MEDIUM.
52. Cap 3: corrected retry → alternate → `blocked`; log symptom+detector+recovery.
53. Ethics hard stops: fictional only, no doxxing/contact/bypass; ambiguous scope → ping operator.
54. Budgets: easy ≤10m / medium ≤30m / hard ≤60m (freeze best chain by 40m) / insane → escalate at 60m.
55. Escalate: /stego (carrier hints), /misc (blobs/coords), /forensics (git/bin), /web (one panel).
56. Packet: seeds + evidence + best chain + 2 negatives + blocker ID (F1–F8) + question.
57. Writeup patterns W1–W35 (SKILL.md): wardrive BSSID→SSID; ADS-B replay climb/descend; IMO-vs-MMSI.
58. OSM way-ID; cadastral lots; Overpass→KML pin-walk; 3m grid-square micro-match; reflection flip.
59. Station-audio timetables; rail-model→pylon→utility-doc; email-lookup→reviews pivot.
60. Census-list rebuild; social-wordlist×date crack; hash-prefix screen; ledger input-data read.
61. Deleted-forum-user recovery; game-platform pivot; status-post+mail-format inference.
62. Catalog decay-sort; chat-ID snowflake math; search-URL param timeline; doc-property anomaly.
63. Review-site pivot; split-record DNS join; livery×route×gate triangulation.
64. Game-map alphabet coords; menu-item venue lock; tram+brand single-hit; road-isoline rings.
65. Fandom→archive→acrostic; commit-address identity; public-text vault crack; multi-gate reset.
66. Video-frame hotel via old streetview; photo-time via sun-scroll/shadow-map sweep.
67. Snowflake epoch: `(id>>22)+1420070400000` ms; chat file-ID = upload time.
68. Grid-square rule: camera square ≠ subject square; trial 5–10 adjacent squares.
69. Timetable rule: operator+time+destination+platform must ALL agree on one station.
70. Registry rule: persistent number (IMO) beats national number (MMSI); re-verify renames.
71. Wordlist rule: harvest likes/places/dates → variant-expand → product-generate → crack.
72. Archive rule: quoted-phrase dork → availability → CDX exact → ≤2 fetches → local grep.
73. Helpers: `curl -s https://api.adsbdb.com/v0/aircraft/<hex>`; `convert -flop`; `keepass2john`.
74. Manifest: `knowledge/writeups_mined/osint_manifest.md` (408 challenge-lines mined).
75. R2 manifest: `knowledge/writeups_mined/osint_manifest_r2.md` (401 hard-only lines, 2024–2026, 0% R1 overlap).
76. R2 patterns W36–W65: bodies in `techniques/writeup-patterns-r2-{1,2,3}.md`; SKILL.md holds index rows only.
77. R2 flights/maritime: air2air callsign-split; TLE-pass + AIS rank; aviation-log triangulation.
78. R2 identity/infra: 7-hop EXIF chain; snowflake epochs; CT-log triage; favicon-hash match.
