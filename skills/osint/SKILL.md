---
name: osint-ctf
description: In-depth CTF OSINT solver — username/email/domain/metadata/archive/breach/geo chaining with exact tool commands.
category: osint
phase: "1-2"
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# OSINT CTF Skill — Evidence-First Open-Source Chaining

> Technique-only. No real flags. CTF fictional targets only.
> Well-known tools only: sherlock, maigret, theHarvester, dig, whois,
> exiftool, Brave Search MCP, GitHub MCP, hashcat, john, hashid,
> CyberChef, openssl. No harassment, no real-person doxing.

## Mental Model

1. OSINT CTFs are **chaining problems**: one clue unlocks the next source.
2. Typical chain: `username → profiles → email → domain → breach → archive → geo`.
3. Every pivot must be **evidenced**: screenshot + URL + UTC timestamp.
4. Treat all persons/handles as **fictional CTF personas** unless stated otherwise.
5. Never contact, threaten, or harass anyone; passive collection only.
6. Rate limits are hard gates: back off, cache, deduplicate, never hammer.
7. One identity claim needs **two independent sources** (profile + commit, photo + EXIF).
8. Metadata beats guessing: EXIF GPS, PDF author, PNG `tEXt`, git history.
9. Archives beat live web: deleted posts live on in Wayback CDX captures.
10. Search engines are APIs: dorks (`site:`, `filetype:`, `inurl:`) narrow the haystack.
11. Code search finds what web search misses: challenge strings in repos/commits.
12. Breach-style data in CTFs is **provided as files**, never fetched illegally.
13. Geo clues compose: language + plate + vegetation + sun angle + EXIF → maps.
14. Sock-puppet accounts (if allowed by rules) are throwaway, isolated, logged.
15. Baseline first: record what the challenge GAVE you before querying anything.
16. Confirmation: each pivot re-queried with a second tool or dork.
17. Negative: plausible-but-wrong personas must be ruled out explicitly.
18. Gated step: one lookup batch ≤120s, then stop and log.
19. Handoff: a fresh validator re-runs your dork/URL list and gets the same hits.
20. If a source needs auth/captcha/paywall, mark `blocked`, try an alternate source.
21. Flag patterns (`flag{...}`) hide in bios, commit messages, image text, old captures.
22. Log tool versions; OSINT tool output drifts as sites change selectors.

## Workflow

### Phase 1 — Baseline (capture normal behavior first)

1. Inventory challenge prompt: usernames, emails, domains, IPs, images, files.
2. Record each seed string verbatim in `results/osint_seeds.txt`.
3. `file` all attachments; `exiftool` every image before opening it.
4. `dig +short` any domain; `whois` any domain/IP; save raw output.
5. Screenshot the challenge page/text with visible UTC timestamp.
6. Check for embedded flags in plaintext: `strings`, `zsteg --help` note, `binwalk` note.
7. List what is IN scope: fictional persona? provided pcap/repo? public CTF site?
8. List what is OUT of scope: real persons, live harassment, credentialed access.
9. Establish output dir: `results/osint/<handle>/` with `evidence.log`.
10. Do NOT query username search engines until seeds are frozen.
11. Note rate-limit posture: max requests/min, cache policy, backoff plan.
12. Record Brave/GitHub MCP availability: test one trivial query each.

Reasoning Checkpoint: evidence = seed list + exiftool/dig/whois raw + scope note → confidence HIGH/MEDIUM/LOW → proceed to Confirmation or stop if scope ambiguous.

### Phase 2 — Confirmation (minimal proof the primitive works)

1. Username: run `sherlock` on the exact handle, keep found-URLs only.
2. Username cross-check: run `maigret` on the same handle, diff against sherlock.
3. Email/domain: run `theHarvester -d <domain> -b crtsh` (passive first).
4. Certificate transparency: `curl crt.sh ?q=%25.<domain>&output=json | jq`.
5. DNS confirm: `dig ANY` / `dig TXT` + `whois` agree on registrar/nameservers.
6. Metadata confirm: `exiftool -GPS*` shows lat/long; plot on maps (no travel).
7. Archive confirm: Wayback CDX exact-URL lookup returns ≥1 capture.
8. Dork confirm: `site:<domain> "<handle>"` returns the same profile in Brave.
9. Code confirm: GitHub code search for challenge string returns same repo.
10. Image confirm: reverse-image hit matches username/profile photo (two sources).
11. Keep the SINGLE strongest pivot; demote the rest to hypotheses.
12. Screenshot every hit: full URL bar + timestamp visible.

Reasoning Checkpoint: evidence = two independent hits agreeing (e.g. sherlock URL + crt.sh name) → confidence HIGH/MEDIUM/LOW → proceed to Negative or re-baseline if hits conflict.

### Phase 3 — Negative (2+ controls that should FAIL)

1. Control 1 — perturbed handle (`handle_` + random digit) should yield NO consistent profile.
2. Control 2 — wrong domain in `site:` dork should yield NO hits for the handle.
3. Control 3 — `crt.sh` for an unrelated domain must NOT contain target names.
4. Control 4 — `exiftool` on a stripped copy must show NO GPS (proves GPS was real).
5. Control 5 — Wayback lookup for a never-existent path should return zero captures.
6. Control 6 — GitHub code search for a random string must NOT return the target repo.
7. Control 7 — reverse-image of an unrelated picture must NOT hit the persona.
8. Log each control: query, tool, exit/HTTP code, why emptiness was expected.
9. If a control unexpectedly HITS, the pivot is weak — discard or re-confirm.
10. Never claim identity on a single-source hit after a failed negative.
11. Keep sock-puppet/login-gated findings segregated from passive findings.

Reasoning Checkpoint: evidence = 2+ expected misses observed → confidence HIGH/MEDIUM/LOW → proceed to gated Exploit or stop if negatives contradict the pivot.

### Phase 4 — Exploit (gated, ONE step, ≤120s)

1. Pick exactly ONE next hop: one profile deep-dive, one CDX page, OR one dork batch.
2. Example allowed step: fetch ONE archived capture and grep for flag pattern.
3. Example allowed step: `maigret --timeout 5` top-sites pass on one handle.
4. Example allowed step: `theHarvester -d <domain> -b bing,crtsh -l 50` single run.
5. Enforce `timeout 120` on every network command; cache responses to disk.
6. Respect rate limits: sleep between batches, stop on 429, note retry-after.
7. No mass scraping: ≤1 page depth, ≤50 results per step unless pre-approved.
8. No authenticated actions, no password resets, no contact attempts, no harassment.
9. Sock-puppet rule: only if challenge rules allow; dedicated browser profile; log all actions.
10. Write new findings to a NEW evidence file; never edit prior screenshots/logs.
11. On timeout/captcha/403: ONE corrected retry, then ONE alternate source, then `blocked`.
12. Stop at first flag-pattern hit; do not keep enumerating in this phase.

Reasoning Checkpoint: evidence = new artifact (capture/commit/photo/geo fix) OR rate-limit log → confidence HIGH/MEDIUM/LOW → proceed to Validation-handoff or declare blocked after 3 attempts.

### Phase 5 — Validation-handoff (what a fresh validator must re-run)

1. Provide `solve.sh` or `notes.md`: ordered URL/dork/command list reproducing the chain.
2. State expected flag regex: e.g. `flag\{[^}]+\}` (generic, technique-only).
3. Include raw evidence: screenshots, `curl` outputs, CDX JSON, `exiftool` dump.
4. Each evidence item: source URL, UTC timestamp, tool + version, command.
5. State what needs live web vs what replays from cached captures.
6. Include negative re-checks: validator re-runs perturbed-handle control, expects miss.
7. Note volatility: profiles/captures may vanish; cached copy is authoritative.
8. Redaction: real-looking PII stays local; handoff cites CTF persona only.
9. If service changed (>20% result shift, new login wall), validator re-baselines.

Reasoning Checkpoint: evidence = validator re-runs dork/URL list and matches flag regex → confidence HIGH/MEDIUM/LOW → close task or loop back to Baseline on mismatch.

## Tool table (exact copy-paste commands)

| Purpose | Exact command |
|---|---|
| Sherlock one handle | `timeout 120 sherlock target_handle --print-found --timeout 10` |
| Sherlock CSV export | `timeout 120 sherlock target_handle --csv --timeout 10` |
| Sherlock limit site | `timeout 120 sherlock target_handle --site GitHub --timeout 10` |
| Maigret top sites | `timeout 120 maigret target_handle --timeout 5` |
| Maigret all sites | `timeout 120 maigret target_handle -a --timeout 5` |
| Maigret HTML report | `timeout 120 maigret target_handle --html --timeout 5` |
| theHarvester passive | `timeout 120 theHarvester -d example.com -b crtsh -l 50` |
| theHarvester multi-source | `timeout 120 theHarvester -d example.com -b bing,crtsh -l 100 -f results` |
| theHarvester new flags | `timeout 120 theHarvester --domain example.com --source google --limit 200` |
| crt.sh subdomains JSON | `curl -s 'https://crt.sh/?q=%25.example.com&output=json' \| jq -r '.[].name_value' \| sort -u` |
| crt.sh exact identity | `curl -s 'https://crt.sh/?q=api.example.com&output=json' \| jq .` |
| dig short | `dig +short example.com` |
| dig TXT/SPF | `dig +short example.com TXT` |
| dig reverse | `dig +short -x 93.184.216.34` |
| whois domain | `whois example.com` |
| whois IP | `whois 93.184.216.34` |
| exiftool full | `exiftool -a -G1 photo.jpg` |
| exiftool GPS only | `exiftool -GPS* -c "%.6f" photo.jpg` |
| exiftool strip test | `exiftool -all= -o stripped.jpg photo.jpg; exiftool -GPS* stripped.jpg` |
| Google dork site | `site:example.com "target_handle"` (Brave Search MCP query) |
| Google dork filetype | `site:example.com filetype:pdf "flag"` (Brave Search MCP query) |
| Google dork inurl | `inurl:admin site:example.com` (Brave Search MCP query) |
| Wayback availability | `curl -s 'https://archive.org/wayback/available?url=example.com'` |
| Wayback CDX exact | `curl -s 'http://web.archive.org/cdx/search/cdx?url=example.com&output=json&limit=10'` |
| Wayback CDX prefix | `curl -s 'http://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&limit=50&collapse=urlkey'` |
| Wayback CDX domain+filter | `curl -s 'http://web.archive.org/cdx/search/cdx?url=example.com&matchType=domain&output=json&filter=statuscode:200&limit=50'` |
| Wayback fetch capture | `curl -sL 'http://web.archive.org/web/20200101000000/http://example.com/' -o capture.html` |
| Reverse image (manual) | Upload to TinEye / Google Lens; record result URLs + timestamps |
| Hash identify blob | `hashid -m '<hex>'` |
| Strings in file | `strings -n 6 blob.bin \| grep -Ei 'flag\|ctf\|passw\|@' \| head -20` |
| Brave MCP people dork | `"target_handle" site:github.com OR site:twitter.com OR site:instagram.com` |
| GitHub MCP code dork | `"<challenge_string>" in:file language:python` (GitHub MCP code search) |
| GitHub MCP commit hunt | `"<handle>" in:message repo:org/repo` then list commit SHAs + diffs |
| Screenshot log | `echo "$(date -u +%FT%TZ) <url> shot01.png" >> results/osint/evidence.log` |

## Payload / code library

### L1 — Google/Brave dork table (copy-paste patterns)

```
site:example.com "target_handle"          # profile on target domain
site:github.com "target_handle"           # code-adjacent identity
site:pastebin.com "target_handle"         # pastes (CTF-planted only)
"target_handle" "@example.com"            # email linkage
filetype:pdf site:example.com "flag"     # stray documents
filetype:xlsx OR filetype:csv "password"  # CTF-provided dumps only
inurl:admin site:example.com              # exposed panels (passive note)
inurl:".git" site:example.com             # leaked repo hint (do not clone blindly)
"challenge_string" -site:example.com      # mirror/duplicate hunt
```

### L2 — crt.sh + dig + whois chaining script

```bash
#!/bin/bash
# Passive domain enum: crt.sh -> dig -> whois. Cache everything.
DOM="example.com"
curl -s "https://crt.sh/?q=%25.${DOM}&output=json" \
  | jq -r '.[].name_value' | tr '\r' '\n' | sed 's/^\*\.//' | sort -u > "subs_${DOM}.txt"
while read -r s; do echo -n "$s: "; dig +short "$s" | head -3; done < "subs_${DOM}.txt" > "resolved_${DOM}.txt"
whois "$DOM" > "whois_${DOM}.txt"
wc -l "subs_${DOM}.txt" "resolved_${DOM}.txt"
```

### L3 — Wayback CDX enumeration (verified params)

```bash
#!/bin/bash
# Exact -> prefix -> domain sweep. Respects 403 auth-gate on popular hosts.
URL="example.com"
curl -s "http://web.archive.org/cdx/search/cdx?url=${URL}&output=json&limit=20" | jq -r '.[1:][] | .[1:3] | @tsv'
curl -s "http://web.archive.org/cdx/search/cdx?url=${URL}/*&output=json&limit=50&collapse=urlkey" -o "cdx_prefix.json"
curl -s "http://web.archive.org/cdx/search/cdx?url=${URL}&matchType=domain&output=json&filter=statuscode:200&limit=50" -o "cdx_domain.json"
jq -r '.[1:][] | .[2]' cdx_domain.json 2>/dev/null | sort -u | head -20
```

### L4 — EXIF GPS to maps link

```bash
exiftool -GPS* -c "%.6f" photo.jpg
# Example output: GPS Latitude : 37.774900 / GPS Longitude : -122.419400
# Maps link pattern (manual open, log timestamp):
#   https://www.google.com/maps/search/?api=1&query=37.774900,-122.419400
#   https://www.openstreetmap.org/search?query=37.774900%2C-122.419400
python3 -c "print('https://www.google.com/maps/search/?api=1&query=37.774900,-122.419400')"
```

### L5 — Username cross-check (sherlock vs maigret diff)

```bash
#!/bin/bash
H="target_handle"
timeout 120 sherlock "$H" --print-found --timeout 10 --csv > "sherlock_${H}.txt" 2>&1
timeout 120 maigret "$H" --timeout 5 > "maigret_${H}.txt" 2>&1
grep -iE 'http' "sherlock_${H}.txt" | sort -u > found_sherlock.txt
grep -iE 'http' "maigret_${H}.txt" | sort -u > found_maigret.txt
echo "--- only sherlock:"; comm -23 found_sherlock.txt found_maigret.txt
echo "--- only maigret:"; comm -13 found_sherlock.txt found_maigret.txt
echo "--- both:"; comm -12 found_sherlock.txt found_maigret.txt
```

### L6 — GitHub MCP dork patterns for CTF

```
"<challenge_string>" in:file              # literal flag-adjacent string in code
"flag{" in:file language:python           # generic CTF marker sweep (bounded repo)
"<handle>" in:message                     # commits mentioning the persona
"<domain>" in:file extension:env          # leaked env/config (CTF repo only)
filename:.env "<domain>"                  # env file hunt in challenge org
# Rule: CTF personas only; never query real users.
```

### L7 — Social graph chaining note (passive)

```text
Seed handle -> profile bio links -> linked GitHub -> commit email
  -> commit email domain -> crt.sh subs -> archived bio revision
  -> photo reuse (reverse image) -> second handle -> EXIF geo fix.
Each arrow = one evidence row: URL + UTC + screenshot + tool version.
Stop rule: two independent sources agree, or mark candidate WEAK.
```

### L8 — Breach-data concept (CTF-provided files only)

```bash
# CTFs ship breach-style CSVs; never query real breach APIs with victim data.
# Pattern: join challenge email list against provided dump, then crack weak hashes.
cut -d: -f1 challenge_emails.txt | sort -u > emails.txt
grep -Ff emails.txt provided_breach.csv > hits.csv
hashid -m "$(cut -d, -f2 hits.csv | head -1)"
```

### L9 — GeoGuessr-style clue decomposition

```text
Language on sign -> driving side -> plate color/shape -> vegetation
  -> architecture -> sun shadow (N/S hemisphere) -> EXIF GPS confirm.
Record each clue with crop-screenshot + timestamp. Final answer =
  lat/long + 3 supporting clues, each with its own evidence row.
```

### L10 — Evidence log template

```text
2026-01-01T00:00:00Z | SEED handle=target_handle | src=challenge.txt
2026-01-01T00:01:00Z | sherlock target_handle --print-found | hits=3 | shot01.png
2026-01-01T00:03:00Z | crt.sh ?q=%25.example.com | subs=12 | subs_example.com.txt
2026-01-01T00:05:00Z | CDX url=example.com limit=10 | captures=7 | cdx_exact.json
2026-01-01T00:07:00Z | NEG perturbed handle_xyz9 | hits=0 as expected
```

## Decision tree

1. Given a handle? → sherlock (fast) → maigret diff → keep URLs in BOTH.
2. Given email/domain? → theHarvester `-b crtsh` → crt.sh curl → dig/whois confirm.
3. Given image? → exiftool GPS → maps link → reverse image → second handle.
4. Given repo/zip? → strings → GitHub code dorks → commit history secrets.
5. Given site URL? → Brave `site:` dorks → CDX exact → CDX prefix/domain.
6. Profile found? → bio links → breach-file join (CTF files only) → archived revision.
7. Photo + place clues? → language/plate/vegetation → EXIF → maps triangulation.
8. Login wall/captcha/429? → cache + backoff → alternate source → `blocked` after 3.
9. Two sources agree? → promote pivot; else demote to WEAK, run negatives.
10. Flag pattern anywhere (bio/commit/capture/EXIF comment)? → freeze chain, validate.
11. NOTHING fires → one bounded dork batch + one CDX page, then blocked.

## AI automation notes

1. Auto-pipeline order (each step `timeout 120`, stop on first flag-pattern hit):
2. Step 0 (30s): freeze seeds, `file`+`exiftool`+`dig`+`whois`, open evidence.log.
3. Step 1 (120s): `sherlock --print-found --timeout 10` on exact handle only.
4. Step 2 (120s): `maigret --timeout 5` diff; keep intersection, log divergence.
5. Step 3 (120s): crt.sh JSON + `theHarvester -b crtsh -l 50` passive domain pass.
6. Step 4 (120s): Brave dork batch (≤5 dorks): `site:`, `filetype:`, `inurl:`, handle+domain.
7. Step 5 (120s): CDX exact (limit 20) → fetch ≤2 captures, grep flag pattern locally.
8. Step 6 (120s): GitHub MCP code+commit dorks for challenge string (bounded org/repo).
9. Brave Search MCP usage: quote handles/emails, `site:` scoping, record result URLs verbatim.
10. GitHub MCP usage: code search → commit SHAs → raw diff fetch; never clone untrusted repos blindly.
11. Reverse image: TinEye/Google Lens manual upload; log query image hash + hit URLs.
12. haveibeenpwned concept: note-only in CTFs; operate on PROVIDED dumps, never submit real emails.
13. Sock-puppet OPSEC: throwaway profile, isolated browser, no real identity, logged, rules-allowed only.
14. Rate-limit discipline: cache to disk, `sleep 2` between batches, honor 429/Retry-After, stop on CAPTCHA.
15. No harassment: no DMs, no password resets, no contact forms, fictional targets only.
16. Unverified at write time: maigret `--html/--pdf` report flags vary by version — run `maigret --help` on-box.
17. Unverified at write time: theHarvester source list (`-b`) changes often — run `theHarvester -h` on-box.

## Evidence contract reminder

1. Skill id: `osint-ctf`; each hop gets its own evidence row and screenshot.
2. Commands recorded verbatim with UTC timestamps and exit/HTTP codes.
3. Baseline diff: seed hash before/after; result-count shifts noted.
4. Verdict HIGH/MEDIUM/LOW with the two agreeing sources named.
5. Attempt count (cap 3 for gated step); PII stays local, handoff cites persona only.

## Advanced / Hard-Challenge Playbook

> Hard CTF OSINT is won in the gaps: deleted pages, second handles,
> stripped metadata, rewritten git history, reused infrastructure.
> Every technique below is passive, technique-only, and scoped to
> fictional CTF personas / challenge-provided data. No real-person
> investigation. If a step needs auth, contact, or payment, stop and
> mark `blocked`.

### A1 — Deleted-content recovery (Wayback CDX + timemap + cache + history)

1. Live first: record HTTP code (`curl -sI` → `200`/`404`/`410`/`403`). A `404/410` is a recovery trigger, not a dead end.
2. Availability check (one cached request):
   `curl -s 'https://archive.org/wayback/available?url=example.com/some/path'`
   If `closest` exists, fetch via `web/.../http://...` pattern, diff vs live, log both timestamps.
3. CDX exact-URL sweep (`limit=20`, then `limit=200` max):
   `curl -s 'http://web.archive.org/cdx/search/cdx?url=example.com/some/path&output=json&limit=20'`
   Changed `digest` across same-URL captures = content edited (bio/flag/link). Fetch the two straddling captures.
4. CDX prefix sweep for renames:
   `curl -s 'http://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&limit=50&collapse=urlkey'`
   Look for near-neighbours (`/about-old`, `/u/handle2`); old paths outlive live 404s.
5. CDX domain sweep: add `&matchType=domain&filter=statuscode:200&limit=50` plus
   `&fl=timestamp,original,statuscode,digest` and `&from=2020&to=2026` to cut noise.
6. Second-archive opinion: same URL against one more archive source (rules permitting).
   Never declare "never existed" on one archive's miss (see F4).
7. Snippet residue: Brave MCP exact-URL-in-quotes query; snippets preserve deleted
   titles/bios. Screenshot + timestamp; snippets are leads — confirm via capture.
8. Commit fallback: deleted web copy survives in `git log -p -- <file>`, old branches,
   force-pushed SHAs (see A6). Search messages AND diffs for the path/handle.
9. Local grep on captures:
   `grep -Eo 'flag\{[^}]+\}|target_handle|[A-Za-z0-9._%+-]+@example\.com' capture.html | sort -u`
   Same grep on live HTML; the diff is the finding. Never edit captures in place.
10. Stop rule: exact + prefix + domain CDX + 1 second-archive check + ≤2 fetches per step.

Reasoning Checkpoint: evidence = live HTTP code + CDX JSON (capture count,
statuscodes, digests) + ≤2 fetched captures with grep diff → confidence
HIGH (two captures agree) / MEDIUM (one capture + snippet) / LOW (snippet only)
→ proceed to pivot or mark blocked.

### A2 — Sock-puppet pivot chains (handle → platform → platform correlation)

1. Normalize handle: exact case, separators (`_`/`.`/`-`), digits, leet variants
   (`target_handle`, `target.handle`, `target_handle2`). Log each variant as its own row.
2. Two passes: `sherlock` exact handle (found-URLs only), then `maigret` diff (L5 script).
   Intersection = strong; singletons = hypotheses needing a correlate.
3. Bio-link walk: open each profile (or archived capture if gated). Outbound links
   (second handle, domain, repo, image) — each is ONE next hop, never all at once.
4. Correlate rule (kills collisions): SAME-PERSONA needs 2+ of: (a) avatar hash match,
   (b) shared domain/repo, (c) writing tic + challenge string, (d) commit email match,
   (e) archived bio naming second handle. One correlate = WEAK.
5. Avatar pivot: `sha256sum avatar.png` + passive reverse-image (TinEye/Lens-style upload).
   Same bytes under a mutated handle = classic bridge. Log query hash + hit URLs.
6. Temporal check: creation/first-post/first-commit dates cluster for one persona;
   same stem years apart + disjoint topics = different person — demote explicitly.
7. Sock-puppet (rules-allowed only): throwaway, isolated profile, no real identity,
   logged, passive viewing only (no follows/likes/DMs). Prefer archived captures
   over logins; login-gated content stays `blocked` unless creds are provided.
8. Stop rule: one handle → ≤2 passes → ONE bio-link hop per gated step.

Reasoning Checkpoint: evidence = intersection URL list + 2+ named correlates
(avatar hash, bio link, commit email, archive revision) → confidence HIGH/MEDIUM/LOW
→ promote pivot or demote to WEAK and run negatives.

### A3 — Image geolocation (sun-angle / shadows, signage, vegetation, EXIF → maps)

1. EXIF first: `exiftool -a -G1` then `exiftool -GPS* -c "%.6f"`. GPS present →
   plot maps link (L4) and treat below as CONFIRM; no GPS → visual chain is discovery.
2. Signage pass (one crop per clue): script/language → driving side → plate shape →
   road markings → ad phone-codes/brands. Language narrows regions, never a city alone.
3. Vegetation/terrain/architecture pass: palm/conifer/scrub, roof/shutter/pole shapes.
   Record `clue + crop + what it EXCLUDES`, not just what it suggests.
4. Sun/shadow pass: (a) shadow direction → sun azimuth (opposite bearing);
   (b) `tan(altitude) = height / shadow_length` (long shadows = low sun);
   (c) with EXIF `DateTimeOriginal`, check a solar-position calculator at candidate
   lat/lon — match corroborates, mismatch re-baselines, never force-fits;
   (d) midday sun south/north = northern/southern hemisphere.
5. Night variant: moon calculators + light color + signage bound region; label day-only clues.
6. GPS → maps triangulation: lat/lon → satellite → street match on 2+ durable features
   (bend, corner, pole line). GPS+visual = HIGH; GPS alone = MEDIUM (spoofable).
7. Second-source rule: reverse-image place name, archived bio city, or commit timezone
   must agree. Pixels alone are never HIGH.
8. Stop rule: EXIF + ≤3 clue families + one maps check per step; 3-way disagreement → freeze.

Reasoning Checkpoint: evidence = EXIF dump + clue crops (signage/vegetation/shadow)
+ maps link + second-source place name → confidence HIGH/MEDIUM/LOW → fix or
re-baseline.

### A4 — Metadata chains (doc author → username → fictional dumps)

1. Triage: `file doc.pdf; pdfinfo doc.pdf; exiftool -a -G1 doc.pdf` → `Author`,
   `Creator`, dates, revision count, comment fields (`LastModifiedBy` for Office).
2. Author → handle: treat `Author` as CANDIDATE, query exactly + as email local-part
   (`author@example.com`). Log which form hit.
3. Handle → commits: GitHub dorks for author string (L6). Commit emails
   (`Name <user@example.com>`) beat bio matches — one email links code to infra.
4. Provided dumps only: `grep -Ff emails.txt provided_breach.csv > hits.csv`.
   Never submit emails to live breach APIs. The shipped dump is the universe.
5. Hashes: `hashid -m '<hex>'`, bounded crack (challenge wordlist, ≤120s).
   Fictional creds work ONLY inside challenge artifacts — never live (hard stop).
6. Hygiene: each arrow (doc→author→handle→commit→dump→crack) = one evidence row
   with file + line/offset. Skipped rows invalidate the chain.
7. Forgery control: author fields are forgeable — second doc must NOT converge on the
   same handle; `exiftool -all= -o clean.pdf doc.pdf` + re-dump separates embedded
   vs viewer fields. Forgery = DECOY, not failure.
8. Stop rule: one doc → one author → one handle pass → one dump join per step.

Reasoning Checkpoint: evidence = raw metadata dump + handle/commit hits +
local dump-join line numbers → confidence HIGH/MEDIUM/LOW → advance chain or
mark author DECOY.

### A5 — Drone / transport ID tracking (ADS-B concept, CTF-scoped)

1. Scope gate: real tracking of real craft is OUT of scope. Applies ONLY to challenge-
   provided captures/logs/screenshots with transport-like IDs. The file is the sensor.
2. Extract locally: `strings -n 6 capture.bin` + bounded `grep -Eoi` for ID-like tokens.
   Record verbatim + byte offset; never normalize silently.
3. Triage: (a) hex-like, (b) callsign-like, (c) timestamped position rows, (d) noise.
   Only (a)–(c) with 2+ co-occurring fields (ID+time, ID+coords) advance.
4. Replay, don't track: plot PROVIDED coords/times (L4 link pattern); finding = ROUTE
   inside the data (clusters, revisits, gaps) — never a live position lookup.
5. Correlate fictionally: EXIF time ↔ telemetry time, commit string ↔ callsign-like ID,
   archived bio ↔ waypoint. Two-source agreement promotes; single-ID stays WEAK.
6. Media pairing: drone-style photos get A3 analysis; altitude-like fields are
   untrusted until a second artifact agrees.
7. Hard stops: no live feed queries, no operator contact, no publishing movement.
   Real-looking IDs are still treated as fictional; queries stay in provided files.
8. Stop rule: extract → triage → plot → one cross-artifact join per step. No polling.

Reasoning Checkpoint: evidence = verbatim IDs + offsets + plotted provided
points + cross-artifact match → confidence HIGH/MEDIUM/LOW → advance or hold
as WEAK single-ID.

### A6 — Source-code archaeology (deleted branches, force-pushed commits, leaks)

1. Clone safe: `git clone --bare --depth 50` or challenge ZIP; `git log` before checkout.
   Log remote URL + time + HEAD SHA first.
2. Inventory: `git branch -a; git tag; git log --all --oneline | head -50`. Stale branches
   get `git log --stat` before diffs.
3. Deleted files: `git log --all --full-history -- '*secret*' '*flag*' '*env*' '*key*'`,
   then `git show <SHA>:<path>`; `git log --diff-filter=D --summary` lists deletions.
4. Orphaned commits: `git reflog`, `git fsck --lost-found` (dangling), forge commit-by-SHA
   when SHA is known. Fetch orphan SHA, `git show`, diff vs replacement; record both SHAs.
5. Secret sweep (one pick-string per step): `git log -p -S 'flag{' --all | head -100`,
   then `-S 'password'`, `-S 'BEGIN PRIVATE KEY'`. Hits need `SHA + file + line`.
6. Roster: `git log --format='%H %an %ae %ad %s' --all`. Commit emails matching handles/
   domains (A2/A4) link code to infra; `%ad` timezones bound geography like shadows.
7. Nested history: `.gitmodules`, vendored `.git`, ZIP-embedded `/.git/` have independent
   logs — outer deletion may miss inner history.
8. Stop rule: inventory → ONE pick-string → ONE SHA recovery per gated step.

Reasoning Checkpoint: evidence = branch list + SHAs + `git show` excerpts with
file:line + author roster → confidence HIGH/MEDIUM/LOW → pivot (email/handle)
or mark sweep clean.

### A7 — Favicon / infrastructure fingerprinting (CTF-scoped, passive)

1. Scope: challenge-provided hosts / authorized CTF nets only. One host, stated ports,
   bounded time — never sweeps or neighbours.
2. Favicon: fetch ONCE (`curl -sL -o favicon.ico`), `sha256sum`, record headers.
   Same hash across hosts = shared scaffolding (lead, not attribution).
3. Headers: `curl -sI https://example.com/` → `Server`/`Via`/cert CN-SAN; confirm via
   `dig`+`whois`+crt.sh. Banner strings feed code-search dorks (`"<banner>" in:file`).
4. Certs: `openssl s_client -connect example.com:443 -servername example.com` pipe to
   `x509 -noout -subject -issuer -dates -ext subjectAltName`, plus crt.sh JSON.
   Shared issuer/SAN = same-deploy hint; CTF self-signed is usually intentional.
5. Search-corpus rule: reason about what an infra search WOULD show, verify with ONE
   passive fetch or provided pcap/screenshot. Query a corpus only if the CTF provides
   one; otherwise stay local to provided artifacts.
6. Evidence: fetch command + raw header bytes + timestamp per claim. Framework-guesses
   without hash/bytes = WEAK until a second artifact (cert/DNS/repo) agrees.
7. Hard stops: no out-of-scope ports, no exploitation in this phase, no credential
   stuffing on discovered panels.
8. Stop rule: ONE host → favicon + headers + cert in ≤120s, then pivot. No loops.

Reasoning Checkpoint: evidence = favicon hash + header/cert bytes + crt.sh/dig
agreement → confidence HIGH/MEDIUM/LOW → pivot to repo/archive or hold as WEAK.

## Multi-Step Chains (abstract patterns — fictional personas only)

> Copy the SHAPE, not the data. Replace every placeholder with challenge seeds.
> Each arrow is one gated step with its own evidence row. Two independent
> sources per identity claim, always.

### Chain 1 — Handle → archive → old-bio → coordinates (the classic hard chain)

```text
Seed: fictional handle H (from challenge text, e.g. target_handle pattern)
Step 1 (username): sherlock H -> found profile URL P1 on platform A.
  Evidence: found-URLs list + screenshot + UTC. (1 source — WEAK so far.)
Step 2 (archive): CDX exact-URL for P1 -> captures C1 (old) and C2 (new).
  Diff C1 vs C2: old bio names second handle H2 + old personal domain D.
  Evidence: CDX JSON + 2 captures + local grep diff. (Second source for H2.)
Step 3 (correlate): maigret H2 -> profile P2 on platform B with same avatar hash
  as P1 (sha256 match) + domain D in bio. Two correlates -> SAME-PERSONA HIGH.
Step 4 (domain): crt.sh for D -> subdomain list; dig/whois confirm registrar.
  theHarvester -b crtsh passive pass corroborates. (Infra leg, independent.)
Step 5 (geo): P2's photo -> exiftool shows GPS lat/lon -> maps link -> satellite
  confirms road-bend + building corner from photo background. Old bio's city name
  (from C1) agrees with GPS city. Two geo sources agree -> fix HIGH.
Negative: perturbed handle H9 yields no P1/P2; wrong-domain dork misses;
  stripped-photo EXIF shows no GPS (proves GPS was embedded, not viewer-added).
Handoff: ordered URL/dork/command list reproducing steps 1-5 + captures + hashes.
```

### Chain 2 — Photo → EXIF → maps → street (no-handle geo chain)

```text
Seed: challenge photo with no name attached (fictional place).
Step 1 (metadata): exiftool -a -G1 -> GPS absent, but DateTimeOriginal + camera
  model present. Stripped-copy control shows same absence (no false GPS).
Step 2 (visual families): signage language narrows to region R (crop 1);
  vegetation + architecture exclude two neighbouring regions (crops 2-3);
  shadow direction + length bound time-of-day and hemisphere (crop 4 + altitude
  estimate via tan(altitude)=height/shadow). Three families converge on R.
Step 3 (maps triangulation): keyword search for region R + visible brand/venue
  text (Brave dork, quoted) -> candidate town T. Maps satellite: match road bend
  + building corner + pole line from photo. Street-level view matches doorway.
Step 4 (confirm): reverse-image of a tight crop -> archived travel-style page
  (fictional, challenge-planted) naming T; its photo matches doorway geometry.
  Second source agrees -> fix HIGH with 3 supporting clues.
Negative: neighbouring town T2 searched the same way yields no doorway match;
  mirrored-crop reverse-image yields no hit (proves hit was geometry, not noise).
Handoff: EXIF dump + 4 crops + maps link + reverse-image URLs + timestamps.
```

### Chain 3 — Doc → author → commit → provided-dump → flag-adjacent secret

```text
Seed: challenge PDF/DOCX (fictional memo).
Step 1 (metadata): exiftool/pdfinfo -> Author field A + Creator tool + dates.
  Evidence: raw dump with field names verbatim.
Step 2 (handle): A as exact handle -> sherlock finds code-platform profile P;
  P's commit email E matches challenge domain D. (Author->handle->email, 2 hops.)
Step 3 (archaeology): challenge repo git log for E -> commit SHA S deleting a
  config-like file; git show S^:path recovers the deleted revision containing
  a username U + hash-like token. Evidence: SHA + file:line.
Step 4 (dump join, PROVIDED file only): U against provided_breach.csv ->
  hits.csv line N; hashid identifies token type; bounded crack with challenge
  wordlist (<=120s) yields fictional credential. No live breach API touched.
Step 5 (close): credential unlocks ONLY the challenge-provided artifact
  (zip/note/host in scope) per task rules; flag-pattern grep confirms.
Negative: second doc's different author does not converge on P (no collision);
  random pick-string -S sweep misses (proves sweep was selective).
Handoff: metadata dump + SHAs + join line numbers + crack command + flag regex.
```

## Failure-Mode Catalog + Recovery

> Detect fast, recover once, alternate once, then `blocked`. Every failure gets
> a log row: symptom → detector → recovery → outcome. Three strikes per gated
> step, then move to unblocked work.

| # | Failure | Detection (how you know) | Recovery (exactly what to do) | Next if still failing |
|---|---|---|---|---|
| F1 | Rate-limit / 429 / throttle | HTTP 429, `Retry-After` header, empty result page, `sherlock` timeouts cluster | Slow + jitter: `sleep 2` base, add random 1-3s, cut batch to ≤5 queries, cache every response, honor `Retry-After`, rotate endpoint (Brave→CDX→crt.sh order swap) | ONE retry after backoff, then `blocked`; resume other chain legs |
| F2 | Deleted page / 404 / 410 | Live `curl -sI` shows 404/410; profile "not found" | 3-archive rule: (1) CDX exact, (2) CDX prefix/domain, (3) second archive or search-snippet; fetch ≤2 captures, grep locally | Mark `recovered` (captures found) or `blocked` (all three miss) |
| F3 | Common handle collision | sherlock/maigret return many disjoint personas for one stem | Disambiguate with 2+ correlates: avatar hash + bio link, commit email, archive revision, temporal cluster; demote singletons to WEAK with explicit rule-out rows | Keep top candidate only; queue rest as hypotheses, do not merge |
| F4 | robots.txt / CDX gaps | CDX returns zero captures for a live-visible page; `robots` exclusion suspected | Sitemap + cert-log pivot: fetch `/sitemap.xml`, run crt.sh subdomain sweep, Brave `site:` dorks for the same path text, check commit history for the path | Log gap as EVIDENCE (exclusion is signal); proceed via alternate source |
| F5 | Stale cache / snippet drift | Snippet names a bio/link the live page and captures contradict | Revalidate: refetch live headers, refetch newest CDX capture, compare digests + timestamps; newest-authoritative rule (capture timestamp beats snippet) | Cite newest artifact; keep stale snippet as HISTORICAL note only |
| F6 | Login / captcha / paywall gate | Redirect to login, captcha widget, 403 with auth body | Do NOT bypass: try archived capture first, then provided files, then alternate public source; log gate verbatim | `blocked` after 1 archive + 1 alternate; ping operator only if challenge provides creds |
| F7 | Stripped / forged metadata | EXIF empty on a "camera original", or Author absurd/mismatched | Strip-test control (`exiftool -all= -o clean...` + re-dump) + second-artifact rule: GPS/author needs visual or commit corroboration before promotion | Mark DECOY or UNRELIABLE; keep chain on non-metadata legs |
| F8 | Tool-output drift | sherlock/maigret/theHarvester version changes selectors, source lists shift | Run `--help`/`-h` on-box, pin version in evidence log, re-run minimal confirm query, diff result counts (>20% shift = re-baseline trigger) | Re-baseline with current flags; note drift in handoff so validator matches |

Recovery drills: F1 `sleep 2` + jitter, `timeout 120`, halve scope on 429, rotate families.
F2 live→exact→prefix→domain→second archive→≤2 fetches→local diff. F3 variant table +
correlate matrix, ≥2 to promote. F4 sitemap + crt.sh + `site:` dork + `git log -- <path>`.
F5 newest artifact wins; stale snippets = historical notes. F6 screenshot gate, archive +
provided files, then stop (no bypass). F7 single headers stay MEDIUM; forgery = DECOY.
Attempt cap 3: corrected retry → alternate source → `blocked`; no fourth attempt.

Reasoning Checkpoint: evidence = failure log rows (symptom + detector + recovery
+ HTTP/exit codes) → confidence in the RECOVERY (not the pivot) HIGH/MEDIUM/LOW
→ resume chain on alternate leg or declare step blocked.

## Ethics Guardrails — Fictional CTF Targets Only (hard stops)

1. Fictional-only: all handles/emails/domains/photos/dumps are challenge-planted.
   Never pivot to real people, accounts, or organizations.
2. No doxxing: no assembling real identity/location for living persons. Real-looking
   PII → stop, redact locally, cite persona only, notify operator.
3. No contact: no DMs/emails/follows/resets/forms. Passive only; rules-allowed
   sock-puppets observe, never interact with real users.
4. Respect gates: honor 429/`Retry-After`, captchas, logins, paywalls. No hammering,
   credential stuffing, borrowed sessions, or captcha services.
5. Provided dumps only: never submit emails to live breach APIs, never crack real hashes.
   Fictional creds work ONLY inside challenge artifacts.
6. In-scope infra + replay-only transport: no neighbour sweeps, no live vehicle tracking,
   no publishing movement, no operator contact.
7. Hygiene: raw artifacts stay local; redact before sharing; reports carry flag regex
   (`flag\{[^}]+\}`) and technique, never personal data.
8. HARD STOPS — ping operator, do not proceed: (a) real private data needed;
   (b) login/captcha bypass, cred reuse, or payment needed; (c) someone contacted/alarmed/
   billed; (d) fictional-vs-real scope unclear; (e) real-world tracking/doxxing proposed.
   Log UTC + reason + trigger; keep solving unblocked work.

Reasoning Checkpoint: evidence = scope note (fictional + in-scope list) with no
real-person data touched → confidence HIGH (explicit fictional scope) or STOP
(any real-person/gate ambiguity) → proceed or operator-ping.

## Time-Budget Tiers (stop rules per tier)

| Tier | Budget | Cadence | Stop / escalate rule |
|---|---|---|---|
| Easy | ≤10 min | Seeds (2m) → one username pass + one dork batch (6m) → handoff (2m) | Flag-pattern or HIGH pivot by 8m, else historied `blocked` + handoff; no archive deep-dives |
| Medium | ≤30 min | + maigret diff + crt.sh + CDX exact + ≤2 captures (20m) → validate (5m) | Two sources agree by 20m or demote to WEAK; one recovery cycle max per failure |
| Hard | ≤60 min | Full playbook: A1–A4 + A6 as needed, 120s gated steps, 3 chains max in parallel | Freeze best chain by 40m; full failure catalog allowed; operator ping only on hard-stop gates |
| Insane | 60m+ → escalate | Timebox 60m investigation → structured escalation (below), never silent overrun | At 60m: handoff best chain + negatives + explicit ask (stego/misc/operator); keep no private queue |

1. Easy (≤10 min): seeds + `file`/`exiftool`/`dig` + sherlock + ≤5 dorks + flag grep.
   No prefix sweeps, archaeology, or second-handle chasing.
2. Medium (≤30 min): + maigret diff, crt.sh/passive Harvester, CDX exact + ≤2 captures,
   one GitHub batch. One retry + one alternate per failure, then `blocked`.
3. Hard (≤60 min): full A1–A4 + A6/A7 as cued; prefix/domain CDX; avatar/commit correlates;
   dump joins; in-scope favicon/cert. Freeze ONE best chain by minute 40, validate after.
4. Insane (60m+): stop new sources at 60m. Deliver best chain + 2 negatives + blocker ID
   (F1–F8) + explicit ask. Overrun without an escalation note = process failure.
5. Accounting: every step ≤120s (`timeout 120`), cap 3 attempts; `evidence.log`
   timestamps prove budget. Max 2 independent legs at once; never parallelize validation.

## Escalation Triggers (when this skill hands off)

1. To `/stego`: EXIF clean + visuals exhausted but size/entropy/`strings`/chunk anomalies
   suggest a CARRIER. Handoff: image hash + `exiftool` + `strings` head + stall reason.
2. To `/misc`: bios/commits/captures/dumps hold base64/hex blobs or odd coordinate
   encodings (MGRS-/plus-code-like). Handoff: verbatim blob + source SHA/URL + `hashid`.
3. To `/forensics`/`/rev`: archaeology hits packed objects, nested repos, macros, or
   binaries. Handoff: SHAs + paths, no re-clone needed.
4. To operator: login/captcha/paywall on the last leg, scope ambiguity, supplied creds,
   real-looking PII, or any hard stop. Ping with need + blocker logs; keep other legs moving.
5. To `/web`: passive work nominates ONE in-scope panel/endpoint. Handoff: host + port +
   header/cert bytes + why passive stopped.
6. Packet: seeds + evidence excerpt + best chain + 2 negatives + blocker ID (F1–F8) +
   explicit question. No blocker ID = bounced.

## Worked End-to-End Example (abstracted, fictional — technique only)

> Personas, handles, domains, and coordinates below are FABRICATED patterns
> showing technique shape. Substitute challenge seeds. No real personal data.

```text
Scenario: challenge text names fictional handle H ("target_handle"-pattern account)
  plus one photo ("harbor crane at dusk"-style scene) and one PDF memo.
  Scope note: all three artifacts are challenge-planted; personas fictional.

T+0-2m BASELINE: seeds to seeds.txt (H verbatim, hashes). exiftool photo (no GPS,
  DateTimeOriginal present); memo Author A present. dig/whois saved. → HIGH.
T+2-6m USERNAME: sherlock H → 3 URLs; maigret → same 3 + 1 (divergence logged).
  Best: code profile P linking domain-pattern D + handle-pattern H2. → MEDIUM.
T+6-10m ARCHIVE: CDX for P → 4 captures; oldest bio names H2 (digest edit proven).
  maigret H2 → P2, avatar sha256 match + D in bio → SAME-PERSONA HIGH.
  Negatives: perturbed handle + wrong-domain dork miss.
T+10-16m DOMAIN+CODE: crt.sh for D → subs; dig resolves 2; Harvester corroborates.
  Commit SHA S (email matching D); `git show S^:path` recovers deleted revision
  with username-pattern U + token. → HIGH link.
T+16-22m DUMP (provided only): Author A matches H stem (logged); roster confirms A
  on SHA S. U vs provided_breach.csv → 1 hit; hashid + bounded crack (≤120s) →
  fictional cred. No live API. → MEDIUM-HIGH.
T+22-28m GEO: shadows bound dusk; signage/vegetation crops → region-class R (3 crops).
  Maps: venue-text → waterfront; satellite (crane row + bend) + street (doorway)
  + planted gallery page naming it → fix HIGH.
T+28-30m HANDOFF: solve.sh replays all (dorks, CDX timestamps, SHAs, join lines,
  maps link); generic flag regex; negatives re-runnable; PII redacted to personas.
```

> Failure branches exercised in this example: F2 (live bio edited → oldest
> capture won), F3 (H2 variant disambiguated by avatar+domain correlates, not
> volume), F5 (one stale snippet demoted to historical after capture recheck).
> If the photo had carried trailing bytes instead of scenery, T+22m would have
> Failure branches exercised in this example: F2 (live bio edited → oldest
> capture won), F3 (H2 variant disambiguated by avatar+domain correlates, not
> volume), F5 (one stale snippet demoted to historical after capture recheck).
> If the photo had carried trailing bytes instead of scenery, T+22m would have
> escalated to /stego with image hash + strings head rather than forcing geo.

## Writeup-Distilled Patterns (W1..W35)

> Mined from `knowledge/writeups_mined/osint_manifest.md` (408 challenge-lines,
> 2022–2026). Each pattern is NEW vs the sections above: name → recognition
> signals → exact steps → commands → pitfalls → source URLs. Methods-only;
> every persona below is a fictional CTF target. Reasoning Checkpoint: evidence
> = 2+ named sources agreeing per pattern → HIGH/MEDIUM/LOW → promote or hold.

### W1 — Wardrive BSSID→SSID lookup
- Signals: challenge gives a MAC/BSSID and asks for the network name or place.
- Steps: 1) normalize MAC case/format 2) wardrive-map BSSID search (free account) 3) zoom to mark, read SSID + coords 4) second network-name cross-check.
- Commands: `grep -Eo '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' note.txt` then web lookup.
- Pitfalls: stale crowdsourced points; partial-SSID needs map-bounding, not guessing.
- Sources: https://404unfound.com/writeups/patriotctf_23/rouge-access-point/ ; https://ctftime.org/writeup/23862 ; https://breydensummers.github.io/blog/SOC-CTF-2024-OSINT-Writeup/

### W2 — ADS-B replay + climb/descend disambiguation
- Signals: aircraft photo + exact time; asks registration/callsign/hex.
- Steps: 1) EXIF time → UTC 2) traffic-replay at place+time, two adjacent minutes 3) altitude trend = departure (climb) vs arrival (descend) 4) registry decode of surviving hex.
- Commands: `curl -s https://api.adsbdb.com/v0/aircraft/<hex>` ; `exiftool -DateTimeOriginal -GPSPosition photo.jpg`
- Pitfalls: coverage gaps over water/remote areas; privacy-program suppression.
- Sources: https://blog.rei.my.id/posts/146/dawgctf-2026-plane-spotting-pt-3-osint-writeup/ ; https://razvanttn.gitbook.io/ctf/2026/oscj/aero-sponge ; https://github.com/RickdeJager/CTF/blob/master/DUC2020/osint/I_think_this_one_is_really_going_to_take_off/writeup.md

### W3 — IMO-vs-MMSI vessel persistence split
- Signals: vessel photo; asks for the number that survives a foreign sale.
- Steps: 1) hull-marking search → vessel page 2) read both numbers 3) persistent registry number wins over national-identifier number.
- Commands: quoted hull-mark search (Brave MCP); no CLI.
- Pitfalls: renamed vessels; reused national identifiers; fan-wiki vs registry.
- Sources: https://hack.nikkei.com/blog/ctf_osint_diver_2025/ ; https://github.com/hackthebox/university-ctf-2025

### W4 — Map object-model way-ID answer
- Signals: coords + asks for a "way"/object number.
- Steps: 1) paste coords into open map 2) select building polygon (not node) 3) read way-ID 4) re-query to confirm stability.
- Commands: none CLI; record object type + ID + timestamp.
- Pitfalls: node vs way vs relation confusion; edited objects renumber.
- Sources: https://hack.nikkei.com/blog/ctf_osint_diver_2025/ ; https://cybersec.uvt.ro/posts/Osprey-1,-2,-3/

### W5 — Cadastral lot registries
- Signals: road-center photo; asks for lot/block number incl. odd notations.
- Steps: 1) shop-sign → street address 2) public cadastral viewer → parcel 3) quote verbatim incl. non-numeric lots.
- Commands: quoted shop-name search (Brave MCP); no CLI.
- Pitfalls: postal address ≠ lot number; unregistered/shared parcels.
- Sources: https://zenn.dev/kn1cht/articles/diver-osint-ctf-2024-kakitsubata ; https://zenn.dev/ardririy/articles/ab9d86739e8ffd ; https://qiita.com/kikyo_nanakusa/items/e7faba1ae788b9a009cf

### W6 — Overpass POI sweep + KML pin-walk
- Signals: countable POI in frame (mills, shops, tram models, pylons).
- Steps: 1) wizard-build tag query 2) export KML 3) Earth pin-walk 4) streetview confirm each candidate.
- Commands: `[out:json][timeout:25];area[name="<X>"];nwr["man_made"="windmill"](area);out geom;`
- Pitfalls: crowdsourced gaps — missing POI never proves wrong area.
- Sources: https://medium.com/@shibaosint/l3akctf-2025-fidget-spinner-writeup-cd94eafc2828 ; https://medium.com/@horus_/writeup-ctf-thcon-2025-osint-3a166f406d1a

### W7 — Grid-square exact-point micro-match
- Signals: 3-word-address flag format.
- Steps: 1) lock area by standard geo 2) stance-match micro-features (pole, rock, sign, planter) 3) trial 5–10 adjacent squares.
- Commands: `https://what3words.com/` coordinate paste; no CLI.
- Pitfalls: camera square vs subject square; satellite-pin drift.
- Sources: https://medium.com/@inferiorak/three-words-all-osint-challenge-utctf-2025-7b1ef89c8cbf ; https://medium.com/@tahamalikmmc/utctf-2026-w3w1-w3w2-w3w3-writeups-393aae3bab3a ; https://medium.com/@great.bj.shark/three-words-1-writeup-ea6167c72839

### W8 — Reflected/mirrored text recovery
- Signals: glass/reflection, half-legible sign, unreadable station board.
- Steps: 1) flip horizontal 2) contrast crop 3) read phrase 4) phrase + venue-type search.
- Commands: `convert photo.jpg -flop flip.jpg` ; quoted-phrase search.
- Pitfalls: searching the mirrored string verbatim misses; translate after flip.
- Sources: https://yocchin.hatenablog.com/entry/2022/10/28/080000 ; https://qiita.com/yuykk02/items/a6184671dbb6dfb7df4b ; https://medium.com/@tahamalikmmc/utctf-2026-w3w1-w3w2-w3w3-writeups-393aae3bab3a

### W9 — Station-audio timetable cross-check
- Signals: announcement audio; asks which station.
- Steps: 1) transcribe operator + time + destination + platform 2) pull each candidate timetable 3) keep only the station where all four agree.
- Commands: audio playback + timetable pages; log transcript verbatim.
- Pitfalls: holiday diagrams; same-time different-platform patterns.
- Sources: https://h-takara.hatenablog.com/entry/2025/06/09/003630 ; https://qiita.com/nicklegr/items/1eceec1ffb9bae7874e3 ; https://zenn.dev/juck28/articles/b050ece3b7bb28

### W10 — Rail-model → corridor → pylon → utility-doc
- Signals: rail-side photo; asks for infra field (capacity, line name).
- Steps: 1) ID train model → operating lines 2) Overpass pylons along each corridor 3) streetview match 4) utility-doc field read.
- Commands: Overpass power-line query; quoted model search.
- Pitfalls: shared rolling stock across lines; doc revision year.
- Sources: https://zenn.dev/kn1cht/articles/diver-osint-ctf-2024-kakitsubata ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2024-13be6d7ea847 ; https://qiita.com/kikyo_nanakusa/items/e7faba1ae788b9a009cf

### W11 — Email-lookup → account → review-profile pivot
- Signals: target email; asks for name, reviews, places.
- Steps: 1) email-lookup service → full name + account ID 2) maps-contrib page for that ID 3) reviews → venues/dates.
- Commands: quoted-email search; no CLI.
- Pitfalls: common-name collisions; corroborate with photo/bio before promoting.
- Sources: https://ctftime.org/writeup/38385 ; https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges/tree/main/Forensics/cartesian-2 ; https://medium.com/@l0rd5ud0/iris-ctf-2024-osint-challenge-51d8ae9f1ef8

### W12 — Census-dataset credential-list rebuild
- Signals: stub list with place+number pattern; asks for vault/sheet password.
- Steps: 1) identify source dataset (census) 2) download matching edition 3) regenerate full list in stub format 4) crack offline.
- Commands: `john --wordlist=rebuilt.txt sheet.hash` ; spreadsheet formula build.
- Pitfalls: dataset year/edition mismatch; delimiter exactness.
- Sources: https://enscribe.dev/blog/wolvctf-2023/wannaflag-series/ ; https://ctftime.org/writeup/38387

### W13 — Social-wordlist × date-variant hash crack
- Signals: persona hash + dossier of likes/places/dates.
- Steps: 1) harvest like-words (foods, places, names) + dates 2) variant-expand (case/plural/date formats) 3) product-generate 4) GPU/offline crack.
- Commands: `hashcat -m 3200 hash.txt custom.txt` ; `itertools.permutations` builder.
- Pitfalls: combinatorial explosion — prune with hint constraints first.
- Sources: https://ctftime.org/writeup/38387 ; https://hackmd.io/@vow/BybjdCJta ; https://medium.com/@l0rd5ud0/iris-ctf-2024-osint-challenge-51d8ae9f1ef8

### W14 — Hash-prefix exposure screen
- Signals: candidate passwords; asks which leaked / how often.
- Steps: 1) SHA1 each candidate 2) query first-5-char range 3) match suffix counts locally.
- Commands: `python3 -c "import hashlib;print(hashlib.sha1(pw.encode()).hexdigest().upper())"` + range GET.
- Pitfalls: never transmit full hash/password; count ties need second signal.
- Sources: https://ctf.thaysan.com/ctf-and-writeups/2024-or-unbreakable/osint/safe-password

### W15 — Ledger input-data message read
- Signals: chain address + ransom/demand note.
- Steps: 1) explorer → address tx list 2) spot self-transfer 3) decode input-data as UTF-8.
- Commands: none CLI; use correct (test vs main) explorer.
- Pitfalls: wrong-network explorer shows nothing; internal-tx vs input-data confusion.
- Sources: https://enscribe.dev/blog/wolvctf-2023/wannaflag-series/ ; https://medium.com/@hughbrown123/osint-htb-challenges-e946b8f8ca87

### W16 — Deleted-forum-user recovery
- Signals: locked forum + deleted/unavailable user.
- Steps: 1) quoted keyphrase search → forum 2) archive-service comment lookup 3) recover handle → re-pivot.
- Commands: quoted-phrase + `site:` searches; archive-service query.
- Pitfalls: single-archive gaps; try 2+ mirrors before declaring gone.
- Sources: https://enscribe.dev/blog/wolvctf-2023/wannaflag-series/ ; https://medium.com/@leventd/cybersoc-cyber-detective-ctf-write-up-life-online-2b9b5f898de

### W17 — Gaming-platform identity pivot
- Signals: game refs, invite links, school-app notes, odd usernames.
- Steps: 1) commit/profile email → username search 2) game profiles 3) invite-link char-diff fix 4) handle sweep → paste/profile find.
- Commands: `sherlock`-family handle sweep; quoted-username search.
- Pitfalls: handle false-positives; require avatar/bio second correlate.
- Sources: https://enscribe.dev/blog/wolvctf-2023/wannaflag-series/ ; https://qiita.com/GenkaiChan/items/ebdc72d940438677a2f

### W18 — Status-post + email-format inference
- Signals: staffer graph; asks for internal mailbox.
- Steps: 1) profile graph → status-post cue (e.g. out-of-office) 2) infer format from known addresses 3) validate via checker 4) stop if contact is out-of-scope.
- Commands: quoted name + site searches; no sending without explicit challenge sanction.
- Pitfalls: format drift across hires; unvalidated guess = burn of limited attempts.
- Sources: https://github.com/rehackxyz/REUN10N/tree/main/CTF-writeups/2024/PatriotCTF/osint/phase-one ; https://medium.com/@kaungzawhein.mk/patriot-ctf-2024-writeup-5724b71e7a27

### W19 — Catalog decay-sort second-to-last
- Signals: destroyed craft; asks for pre-last debris piece + ID.
- Steps: 1) event wiki → craft + date 2) public catalog search 3) uncheck filters hiding decayed rows 4) sort by decay → pre-last row.
- Commands: catalog query URL with object-ID filter.
- Pitfalls: default filters hide decayed objects; API vs UI row mismatch.
- Sources: https://la13x.github.io/2023/09/11/PCTF-wp/ ; https://blog.bravosec.net/posts/PatriotCTF-2023/ ; https://medium.com/@thisiskaung/patriotctf-2023-writeups-2aefb19bee18

### W20 — Chat-ID snowflake → timestamp
- Signals: long numeric IDs in chat/CDN URLs.
- Steps: 1) extract each numeric segment 2) convert via snowflake epoch 3) label channel-ID vs file-ID semantics.
- Commands: `python3 -c "print((ID>>22)+1420070400000)"` then UTC convert; or unfurl parse.
- Pitfalls: channel-create ≠ first-message; file-ID = upload, not send-read.
- Sources: https://mwalkowski.com/post/sherlock-constellation/ ; https://0xdf.gitlab.io/2024/06/05/htb-sherlock-constellation.html ; https://blog.hamayanhamayan.com/entry/2024/07/15/222738

### W21 — Search-URL parameter timeline
- Signals: pasted search-engine URL in evidence.
- Steps: 1) split `q` (final) vs `oq` (typed) 2) decode session/time tokens 3) order against file-event times.
- Commands: URL-decode params; unfurl-style parse; no CLI needed.
- Pitfalls: params rotate over time; corroborate with a second token.
- Sources: https://0xdf.gitlab.io/2024/06/05/htb-sherlock-constellation.html ; https://mwalkowski.com/post/sherlock-constellation/ ; https://medium.com/@chaoskist/htb-sherlocks-write-up-constellation-71a5a8284448

### W22 — Document-property author + anomaly read
- Signals: provided PDF/notice; asks who authored or what is off.
- Steps: 1) dump full properties 2) author/producer/title/created 3) impossible date = tamper signal 4) author-token → profile search.
- Commands: `exiftool -a -G1 doc.pdf` ; `pdfinfo doc.pdf`
- Pitfalls: all fields forgeable — author needs second-artifact corroboration.
- Sources: https://mwalkowski.com/post/sherlock-constellation/ ; https://0xdf.gitlab.io/2024/06/05/htb-sherlock-constellation.html ; https://hack.nikkei.com/blog/ctf_osint_diver_2025/

### W23 — Crowdsourced-review pivot
- Signals: venue/restaurant/lodging photo; review-site review by persona.
- Steps: 1) venue lock via photo 2) review-site venue page → persona review 3) review text/media → handle, date, companion detail.
- Commands: quoted venue + persona searches; review-sort by newest.
- Pitfalls: common names in reviews; planted-review vs organic-review check via account history.
- Sources: https://dree.blog/posts/nahamcon-ctf-2022/ ; https://maplebacon.org/2023/07/uiuctf-osint/ ; https://mindcrafters.xyz/writeups/swampctf-osint/

### W24 — Split-record value join
- Signals: two DNS/text halves each holding part of a secret.
- Steps: 1) query both record names 2) read policy/meaning of each half 3) concatenate in challenge order.
- Commands: `dig +short example.com TXT` ; `dig +short _dmarc.example.com TXT`
- Pitfalls: record caching staleness; wrong join order.
- Sources: https://sechub.in/view/2820461 ; https://medium.com/@hughbrown123/osint-htb-challenges-e946b8f8ca87

### W25 — Livery × route × gate-code triangulation
- Signals: tarmac photo with several aircraft; asks for airport code.
- Steps: 1) ID each livery incl. tail-logo-only craft 2) intersect route sets 3) gate-code lettering rule 4) spotter-blog photo confirm.
- Commands: quoted registration + Lens crop searches.
- Pitfalls: code-share liveries; similar gates at hub pairs.
- Sources: https://tsukuctf.org/ctf/TsukuCTF2023/travel_with_tsukushi ; https://blog.albina.cc/posts/tsukuctf2023-writeup/ ; https://hackmd.io/@eaint/tsukuctf-2023-writeup

### W26 — Fictional-map alphabet coordinate decode
- Signals: game-map scene; lettered coordinates.
- Steps: 1) confirm map identity 2) find map-wiki alphabet rule 3) letters→digits 4) DMS→decimal convert.
- Commands: `python3 -c` DMS→DD math; quoted map-name search.
- Pitfalls: per-map alphabets differ; fan-wiki vs canonical rule.
- Sources: https://qiita.com/GenkaiChan/items/ebdc72d940438677a2f ; https://www.sitoosite.net/computer/1585/

### W27 — Menu-item venue lock
- Signals: food-blog persona; dish/drink names; hometown page.
- Steps: 1) about-page hometown 2) town + dish + drink search 3) review-post/menu lock.
- Commands: quoted dish + town searches.
- Pitfalls: chain venues with same menu; seasonal-menu drift.
- Sources: https://zenc.my.id/blog/irisctf-2025 ; https://maplebacon.org/2023/07/uiuctf-osint/

### W28 — Vehicle-model → city + brand single-hit
- Signals: transit-vehicle photo + adjacent shop brand.
- Steps: 1) vehicle model → city/fleet 2) map brand-query scoped to city 3) single-hit → street confirm.
- Commands: Overpass brand query; quoted model search.
- Pitfalls: multi-city fleets; rebranded shops.
- Sources: https://medium.com/@horus_/writeup-ctf-thcon-2025-osint-3a166f406d1a ; https://blog.ar-lacroix.fr/posts/2025/04/thcon-ctf-2025-geosint-write-up/

### W29 — Road-distance isoline triangulation
- Signals: distance-board with towns + km.
- Steps: 1) read board towns/distances 2) plot ROAD-distance rings (not crow-flies) 3) intersect → candidate 4) crowd-photo confirm.
- Commands: isoline tool or OSM routing queries; streetview verify.
- Pitfalls: crow-flies rings land in the sea; sign-side vs facing-side confusion.
- Sources: https://medium.com/@horus_/writeup-ctf-thcon-2025-osint-3a166f406d1a ; https://blog.ar-lacroix.fr/posts/2025/04/thcon-ctf-2025-geosint-write-up/

### W30 — Fandom-account → archive → acrostic
- Signals: fandom handle + dead links + riddle text.
- Steps: 1) fandom-account find 2) about-page riddle 3) dead-link → archive capture 4) post-history → second link 5) acrostic read.
- Commands: archive-availability + CDX exact-URL fetch.
- Pitfalls: archive robots-gaps; acrostic line-order shifts.
- Sources: https://ctftime.org/writeup/39524 ; https://medium.com/thedeephub/2024-n00bz-ctf-pastebin-writeup-aaa8991187ed ; https://medium.com/techiepedia/ctf-1337up-ctf-blinks-secret-71149427f852

### W31 — Commit-address identity + patch-email reveal
- Signals: code-profile; asks for personal email.
- Steps: 1) commit list → off-domain address 2) patch-view for full address 3) username search re-pivot.
- Commands: `git log --format='%H %an %ae %s'` ; `.../commit/<sha>.patch`
- Pitfalls: noreply/private addresses; squashed-history loss.
- Sources: https://infosecwriteups.com/approaching-ctf-osint-challenges-learn-by-example-b92be1dddc8d ; https://enscribe.dev/blog/wolvctf-2023/wannaflag-series/ ; https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges/tree/main/Forensics/cartesian-2

### W32 — Public-text vault crack
- Signals: encrypted vault + single-word-themed password hint.
- Steps: 1) harvest org public words 2) format per hint 3) hash-extract 4) dictionary crack.
- Commands: `keepass2john vault.kdbx > h.txt` ; `hashcat -m 13400 h.txt words.txt`
- Pitfalls: format variants (case/plural); rockyou-first wastes the hint.
- Sources: https://infosecwriteups.com/approaching-ctf-osint-challenges-learn-by-example-b92be1dddc8d ; https://dree.blog/posts/nahamcon-ctf-2022/

### W33 — Multi-gate account-reset chain
- Signals: reset-QA wall (10+ questions) over one persona.
- Steps: 1) map each Q to cheapest source (posts, commits, calendar, career-pages) 2) trilaterate distance-Qs 3) commit-age math 4) submit once.
- Commands: quoted handle + site searches; `git log` date math.
- Pitfalls: limited attempts — never probe; solve fully offline first.
- Sources: https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges/tree/main/Forensics/cartesian-3 ; https://medium.com/@lecture_honorer/imaginaryctf-2024-writeup-part-2-74c15a6032db

### W34 — Video-frame hotel via old streetview
- Signals: hotel-room video; venue demolished/renamed.
- Steps: 1) freeze landmark frames 2) reverse-search → building lock 3) stance from angle 4) old streetview layer → prior name.
- Commands: frame-extract + reverse-search; streetview time-slider.
- Pitfalls: current-name searches miss defunct venues; angle mirrored by pano stitching.
- Sources: https://infophreak.com/tryhackme-searchlight-imint-writeup/ ; https://blog.michweb.de/2024/06/08/tryhackme-searchlight-imint-write-up/

### W35 — Photo-time via globe sun-scroll + shadow-map
- Signals: outdoor photo; asks WHEN (block or minute).
- Steps: 1) EXIF place + date cue 2) 3D-globe sun-scroll to match rays 3) shadow-map time sweep 4) answer the required block.
- Commands: `exiftool -GPS* -DateTimeOriginal photo.jpg` ; sun/shadow web tools.
- Pitfalls: viewer-vs-capture timestamps; DST vs standard-time slips.
- Sources: https://blog.wern.cc/govtech-stack-the-flags-2020-writeups ; https://stromlarsen.com/2023/12/09/npst-09-kronolokalisering/ ; https://qiita.com/GenkaiChan/items/ebdc72d940438677a2f

## Writeup-Distilled Patterns R2 (W36..W71)

> Mined from `knowledge/writeups_mined/osint_manifest_r2.md` (713
> challenge-lines, all Hard, 2024–2026, zero R1 URL overlap). Bodies live in
> `skills/osint/techniques/writeup-patterns-r2-{1,2,3,4}.md`; rows below are
> index-only. Methods-only; fictional CTF targets. Reasoning Checkpoint:
> evidence = 2+ named sources agreeing per pattern → HIGH/MEDIUM/LOW.

### W36 — Air-to-air callsign-vs-registration split → techniques/writeup-patterns-r2-1.md (distant-craft frame; callsign ≠ registration)
### W37 — Aviation-history archive triangulation → techniques/writeup-patterns-r2-1.md (sortie log + roster + damage report + time window)
### W38 — Orbital-pass proximity + vessel-registry resolve → techniques/writeup-patterns-r2-1.md (TLE + base coords + AIS window + registry field)
### W39 — Equirect pano unwarp + brand-pylon triangle → techniques/writeup-patterns-r2-1.md (curvy panorama; two-landmark triangle)
### W40 — Clip watermark → profile → native-language field hunt → techniques/writeup-patterns-r2-1.md (seconds-long clip; POI coords)
### W41 — Historical complaint-desk + newspaper-edition pivot → techniques/writeup-patterns-r2-1.md (decades-old cue; archive edition match)
### W42 — Native-language search ladder → techniques/writeup-patterns-r2-1.md (foreign script stalls English search)
### W43 — Signage-script + road-code decoder → techniques/writeup-patterns-r2-1.md (road plates/codes; intersection + radius sweep)
### W44 — CT-log + DNS + WHOIS infra triangulation → techniques/writeup-patterns-r2-1.md (fictional org domain; record fields)
### W45 — Favicon-hash at-scale infra match → techniques/writeup-patterns-r2-1.md (in-scope host; shared scaffolding / origin check)
### W46 — Credential-reuse + provided-dump join → techniques/writeup-patterns-r2-2.md (persona hints; PROVIDED dump only; fictional use)
### W47 — Sockpuppet-graph follower/following walk → techniques/writeup-patterns-r2-2.md (quiet starter profile; hidden watcher bio)
### W48 — Snowflake/ID-epoch timestamp math → techniques/writeup-patterns-r2-2.md (chat/CDN numeric IDs; start/upload times)
### W49 — Search-URL session-token timeline → techniques/writeup-patterns-r2-2.md (pasted search URLs; query order/times)
### W50 — Doc-property author + anomaly trio → techniques/writeup-patterns-r2-2.md (provided doc; author or tamper signal)
### W51 — Commit-message archaeology → techniques/writeup-patterns-r2-2.md (delete-secret message; pre-fix SHA recovery)
### W52 — Seven-hop EXIF identity chain → techniques/writeup-patterns-r2-2.md (one image → avatar/city/network/email/holiday/secret)
### W53 — Blog author-archive + concealed-text secret → techniques/writeup-patterns-r2-2.md (persona blog; hidden rows)
### W54 — Review-plant + commute-bound workplace lock → techniques/writeup-patterns-r2-2.md (staffer + venue hints; review match)
### W55 — Degraded-asset recovery → techniques/writeup-patterns-r2-2.md (pixelated/HEIC/cropped asset; facility cue)
### W56 — Ledger self-transfer message read → techniques/writeup-patterns-r2-3.md (chain address + demand note; input-data decode)
### W57 — Threat-intel IP→coven + malware→actor double pivot → techniques/writeup-patterns-r2-3.md (attack IP + victim reports)
### W58 — Multi-image exam orchestration → techniques/writeup-patterns-r2-3.md (image bundle + question server; per-row formats)
### W59 — Question-recovery (find-your-own-question) → techniques/writeup-patterns-r2-3.md (description-less board)
### W60 — Rail video-frame → operator → speed-table chain → techniques/writeup-patterns-r2-3.md (train clip; model + speed)
### W61 — Grid-square trial-budget discipline → techniques/writeup-patterns-r2-3.md (3-word answer; 5–10 adjacent trials)
### W62 — Night-photo venue lock → techniques/writeup-patterns-r2-3.md (night scene; lamp + type filter)
### W63 — Rules-channel acrostic + ID hunt → techniques/writeup-patterns-r2-3.md (community server; hidden line/ID)
### W64 — Commute/travel-post geographic bound → techniques/writeup-patterns-r2-3.md (travel posts; short-ride bound)
### W65 — Edited-post + description-line find → techniques/writeup-patterns-r2-3.md (follow-for-clues page; hidden line)
### W66 — Fitness-tracker route + heatmap pivot → techniques/writeup-patterns-r2-4.md (training-route photo; pause = transfer point)
### W67 — AI-geolocation estimate + manual-verify loop → techniques/writeup-patterns-r2-4.md (featureless photo; top-3 candidates verified)
### W68 — Career-platform endorsement + contact-info pivot → techniques/writeup-patterns-r2-4.md (org profile; endorsement reveals partner)
### W69 — Cell-tower open-data triangulation → techniques/writeup-patterns-r2-4.md (two antenna IDs; search between + OSM sweep)
### W70 — OSM object-history persona pivot → techniques/writeup-patterns-r2-4.md (map object history; alt-handle + QR hop)
### W71 — Multi-pano country-code flag assembly → techniques/writeup-patterns-r2-4.md (N panoramas; letters + population case rule)

## EASY-FIRST ladder (2026 training refresh — ≤20 min)
1. Exact-quote Google (`"handle"` + `site:`) + reverse-image-search the photo (crop landmark first).
2. `sherlock`/`maigret` on the handle → MANUALLY verify top hits (GitHub/Twitter/Reddit); rate-limits lie, browsers don't.
3. Photo: `exiftool -a -u -g1 | grep -i 'gps|comment|artist'`; stripped EXIF → Street View landmarks, shadows/vegetation/signs.
4. Deleted/secret pages: `waybackurls TARGET | grep -i flag`; GitHub: `git log -p --all | grep -i 'flag|password|key'` (history + branches, not HEAD).
5. Domains/infra: `crt.sh %25.target + dig ANY +short`; `whois`/Shodan for the rest.

## R4 field patterns (browser-swarm 2026 — from 48 new writeups)
- ADS-B tail-numbers: registration → archive route reconstruction (flight-tracking challenges).
- Plus-Codes + OSM way IDs: Japanese PDF/video geolocation via Gemini + OpenStreetMap metadata cross-check.
- UN/NGO docs: Digital Library resolutions (voter/abstain lists) answer "who" questions directly.
- Street-view signage chains: storefront → brand → address (Taco-Bell/Parmer pattern); stream jerseys + timestamps for event location.

Deep-read bodies (5 complete articles): techniques/r5-deep-reads.md.
