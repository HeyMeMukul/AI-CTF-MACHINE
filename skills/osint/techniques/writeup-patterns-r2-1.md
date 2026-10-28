# OSINT R2 Patterns — Flight / Maritime / Imagery / Language / Infra (W36–W45)

> Methods-only. Fictional CTF targets. Each pattern: signals → steps →
> commands → pitfalls → 2–3 R2 source URLs (all in
> `knowledge/writeups_mined/osint_manifest_r2.md`, zero R1 overlap).

### W36 — Air-to-air callsign-vs-registration split
- Signals: video frame shows a distant aircraft; task asks for BOTH callsign and registration (they differ).
- Steps: 1) freeze the clearest frame 2) crop distant craft only (not the photographer's own) 3) read callsign-vs-registration as separate fields 4) registry-decode the survivor.
- Commands: `ffmpeg -ss <t> -i clip.mp4 -frames:v 1 frame.png` ; `exiftool -DateTimeOriginal -GPSPosition frame.png`
- Pitfalls: answering with the photographer's own craft; code-share callsign confusion.
- Sources: https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763 ; https://github.com/diver-osint-ctf/writeups/tree/main/diver2025 ; https://github.com/spideyctf/DawgCTF-2026-Writeups/tree/main/OSINT

### W37 — Aviation-history archive triangulation
- Signals: historical sortie photo/log; asks mission number + pilot + damage spot + time window.
- Steps: 1) date-sortie → mission-log archive 2) roster → pilot lock 3) damage report → fragment spot 4) path log → ISO window.
- Commands: quoted sortie-date + `site:` archive search; log-table read.
- Pitfalls: similarly-numbered missions; post-war renames; local-vs-UTC log times.
- Sources: https://medium.com/@hadir3mr/aviation-history-them-ctf-2026-writeup-da3b03f92908 ; https://ctftime.org/writeup/40517 ; https://ctftime.org/writeup/40679

### W38 — Orbital-pass proximity + vessel-registry resolve
- Signals: TLE set + time window + research base; asks nearest vessel + identifier.
- Steps: 1) TLE → tracker script → lat/long series 2) nearest-pass timestamp to base coords 3) AIS-history window query 4) rank by distance → registry field.
- Commands: `python3 tle_track.py tle.txt --base LAT,LON` ; portal time-window query.
- Pitfalls: TLE epoch staleness; AIS gaps near poles; MMSI-vs-IMO field confusion.
- Sources: https://vulnquest58.github.io/ctf/writeups/challenges/osint/satellite/ ; https://github.com/spideyctf/DawgCTF-2026-Writeups/tree/main/OSINT

### W39 — Equirectangular pano unwarp + brand-pylon triangle
- Signals: distorted curvy panorama; asks exact coords; hint mentions a viewer.
- Steps: 1) pano-viewer unwrap 2) 360 pan for text (signs) 3) district anchor 4) brand-pylon second landmark → triangle 5) stance-match.
- Commands: pano-viewer upload; quoted-sign search; streetview stance compare.
- Pitfalls: searching before unwrapping; single-landmark guess without triangle.
- Sources: https://medium.com/@mohamedamenallahrouahi/writeup-spooky-ctf-geo-osint-75bde9b61602 ; https://www.jalblas.com/blog/tryhackme-searchlight-imint-walkthrough ; https://medium.com/@0xT4D/writeup-for-osint-tasks-securinets-friendly-ctf-2025-746bc1e1e3d3

### W40 — Clip watermark → profile → native-language field hunt
- Signals: seconds-long social clip, near-empty frame; asks nearest POI + coords.
- Steps: 1) frame-extract → watermark-handle read 2) public profile open → bio origin cue 3) native-language search → candidate fields 4) multi-element terrain match → POI lock.
- Commands: `ffmpeg -i clip.mp4 -vf fps=2 f%03d.png` ; quoted-handle + native-term search.
- Pitfalls: translated-keyword search misses local terms; one-element terrain match.
- Sources: https://medium.com/@zetrocleirbag/the-hidden-sunflowers-osint-industries-ctf-writeup-ebf1b676cff0 ; https://www.aristore.top/posts/DawgCTF2025 ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763

### W41 — Historical complaint-desk + newspaper-edition pivot
- Signals: decades-old grievance cue ("20 years ago, November") or dated clipping; asks reason/date.
- Steps: 1) date-window bound 2) municipal/newspaper archive search 3) edition match 4) reason/date field read.
- Commands: quoted-phrase + date-range search; archive-edition compare.
- Pitfalls: reprinted editions change dates; OCR misreads old type.
- Sources: https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763 ; https://github.com/diver-osint-ctf/writeups/tree/main/diver2025 ; https://ctftime.org/writeup/39562

### W42 — Native-language search ladder
- Signals: foreign-script signage; English search stalls.
- Steps: 1) transcribe script verbatim 2) search in the source language 3) city-scope the native phrase 4) branch/outlet hunt in-language.
- Commands: quoted native-phrase search; `site:` regional domains.
- Pitfalls: machine-transliteration drift; same chain, different city.
- Sources: https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763 ; https://medium.com/@zetrocleirbag/the-hidden-sunflowers-osint-industries-ctf-writeup-ebf1b676cff0 ; https://ctftime.org/writeup/40517

### W43 — Signage-script + road-code decoder
- Signals: road plates like `QL.32`/`DT.317` or district words; asks place from road furniture.
- Steps: 1) transcribe codes verbatim 2) code-system lookup (national road scheme) 3) intersection fix 4) radius sweep for target class.
- Commands: quoted code search; maps intersection + radius walk.
- Pitfalls: old-vs-new numbering; similarly-coded roads in other provinces.
- Sources: https://github.com/Lost-Kids-CTF/greyctf25-writeup ; https://medium.com/@mohamedamenallahrouahi/writeup-spooky-ctf-geo-osint-75bde9b61602 ; https://medium.com/@PretendNotToBe/writeup-of-diver-osint-ctf-2025-ea6e8f3fb763

### W44 — CT-log + DNS + WHOIS infra triangulation
- Signals: fictional org + domain; asks infra/record fields.
- Steps: 1) crt.sh wildcard JSON → subdomain list 2) `dig +short` each → live set 3) `whois` registrar lock 4) record-field read.
- Commands: `curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u` ; `dig +short X` ; `whois X`
- Pitfalls: expired-cert ghosts; wildcard-only certs hide hosts.
- Sources: https://github.com/ctf-cit/CIT-CTF-2025 ; https://github.com/MOCSCTF/MOCSCTF2025-Writeup ; https://luisvazquez2.github.io/spartanCTF-2024/OSINT

### W45 — Favicon-hash at-scale infra match
- Signals: in-scope host; asks shared-scaffolding / origin-behind-CDN evidence.
- Steps: 1) fetch favicon once 2) murmur3 hash 3) `http.favicon.hash:` corpus search 4) header/cert second-source confirm.
- Commands: `python3 -c "import mmh3,codecs,requests;print(mmh3.hash(codecs.encode(requests.get(URL+'/favicon.ico').content,'base64')))"`
- Pitfalls: default-framework favicons collide; CDN vs origin double-count.
- Sources: https://isc.sans.edu/diary/27326 ; https://book.shodan.io/command-line-tools/shodan-hash/ ; https://github.com/rix4uni/favinfo
