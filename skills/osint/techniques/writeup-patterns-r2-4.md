# OSINT R2 Patterns — Fitness / AI-Geo / Career-Graph / Infra / Assembly (W66–W71)

> Methods-only. Fictional CTF targets. Each pattern: signals → steps →
> commands → pitfalls → 2–3 R2 source URLs (all in
> `knowledge/writeups_mined/osint_manifest_r2.md`, zero R1 overlap).

### W66 — Fitness-tracker route + heatmap pivot
- Signals: run/ride photo or persona with training posts; asks place from route.
- Steps: 1) profile/route-ID open (athlete search, URL ID) 2) route geometry → park/place photo match 3) pause-duration anomalies = transfer/meet points 4) heatmap confirms frequented spot.
- Commands: athlete-name search; route-photo vs maps-photo compare; pause-time read.
- Pitfalls: relocated personas; treadmill/spoofed activities; private-by-default gaps.
- Sources: https://sherlockholmes.is-a.dev/posts/ctfs/greyctf-2025-quals-writeups/ ; https://camael.fr/en/writeups/where_was_chine/ ; https://blog.ar-lacroix.fr/posts/2024/04/toulouse-hacking-convention-2024-osint/

### W67 — AI-geolocation estimate + manual-verify loop
- Signals: featureless or low-cue photo; asks coords with no streetview.
- Steps: 1) AI-guess narrows country/region (never trust blindly) 2) pick top-3 candidates 3) manual stance/satellite verify each 4) log AI misses explicitly.
- Commands: AI-classify API loop; candidate table with verify-status per row.
- Pitfalls: AI hallucinates confident regions; similar biomes across continents.
- Sources: https://www.securityartwork.es/2024/06/18/geolocation-through-artificial-intelligence-osint/ ; https://medium.com/@sunya22839/independence-day-ctf-2024-5db1c239815c ; https://blog.spuria.app/writeups/geoclip-streetclip-hacktoria-norway/

### W68 — Career-platform endorsement + contact-info pivot
- Signals: fictional org/persona; asks partner identity or hidden collab.
- Steps: 1) org profile → bio-link walk 2) endorsement/skill section = partner reveal 3) contact-info block = next platform (audio/playlist) 4) follow-gated activity exposes hidden item.
- Commands: bio-link inventory; endorsement list read; follow + activity-panel check.
- Pitfalls: fan/parody profiles; empty profiles needing follow-gate; renamed playlists.
- Sources: https://odintheprotector.github.io/2024/07/01/UIUCTF-OSINT-writeup.html ; https://kevin.fish/writeups/11ade1fe6eaaf1a864f60291a6ca3764 ; https://k3sero.github.io/posts/linkedout-recon-TJCTF2025/

### W69 — Cell-tower open-data triangulation
- Signals: two antenna/station IDs; asks hideout coords, reverse-search-proof photo.
- Steps: 1) regulator open-data map → two antenna fixes 2) search between them (third would be ideal) 3) OSM query for candidate structures 4) walk candidates to stance match.
- Commands: regulator map query; Overpass structure sweep; stance-verify per candidate.
- Pitfalls: two antennas = area not point; outdated OSM structures; IRL photos unsearchable.
- Sources: https://blog.ar-lacroix.fr/posts/2024/04/toulouse-hacking-convention-2024-osint/ ; https://blog.ar-lacroix.fr/fr/posts/2024/04/toulouse-hacking-convention-2024-osint/

### W70 — OSM object-history persona pivot
- Signals: map object tied to challenge; asks handle/instance/meeting place.
- Steps: 1) object history → creator node + notes 2) profile line gives alt-handle 3) handle-sweep → second profile 4) desk-photo QR/code → hidden instance hop.
- Commands: object-history view; quoted alt-handle search; QR/photo-code scan.
- Pitfalls: vandalism edits; shared editor accounts; QR rotation/expiry.
- Sources: https://blog.ar-lacroix.fr/posts/2024/04/toulouse-hacking-convention-2024-osint/ ; https://blog.ar-lacroix.fr/fr/posts/2024/04/toulouse-hacking-convention-2024-osint/

### W71 — Multi-pano country-code flag assembly
- Signals: N panorama images, no coords; asks flag built from countries.
- Steps: 1) per-image country via script/plate/sign/vegetation/vehicle meta 2) population rule → letter case/placeholder 3) guess-check partial words against dictionary 4) hardest images last, constrained by word shape.
- Commands: per-image clue table; population lookup; word-shape filter.
- Pitfalls: look-alike plates/signs; StreetView coverage gaps; forcing words too early.
- Sources: http://www.kronbergbuehlertal.com/blog/geo.html ; https://www.cjxol.com/posts/idekctf-2024-writeup/
