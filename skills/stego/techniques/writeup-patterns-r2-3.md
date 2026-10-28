# Stego Writeup-Distilled Patterns, R2 Part 3 — Documents / Audio-Deep / Chains (W69–W80)

Same source discipline as R1. Every pattern cites 2-3 real URLs from the R2 manifest
(`knowledge/writeups_mined/stego_manifest_r2.md`). Technique-only: no flag or payload values.
These patterns EXTEND `../SKILL.md` — nothing here repeats its pipeline or playbook.

## W69 — PDF polyglot plus ACK-whitespace plus versioned streams

Recognition: file reports as data, Ruby header plus PDF header plus ZIP in one, blank-page render, object 1337 hints.
Steps: (1) run as Ruby to get self-served ZIP (mutool plus note); (2) `bbe` replace 0x06-stream with whitespace; (3) Polyfile html to object 0x1337 versions; (4) cascade-decode Flate plus ASCIIHex plus DCT second version.
```bash
bbe -e "s/\x06stream\n/\nstream\n/" -o fixed.pdf challenge.pdf
polyfile fixed.pdf --html fixed.html
```
Pitfalls: header may be past 1024B — parsers complain; first stream version is decoy hint; six-whitespace spec is the gate. Sources:
- https://blog.trailofbits.com/2021/02/02/pdf-is-broken-a-justctf-challenge/
- https://blog.didierstevens.com/2008/05/07/solving-a-little-pdf-puzzle/
- https://2014.mrmcd.net/fahrplan/system/attachments/2353/original/PDF_Secrets.pdf

## W70 — PDF embedded-file plus stream-carve chain

Recognition: PDF 1.7 two pages, pdf-parser stats show EmbeddedFile plus ObjStm plus unreferenced, strings shows fake only.
Steps: (1) `pdf-parser --stats` list EmbeddedFile 110 plus Filespec; (2) `--object 110 --raw --filter` extract JS AES; (3) binwalk zlib at offset carve fallback; (4) nodejs decrypt hex to bytes.
```bash
pdf-parser --stats strange.pdf
pdf-parser --object 110 --raw --filter strange.pdf > out.js
```
Pitfalls: version-warning is benign; Checksum validates decrypt input; comment plus XREF plus Trailer counts guide object pick. Sources:
- https://ctftime.org/writeup/37014
- https://0xnaresh.hashnode.dev/pdf-forensics-challenge-writeup-scriptctf-2025.md
- https://blog.trailofbits.com/2021/02/02/pdf-is-broken-a-justctf-challenge/

## W71 — PDF incremental phishing reuse forensics

Recognition: PDF with 5x %%EOF, same object index (e.g. 41) repeated with different URIs, Word author plus ISO timestamps.
Steps: (1) `pdfid -e` count EOFs; (2) extract each object-41 version across EOFs; (3) re-search ISO timestamps plus metadata author; (4) truncate after each EOF to recover prior campaign PDFs.
Pitfalls: linearized PDFs also multi-trailer — check Linearized object; active URL is last version only; timezone offset is investigative, not payload. Sources:
- https://isc.sans.edu/diary/25904
- https://blog.didierstevens.com/2008/05/07/solving-a-little-pdf-puzzle/
- https://2014.mrmcd.net/fahrplan/system/attachments/2353/original/PDF_Secrets.pdf

## W72 — OOXML off-page coords plus header brainfuck

Recognition: docx opens with little visible text, bottom-left count mismatch, document.xml has large negative coords.
Steps: (1) `unzip Secret.docx`; (2) grep document.xml for minus-80000 coords; (3) set them to 0, `zip -r fixed.docx`; (4) enlarge header text, run brainfuck via dcode.
```bash
unzip Secret_file.docx -d docx_out
grep -o '\-84524 \|\-914400' docx_out/word/document.xml | head
```
Pitfalls: header1.xml holds same code — check both; select-all plus black recolor confirms hidden extent; coordinates differ per file — don't hardcode. Sources:
- https://ctf.krloer.com/writeups/cybergon/hide_and_seek/
- https://odintheprotector.github.io/2024/07/13/osctf-forensic.html
- https://mindcrafters.xyz/writeups/forensic-why2025/

## W73 — OOXML VBA-xor blackout recovery

Recognition: docm with blacked-out text, encrypted-looking strings, vbaProject.bin present, core.xml username.
Steps: (1) unzip, read word/vbaProject.bin decrypt routine (xor 0x7B plus username lower nospace from second byte); (2) get username from docProps/core.xml; (3) apply to blacked-out runs; (4) validate 5-of-5 sweep.
Pitfalls: username transform is exact (lower, no spaces, second-byte start); 0x7B is per-file — read bin, don't assume; PII-safe handling required. Sources:
- https://mindcrafters.xyz/writeups/forensic-why2025/
- https://ctf.krloer.com/writeups/cybergon/hide_and_seek/
- https://docs.rs/chk_defaced/latest/src/chk_defaced/scan/docx.rs.html

## W74 — OOXML media steghide chain (decoy-aware)

Recognition: docx with word/media images, exiftool clean, binwalk lists ZIP segments, crab plus sponge plus squid set.
Steps: (1) `unzip docx -d contents`; (2) steghide blank-pass each media (crab first for hint); (3) follow hint to cashier image (squid); (4) extract second layer, ignore decoy text.
```bash
unzip word_sea_adventures.docx -d docx_contents
steghide extract -sf docx_contents/word/media/crab.jpg -p ''
steghide extract -sf docx_contents/word/media/squid.jpg -p ''
```
Pitfalls: first image is hint, not answer — read decoy; chatgpt-style guessing wastes time — follow file-size outlier; tctf versus pctf format gate. Sources:
- https://prayush.hashnode.dev/word-sea-adventures-writeup
- https://ctf.krloer.com/writeups/cybergon/hide_and_seek/
- https://github.com/isaaclo97/JNIC_2024

## W75 — OOXML vanish plus obfuscated-font (odttf) forensics

Recognition: docx with fontTable plus odttf, w:t looks clean, chk_defaced flags vanish plus font issues, visibility scan hits.
Steps: (1) extract w:t plus count w:vanish; (2) get fontKey GUIDs from fontTable.xml; (3) deobfuscate odttf (try reversed plus normal); (4) glyph-outline substitution check vs registry.
Pitfalls: no rendering in v1 — structural plus font first; reversed GUID variant common; near-white plus sub-visible is prompt-injection vector, verify. Sources:
- https://docs.rs/chk_defaced/latest/src/chk_defaced/scan/docx.rs.html
- https://readthedocs.org/projects/docxperiments/downloads/pdf/latest/
- https://mindcrafters.xyz/writeups/forensic-why2025/

## W76 — Whitespace SNOW plus COW esolang chain

Recognition: poem txt with tabs-spaces, SNOW caps title, password is name, pastebin Mooooooo hop, COW file magic.
Steps: (1) `cat -A` confirm trailing WS; (2) `stegsnow -C -p Name poem.txt` decrypt; (3) file Mooooooo.txt check COW magic; (4) cachesleuth COW interpreter exec.
```bash
stegsnow -C -p "Aakash" poemm.txt
file Mooooooo.txt
```
Pitfalls: -C compress flag mandatory; name password case-exact; MOo case variants are ops — don't lowercase. Sources:
- https://medium.com/@hellspy-usscfedora.org/kashi-ctf-2025-steganography-snowy-evening-a-stegsnow-cow-writeup-4c4edefaa626
- https://github.com/isaaclo97/JNIC_2024
- https://www.dkly.net/blog/post/ctf-cit-2025-write-up-blank-image-steganography

## W77 — Ultrasonic dual-morse (decoy plus hidden)

Recognition: audio with audible morse plus spectrum-retune hint, 500Hz decoy plus 20kHz ultrasonic, hex-fix mention.
Steps: (1) decode audible morse (decoy); (2) retune spectrum to 18-21kHz, isolate ultrasonic; (3) decode second morse; (4) hex-fix join.
Pitfalls: stopping at first morse is the trap; sample-rate must support ultrasonic (44.1k-plus); bandpass before decode. Sources:
- https://medium.com/@mussharat08/while-participating-in-ritsec-ctf-2025-i-came-across-a-challenge-in-the-miscellaneous-category-c9b7bf336a02
- https://medium.com/@joonhaobek/lnc-ctf-2025-secure-the-network-write-up-15a3f6de4f7e
- https://medium.com/@panahifarah/ctf-write-up-decoding-hidden-exfiltration-via-dns-queries-creepy-dns-f30fc5067488

## W78 — ICMP-telemetry covert plus DTMF-telegram hop

Recognition: pcapng with TLS noise plus ICMP few packets, covert-communication hint, telegram bot plus taxi-cab-number cue.
Steps: (1) filter icmp, caesar-4 the payload chat; (2) follow g3t_audi0 plus 1729-squared password to telegram; (3) WAV DTMF via netlify decoder to digit string; (4) ascii-to-text convert.
Pitfalls: TLS decrypt is rabbit hole — ICMP is the channel; 1729 squared is 2989441 — compute, don't guess; DTMF order plus spaces matter. Sources:
- https://infosecwriteups.com/c0c0n-ctf-2025-writeup-97d6c66026f7
- https://medium.com/@joonhaobek/lnc-ctf-2025-secure-the-network-write-up-15a3f6de4f7e
- https://medium.com/etticblog/hackfest24-write-up-galactica-dnsnet-bb06742fc37c

## W79 — KnightCTF multi-hop (base58-DeepSound-binwalk plus zip-morse-steghide)

Recognition: tar with clue.jpg plus peaceful.wav, base58 time string, morse beeps plus lowercase-tip file, size-outlier image.
Steps: (1) exiftool base58 decode to ocean phrase; (2) DeepSound with phrase to flag.png; (3) binwalk flag.png recurse; (4) parallel: zip2john plus morse plus lowercase steghide on outlier.
```bash
exiftool clue.jpg | head
fcrackzip -b -D -p /usr/share/wordlists/rockyou.txt -u chall.zip
```
Pitfalls: sonic-visualizer morse hole is distractor for Oceanic — DeepSound first; lowercase-only tip is load-bearing; size-sort finds outlier fast. Sources:
- https://warlocksmurf.github.io/posts/knightctf2024/
- https://0xepitome.github.io/posts/ctf-writeups/knight24/
- https://t3l3sc0p3.github.io/posts/knightctf-2024-writeup/

## W80 — Classroom-CTF ladder (UWSP tiers plus alien-cipher)

Recognition: repo tree with Stego 100-400 tiers, clock-tower SOS story, JPG-plus-cipher plus instruction chain.
Steps: (1) climb tiers: line-gap (100) to micro-LSB (200) to polyglot (300) to multi-layer (400); (2) JPG zip carve; (3) dcode alien-language decipher; (4) follow instruction text.
Pitfalls: tier order teaches tools — don't jump to 400; alien cipher needs exact dcode table; instruction-follow hop is graded. Sources:
- https://github.com/shivang1209-dot/CTF-Writeup/tree/main/UWSP%20Pointer%20Overflow%20CTF24/Stego
- https://github.com/rehackxyz/REUN10N/tree/main/CTF-writeups/2024/SpookyCTF/steg-Phenominal-Photo
- https://breydensummers.github.io/blog/SOC-CTF-2024-Steganography-Writeup/
