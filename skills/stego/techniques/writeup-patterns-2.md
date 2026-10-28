# Stego Writeup-Distilled Patterns, Part 2 — Audio / Docs / Terminal / Chains (W21–W40)

Same source discipline as Part 1. Extends `../SKILL.md` (which already covers
standard spectrogram/DTMF/SSTV/DeepSound/whitespace-ZW/PDF-streams/font-glyph
basics) — every entry below is harder substance only.

## W21 — Nested-resize survivor-pixel QR

Recognition: QR decodes to message A at full size but a DIFFERENT QR/message after
chained nearest-neighbor downscales (e.g. 500→250→100→50).
Steps: (1) confirm interpolation is nearest (else technique impossible);
(2) compute survivor index per step (`floor(orig·scale)+0.5` rounding — empirically
`(10i+7,10j+7)`-style per 10×); (3) sample survivors → hidden QR → zbarimg.
Pitfalls: bilinear/bicubic chains are one-way destructive — verify NEAREST first;
each resize step has its OWN offset — compose, don't guess once. Sources:
- https://ctftime.org/writeup/12014
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md

## W22 — Steghide passphrase leaked in JPEG header bytes

Recognition: `steghide info` suggests capacity but no password; `exiftool` clean.
Steps: (1) `xxd img.jpg | head -20` — scan first ~256 B for ASCII runs inside
JFIF/APPn/DQT gaps (e.g. passphrase sitting at offset 0x18 inside a DQT segment);
(2) try it directly in `steghide extract -p`; (3) fallback: seed stegseek wordlist
with the token.
Pitfalls: `strings` alone MISSES short runs glued to binary — hex view is
mandatory; the leak may be truncated/padded — try raw and stripped variants.
Sources:
- https://ctftime.org/writeup/13232
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md

## W23 — Corrupt-container repair ladder (magic → case → chunks → overlays)

Recognition: file won't open; `pngcheck` names VERIFY-failures per chunk.
Ladder (cheapest first): (1) patch 8-B magic (`\x89PNG\r\n\x1a\n`);
(2) re-capitalise critical chunk names (`idat→IDAT`, `iend→IEND` — lowercase =
ancillary = skipped); (3) reorder signature+IHDR+ancillary+IDATs+IEND (W23b);
(4) PCRT auto-repair for IHDR-CRC/IDAT-length cascades; (5) post-IEND trailer:
if it starts with `\x89PNG`, swap first 6 B for `7z` magic (`37 7a bc af 27 1c`).
```bash
printf '\x89PNG\r\n\x1a\n' | dd of=broken.png conv=notrunc bs=1 count=8
python3 -c "d=open('broken.png','rb').read();d=d.replace(b'idat',b'IDAT').replace(b'iend',b'IEND');open('fixed.png','wb').write(d)"
python3 PCRT/PCRT.py -i fixed.png -o pcrtd.png
```
Pitfalls: CRC-fix BEFORE length-fix (PCRT order matters); DOS→Unix `0D 0A`
mangles lengths — keep pristine copy; trailer may be a SECOND PNG, not an archive
— `file` it before magic-swapping. Sources:
- https://ctftime.org/writeup/13833
- https://github.com/DoomHackCTF/WriteUps/blob/main/mhsCTF-2022/Forensics/Blatant%20Corruption/README.md
- https://gist.github.com/Drakota/e17f4e8a1b6f30292acd442dda9d3565

## W24 — Byte-reversed bidirectional archive (mirror-ZIP/docx)

Recognition: docx/ZIP opens but holds only a decoy; file size ≫ decoy content.
Steps: (1) `unzip -l f.docx` (forward = decoy); (2) full byte-reverse → `unzip -l
mirror.zip` (central directory reads from the tail, so BOTH directions parse);
(3) extract `word/media/*` from mirror; (4) generalise: binwalk forward AND
reversed copies (works for any tail-parsed format: ZIP/RAR/PDF/tar).
```bash
python3 -c "import sys;sys.stdout.buffer.write(open('f.docx','rb').read()[::-1])" > mirror.zip
unzip -l mirror.zip && unzip mirror.zip 'word/media/*' -d mirror/
```
Pitfalls: partial reversal (per-4B word-swap) is a different trick — test full
reverse first, then word/bit variants; OpenXML `[Content_Types]` must validate in
the WINNING direction. Sources:
- https://ctftime.org/writeup/10204
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md

## W25 — MIDI note-pair byte encoding

Recognition: `.mid` plays atonal/nothing but note events strictly alternate
Note-On/Note-Off.
Steps: (1) `mido` dump pairs; (2) try `chr(on+off)`, `(on<<4)|off`, `off-on`,
`on^off` in order; (3) ASCII-check.
```python
import mido
mid=mido.MidiFile('h.mid'); ons=[e.note for e in mid.tracks[0] if e.type=='note_on']; offs=[e.note for e in mid.tracks[0] if e.type=='note_off']
for f in (lambda a,b: a+b, lambda a,b:(a<<4)|b, lambda a,b:abs(a-b), lambda a,b:a^b):
    print(''.join(chr(f(a,b)) for a,b in zip(ons,offs))[:80])
```
Pitfalls: multi-track files — test track 0 first, then merged; velocity is NOT
pitch (don't mix fields); 7-bit pitches cap sums at 254. Sources:
- https://ctftime.org/writeup/12667
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md

## W26 — Audio symbolic layers: waveform-binary + note-name FFT

Recognition: (a) Audacity zoom shows TWO alternating wave shapes (peak vs flat);
(b) tonal/melodic audio with "piano/music" hints.
Steps (a): fixed-window classify (`max>RMS-threshold` → 1/0), 8-bit groups → ASCII.
Steps (b): FFT peaks → nearest note (A4=440 table) → FIRST LETTERS spell the word.
```python
import numpy as np
from scipy.io import wavfile
rate,a=wavfile.read('c.wav'); a=a[:,0] if a.ndim>1 else a
fr=np.fft.rfftfreq(len(a),1/rate); mg=np.abs(np.fft.rfft(a))
peaks=sorted(set(round(fr[i]) for i in np.argsort(mg)[-20:] if fr[i]>20))
NOTES={'C4':261.63,'D4':293.66,'E4':329.63,'F4':349.23,'G4':392.0,'A4':440.0,'B4':493.88,'C5':523.25,'D5':587.33,'E5':659.25,'F5':698.46,'G5':783.99,'A5':880.0,'B5':987.77}
print(''.join(min(NOTES,key=lambda n:abs(NOTES[n]-f))[0] for f in peaks))
```
Pitfalls: window size must divide the symbol grid — estimate from zoom first;
note-octave errors (C4 vs C5 share letter — harmless for letter-spelling);
percussive attacks smear FFT — window the sustained part. Sources:
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
- https://github.com/ljagiello/ctf-skills/blob/main/ctf-forensics/stego-advanced.md

## W27 — Non-standard audio signalling: custom DTMF grids + missed-tone fill + dial clicks

Recognition: tones that DON'T match 697/770/852/941×1209/1336/1477/1633;
decoders (multimon-ng, web tools) return partial/garbled digits; or rhythmic
CLICKS (not tones) in a lock/dial recording.
Steps: (1) hi-res spectrogram → read the ACTUAL row/col frequency sets
(e.g. rows 301/902/1503/2104, cols 2705/3306/3907); (2) per-window dual-peak FFT
→ keypad digit; (3) digit-string → ASCII by 2/3-digit greedy split (32–126);
(4) decoder-missed extras: eyeball spectrogram gaps (4×4 keypads add A/B/C/D
column — online tools drop them); (5) clicks: COUNT per group via spectrogram,
simulate the device (dial alphabet, direction alternation, +1 detent click) over
all start positions, keep the English-readable output.
```python
# custom-grid per-window decode sketch
seg=a[i:i+W]; mg=np.abs(np.fft.rfft(seg)); fr=np.fft.rfftfreq(len(seg),1/rate)
top=sorted(fr[np.argsort(mg)[-4:]])  # two strongest ≈ row+col tones
```
Pitfalls: standard-DTMF assumption is the #1 killer — verify frequencies FIRST;
`#`/`*` may alias to hex letters (map per picture: `#`→`F` seen); click counts
include the terminal detent (+1) — model it. Sources:
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
- https://github.com/danieltaylor/ctf-writeups/blob/main/bsidessf-22/dual-type-multi-format/README.md
- https://github.com/danieltaylor/ctf-writeups/blob/main/bsidessf-22/lph/README.md

## W28 — Multi-track differential cancellation (phase-invert null)

Recognition: MKV/MP4 with 2+ near-identical audio tracks (ffprobe shows them;
labels may lie, e.g. stereo tagged "5.1"); metadata holds a DECOY string.
Steps: (1) `-map 0:a:0 / 0:a:1` extract; (2) `sox -m t0.wav "|sox t1.wav -p vol -1"`
→ diff (shared content cancels); (3) `gain -n` normalize; (4) hi-res spectrogram
of diff (`-X 2000`), bandpass 5–12 kHz; (5) narrow time-window if needed.
```bash
ffmpeg -i c.mkv -map 0:a:0 t0.flac -map 0:a:1 t1.flac
sox -m t0.wav "|sox t1.wav -p vol -1" diff.wav
sox diff.wav dn.wav gain -n -3
sox dn.wav -n spectrogram -o sp.png -X 2000 -Y 1000 -z 100 -h
```
Pitfalls: sample-rate/channel mismatch kills the null — convert identically first;
MP3-sourced tracks won't null (lossy) — demand lossless; decoy metadata is
expected, ignore until diff is clean. Sources:
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
- https://github.com/ljagiello/ctf-skills/blob/main/ctf-forensics/stego-advanced.md

## W29 — Per-channel-plane-cycled LSB (R0/G1/B2 and audio multi-bit)

Recognition: `zsteg -a` / `stegsolve` / `wavsteg` empty BUT metadata hints insist
data exists ("cycles", "modular", "armor").
Steps: (1) images: read DIFFERENT bit positions per channel
(R[0]G[1]B[2], R[1]G[2]B[0], R[2]G[0]B[1]…), MSB-first AND LSB-first;
(2) audio: `stegolsb wavsteg -r -i a.wav -o o.bin -n 2 -b 1000` (try -n 1..3);
(3) printable-ratio gate (>0.85 over 200 B) per combo, cap 72 combos.
Pitfalls: bit-ORDER (MSB vs LSB accumulation) doubles the space — test both;
audio bit-depth (8/16-bit) changes framing — check `soxi` first. Sources:
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
- https://ctftime.org/writeup/37241

## W30 — Metadata-carrier family (octal comments, Producer/Artist, XMP/iTXt)

Recognition: carrier opens clean; `exiftool` shows ODD fields (underscore-number
comments, Artist like `md5_…`, Producer strings, XMP blobs).
Steps: (1) dump ALL metadata (`exiftool -a -G`); (2) underscore-numbers with
digits 0–7 only → octal→ASCII (often → base64 → plaintext, layered);
(3) `Artist md5_<tok>` → md5-of-token as archive password; (4) `Producer/Author/
Keywords` → direct strings or passwords; (5) PNG `iTXt/tEXt`, MP3 ID3, Vorbis
comments same treatment.
```python
c="103_137_63_157_144_145"; s=''.join(chr(int(v,8)) for v in c.split('_'))
import base64; print(base64.b64decode(s).decode(errors='replace'))
```
Pitfalls: verify octal (digits ≤7) vs decimal vs hex BEFORE decoding;
`md5_` prefix means hash, not literal — compute it; XMP may be compressed.
Sources:
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
- https://ctftime.org/writeup/13833

## W31 — Invisible carriers: nested-tar whitespace + ternary zero-width + SNOW-negative

Recognition: (a) tar-in-tar chains ending in whitespace-only files/names;
(b) "empty" .txt where `stegsnow -C` returns NOTHING but `xxd` shows
`EF BB BF` / `E2 80 8B` / `20` runs.
Steps (a): recursive-extract (depth-guard 100), collect space→0/tab→1, 8-bit groups.
Steps (b): map the THREE tokens seen in hex (BOM+ZW→0, bare-ZW→0, space→1 is one
real case — DERIVE mapping per file, don't assume), 8-bit groups.
```bash
stegsnow -C file.txt            # if empty output, go to hex mapping:
python3 -c "
d=open('f.txt','rb').read().replace(b'\xef\xbb\xbf\xe2\x80\x8b',b'0').replace(b'\xe2\x80\x8b',b'0').replace(b' ',b'1')
s=d.decode();print(bytes(int(s[i:i+8],2) for i in range(0,len(s)-7,8)))"  # 0x200B=ZWSP
```
Pitfalls: editors strip trailing WS on save — work on pristine bytes; BOM-prefixed
vs bare zero-widths are DIFFERENT tokens; non-multiple-of-8 → try MSB-reverse,
then 7-bit. Sources:
- https://github.com/DoomHackCTF/WriteUps/blob/main/mhsCTF-2022/Forensics/Blank%20Slate%204/README.md
- https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/WhitePages.md
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md

## W32 — Post-SSTV image handling: decoy-aware LSB + non-QR symbologies

Recognition: SSTV decodes fine (Robot-36/Scottie/Martin-1) but image says DEADEND /
looks irrelevant, OR shows dot patterns that are NOT QR.
Steps: (1) treat ANY SSTV text-image as SUSPECT — always run `wavsteg -n 1..3`
afterwards (Melodie case: real data in 2-bit audio LSB); (2) dot-matrix output →
test DotCode readers (NOT zbarimg); (3) SSTV-image-that-is-a-barcode → Part-1
ladder, then decode.
Pitfalls: QSSTV auto-mode can mislabel Scottie↔Martin — force modes on retry;
MP3-sourced SSTV is lossy — resample/slice before declaring decoy. Sources:
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
- https://ctftime.org/writeup/32649

## W33 — Damaged-QR hard rebuild: format-bit lookup + erasure decoding + known-plaintext

Recognition: QR unscannable; finder/timing/format zones damaged (crayon, handprint,
missing alignment → "Couldn't find enough alignment patterns").
Ladder: (1) pad quiet zone ≥4 modules; upscale+threshold; invert; WeChat detector;
(2) repaint FUNCTION patterns first (finders/timing), fill destroyed modules
uniformly (erasure-style > noisy contrast); (3) partial format bits → ECC-level +
mask lookup (Q=25%, H=30%); unmask; zigzag-extract with `?` for unknowns;
(4) recover known bytes for free: mode/length header, terminator+pad bytes
(`EC 11` alternation), then `reedsolo.rs_correct_msg(msg, nsym, erase_pos=…)` —
erasures repair 2× unknown errors; (5) known-prefix (`PCTF{`-style) fixes early
data modules when decode still fails.
Pitfalls: damage past ECC budget (~1/6 area at M) = stop, don't repaint for an hour;
mode/length parse FIRST (tells you how many pad bytes you own); readers sample
module CENTRES — rounded corners don't matter.
Geometric-distortion variant: twirl/swirl filters break module geometry BEFORE
ECC matters — counter-rotate (Photopea Filter→Distort→Twirl, or PIL rotate/scale
search) until finders are square, THEN transcribe. Empty-format-info variant:
when format zones are blank AND brute-force fails, hand-search ECC-level × mask
(4 levels × 8 masks = 32 combos) with the RS-decoder as oracle — occlusion-removal
(dog/hand removal) first so the grid imports cleanly. Sources:
- https://ctftime.org/writeup/1648
- https://github.com/pwning/public-writeup/blob/master/mma2015/misc400-qr/writeup.md
- https://ctftime.org/writeup/36640
- https://ctftime.org/writeup/39908
- https://github.com/Dvd848/CTFs/blob/master/2020_Deloitte_CyberTank/QR_code.md
- https://github.com/Shotscape/ctf-writeups/blob/main/bsidestlv/the-dog-ate-my-QR!/README.md

## W34 — XQR grid-XOR multiplex (many QRs → one QR)

Recognition: image is a GRID of equal-size QR tiles (each scans to random text or
fails); title hints XOR.
Steps: (1) determine tile size incl. border (e.g. 27); (2) slice grid;
(3) `ImageChops.logical_xor` accumulate ALL tiles; (4) scan result.
```python
from PIL import Image, ImageChops
S=27; tmp=Image.new('1',(S,S),1); acc=None
im=Image.open('xqr.png')
for sy in range(0,im.size[1],S):
    for sx in range(0,im.size[0],S):
        tmp.paste(im.crop((sx,sy,sx+S,sy+S)))
        acc=tmp.copy() if acc is None else ImageChops.logical_xor(acc,tmp)
acc.save('flag.png')
```
Pitfalls: tile stride INCLUDES the quiet-zone border — off-by-one desyncs
everything (verify by re-tiling edges); binarise (`'1'` mode) before XOR;
center "keystone" tile is part of the XOR set, not the answer. Sources:
- https://github.com/danieltaylor/ctf-writeups/blob/main/byuctf-22/xqr/README.md
- https://github.com/TFNS/writeups/blob/master/2020-03-07-zer0ptsCTF/qr/README.md

## W35 — PDF advanced hiding: annotations, vector-QR, deblur, streams, selectable-redaction

Recognition: PDF renders innocuously; `strings`+`exiftool` mostly clean.
Checklist (all six seen in ONE series): (1) `pdftotext -layout` + normalize
invisible separators; (2) Link annotations: URIs with escaped braces
(`pikepdf`, `.replace(r"\{","{")`); (3) redaction boxes: REMOVE overlay object in
editor (text underneath is often SELECTABLE — try select-all first);
(4) blurred images: Wiener deconvolution (gaussian PSF σ≈3);
(5) vector QR: hundreds of tiny `re` rects → centers → grid → zbarimg;
(6) `mutool clean -d -c -m` + zlib-walk streams + post-`%%EOF` bytes +
`/Prev` incremental versions.
Pitfalls: redaction ≠ removal — always try text-select before deblur;
`re` rects need exact unit→module scaling (derive from finder squares);
Flate+ASCIIHex cascades need multi-pass decode. Sources:
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md
- https://github.com/DoomHackCTF/WriteUps/blob/main/picoCTF2022/Forensics/Redaction%20gone%20wrong/README.md
- https://ctftime.org/writeup/36632

## W36 — SVG text-element + micro-coordinate hiding

Recognition: SVG renders a bland graphic but file is large; `cat` shows
`<tspan>`/`text` runs with white fill + microscopic `font-size` (0.003px),
or `<g>` clusters with 5-decimal coordinates in a tiny range.
Steps: (1) grep text nodes (`grep -o '<tspan[^>]*>[^<]*</tspan>'`), concat in
document order; (2) micro-coords: set `viewBox` to the cluster bbox + 2 units,
width 2000 (or `scale(200) translate(-cx,-cy)`), screenshot; (3) white-on-white:
select-all / `fill` override in CSS.
Pitfalls: y-increments per tspan (~0.004) confirm line order — don't sort
alphabetically; transforms COMPOSE — apply translate BEFORE scale mentally;
renderers clip micro-drawings — force viewBox. Sources:
- https://github.com/DoomHackCTF/WriteUps/blob/main/picoCTF2022/Forensics/Enhance!/README.md
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md

## W37 — Terminal carriers: Kitty graphics, ANSI interleaves, braille layers, Alt-code symbols

Recognition: file looks like terminal art/log with `\x1b[` runs, braille block
(U+2800–28FF), or "random symbols" email (Mac `` present).
Steps: (1) Kitty: `re \x1b_G([^;]*);([^\x1b]*)\x1b\\\\` → concat b64 (m=1 chains)
→ b64dec → zlib → RGB(s,v); (2) ANSI art: strip `\x1b\[[0-9;]*[a-zA-Z]`, keep
printable-ASCII-non-space; diff raw vs `col -b` rendered to confirm;
(3) braille: decode layer first (CyberChef Braille), THEN morse, THEN octal —
order matters; (4) Alt-code symbols: anchor on known word (`ç†ƒ`=ctf), build
abc→å∫ç map by typing the alphabet with Option held (or per-symbol lookup).
Pitfalls: multi-chunk Kitty (`m=1`) MUST concat pre-decode; braille LOOKS like
one layer but chains 2–3 deep; Alt-code maps are OS/keyboard-specific (Mac vs Win
differ) — derive from the anchor, don't import a table blindly. Sources:
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md
- https://github.com/DoomHackCTF/WriteUps/blob/main/mhsCTF-2022/Crypto/What%27s%20Cooking%202/README.md
- https://github.com/danieltaylor/ctf-writeups/blob/main/byuctf-22/sticky-key/README.md

## W38 — Numeric carriers: raw-dump rebuild + frequency-rank bytes

Recognition: text file of 0–255 ints with `;`/`,` separators; or spreadsheet of
numbers (≤256 unique values).
Steps: (a) reshape by row-separator count (e.g. 960/row → 960×960 RGB via
`putdata` triplets), view, deskew in GIMP; (b) frequency-rank: `Counter` values,
`byte = rank(value)`, output is ELF/PNG.
```python
from PIL import Image
rows=[l for l in open('d.txt').read().strip(';').split(';')]
px=[tuple(map(int,r.split(',')[i:i+3])) for r in (x.strip(',').split(',') for x in rows) for i in range(0,len(r),3)]
Image.new('RGB',(960,960)).__class__; im=Image.new('RGB',(960,960)); im.putdata(px); im.save('o.png')
```
Pitfalls: row width must EXACTLY divide the stream — try separator counts first;
endianness/GL-vs-C order flips image — transpose on garbage; rank direction
(asc vs desc) both tried. Sources:
- https://github.com/DoomHackCTF/WriteUps/blob/main/mhsCTF-2022/General/Reconstruction/README.md
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md

## W39 — Perception-gap visuals: autostereogram + reflection-QR + palette-QR

Recognition: repeating-texture image ("magic eye" hints); QR visible only as a
tiny mirrored/warped reflection in a photo/video frame; GIF with square-count
frames but static pixels.
Steps: (a) autostereogram: shifted-difference `|img[x:]-img[:-x]|`, find shift by
row-autocorrelation peak (try 80–120); (b) reflection: crop best frame,
FLIP_LEFT_RIGHT (mirrors!), NEAREST-upscale, hand-transcribe 25×25 grid, render
clean modules at 20 px/cell, known-prefix-fix + ECC finish (→W33);
(c) palette-QR: `n_frames==k²` → per-frame palette[0]→bit → k×k bitmap → zbarimg.
Pitfalls: reflection MUST be mirror-flipped before transcription; version from
grid size (25=Version 2); palette-QR threshold per-GIF (sample both colors).
Sources:
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md

## W40 — Proven hard chains (validate EVERY hop)

Chain A `png→repair→palette/LSB→password→steghide`: corrupted PNG (W23) → readable
→ unused-palette or plane-5 hit yields token → ONE stegseek/steghide run.
Chain B `container→audio→spectrogram-manual→keypad→hex`: WebP/MP4 carve (CyberChef
Extract Files) → dial-tone WAV → decoder gaps filled by hand from spectrogram
(4×4 ABCD column) → `#`→`F` alias → `xxd -r -p`.
Chain C `wav→spectrogram→SSTV-image→barcode→bytes`: warble → SSTV PNG → barcode
(QR/DotCode ladder) → token; high-entropy token → `/crypto` with bytes attached.
Chain D `audio→spectrogram-half + DeepSound-half`: spectrogram gives PART 1 only;
`deepsound2john.py` + john(rockyou) unlocks part 2 — never stop at the easy half.
Rules: `file` + eyeball each hop before chaining; save renders under `./work/`;
3-strike stop; inner EXE→rev, pcap→forensics, cipher→crypto. Sources:
- https://ctftime.org/writeup/9638
- https://github.com/danieltaylor/ctf-writeups/blob/main/bsidessf-22/dual-type-multi-format/README.md
- https://ctftime.org/writeup/32649
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md
