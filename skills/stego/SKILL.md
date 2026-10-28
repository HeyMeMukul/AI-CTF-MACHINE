---
name: stego
description: Image/audio/QR steganography via ordered pipeline zsteg steghide stegseek outguess spectrogram
category: stego
phase: 1-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Stego Skill — Steganography (Image / Audio / QR / Whitespace)

## Mental Model

> Stego hides data in noise or redundancy: LSBs, metadata,
> appended archives, spectrograms, zero-width chars.
> Pipeline order matters — cheap checks first, destructive last.

Universal pipeline ORDER (later steps destroy earlier evidence):

1. `file` 2. `strings`-grep 3. `exiftool` 4. `binwalk` (carve FIRST)
5. format-verify (`pngcheck`/`identify`/`soxi`) 6. tool-specific.

`steghide extract` before `binwalk -e` clobbers appended offsets;
`zsteg -a` before `exiftool` wastes minutes on a comment-field answer.
`strings` alone catches ~30% of easy challenges.
Budget: steps 1-5 <=3 min, tools <=10 min, spectrogram eyeball <=5 min.

## Workflow

### Phase 1 — Baseline (universal pipeline steps 1-5, read-only)

Goal: true type + any freebie flag + appended payload + validity.

Run in ORDER, stop at first flag-pattern hit (but still note rest):

```bash
file mystery.png; ls -l mystery.png
strings -n 6 mystery.png | head -n 40
strings -n 6 mystery.png | grep -E -o -m5 'flag\{[^}]*\}|FLAG\{[^}]*\}|picoCTF\{[^}]*\}|CTF\{[^}]*\}' || true
strings -n 6 mystery.png | grep -Ei -m10 'password|passphrase|steg|hide|zip|rar|key' || true
exiftool mystery.png | head -n 40
binwalk mystery.png 2>/dev/null | head -n 20
pngcheck -v mystery.png 2>&1 | head -n 20
xxd mystery.png | head -n 5; xxd mystery.png | tail -n 5
```

Audio baseline variant (`*.wav/*.mp3/*.ogg`):

```bash
file audio.wav; soxi audio.wav 2>/dev/null || ffprobe -hide_banner audio.wav 2>&1 | head -n 20
strings -n 6 audio.wav | grep -E -o -m5 'flag\{[^}]*\}' || true
exiftool audio.wav | head -n 20
binwalk audio.wav 2>/dev/null | head
```

Signals: ext `.png` but `file`=JPEG -> JPEG track; trailing `PK` ->
appended ZIP; `exiftool Comment` -> password hint; `binwalk Zip@N` ->
carve; `pngcheck CRC error` -> IHDR height trick, not LSB.

`Reasoning Checkpoint`: true format + strings hit? + exiftool hints? +
binwalk offsets? + pngcheck clean/error? Record all four; tool-specific
Phase 2 choice follows directly from them. If `file`+`strings` already
yielded flag-pattern -> still run exiftool+binwalk quickly to rule out
decoy, then jump to Phase 5.

### Phase 2 — Confirmation (format-specific probes, non-destructive)

Goal: confirm WHICH hiding family with one cheap probe each —
LSB? JPEG-container? spectrogram? QR? whitespace?

PNG probes:

```bash
timeout 60 zsteg mystery.png 2>&1 | head -n 30
identify -verbose mystery.png 2>/dev/null | grep -Ei -m10 'geometry|depth|comment' || true
```

JPEG probes:

```bash
steghide info mystery.jpg -p '' 2>&1 | head -n 10
timeout 30 stegseek --seed mystery.jpg 2>&1 | head -n 10
outguess -r mystery.jpg /tmp/out.txt 2>&1 | head -n 5
```

Audio probes (spectrogram thumbnail + channel + signalling scan):

```bash
ffmpeg -hide_banner -y -i audio.wav -lavfi showspectrumpic=s=1280x720 spec.png 2>&1 | tail -n 3
sox audio.wav -n stat 2>&1 | head -n 15
timeout 30 multimon-ng -a MORSE_CW -a DTMF -t wav audio.wav 2>&1 | head -n 20
```

QR / whitespace / appended probes:

```bash
zbarimg --raw mystery.png 2>&1 | head -n 5
python3 -c "d=open('mystery.png','rb').read(); print('IEND at', d.find(b'IEND'), 'file end', len(d), 'trailing', len(d)-d.find(b'IEND')-12)"
grep -P -o -m5 '[\x{200B}\x{200C}\x{200D}\x{FEFF}]{4,}' text.txt 2>/dev/null || true
7z l mystery.png 2>/dev/null | head -n 10
```

`Reasoning Checkpoint`: which family confirmed (zsteg hit / steghide-capable /
spectrogram shapes / QR decoded / trailing bytes>0 / zero-width found)?
Quote ONE probe output. Only confirmed family enters Phase 3; queue others.

### Phase 3 — Negative testing (kill decoys before extraction)

Goal: disprove the three standard stego traps.

1. **zsteg false positives**: noise decodes to garbage `text:` lines.
   Only coherent words / `file:` payloads / `zlib` count; require
   `zsteg -E` output to `file` clean.
2. **JPEG password hole**: `steghide info` capacity != embedded data.
   `stegseek --seed` empty -> NO rockyou burn; try outguess/DQT.
3. **Spectrogram pareidolia**: real payload = sharp edges at 5-12 kHz
   or >18 kHz. Zoom `start/stop` + `sox` channel isolate to confirm.

Negative probes:

```bash
timeout 60 zsteg -a mystery.png 2>&1 | grep -Ei -m10 'text: "[A-Za-z0-9 _{},!.-]{8,}"|file:|zlib' || echo 'NO coherent zsteg hit'
timeout 30 stegseek --seed mystery.jpg 2>&1 | tail -n 3
ffmpeg -hide_banner -y -i audio.wav -lavfi showspectrumpic=s=1280x720:start=5000:stop=12000 spec_hi.png 2>&1 | tail -n 1
sox audio.wav left.wav remix 1; sox audio.wav right.wav remix 2; ls -l left.wav right.wav
```

`Reasoning Checkpoint`: decoys excluded with evidence (incoherent /
no-seed / music-only)? Surviving payload type + exact parameters
(channel/bit/order, password-or-seed, freq band) written down? If all
denied -> check whitespace/QR/appended-ZIP branches once, then escalate.

### Phase 4 — Exploit, gated (ONE extraction step, <=120s)

Goal: run exactly ONE extraction. Timer mandatory.

Option A — PNG LSB extract (zsteg-guided, then Pillow if needed):

```bash
timeout 120 zsteg -a mystery.png 2>&1 | tee ./work/zsteg.txt
timeout 60 zsteg -E "b1,rgb,lsb,xy" mystery.png > ./work/lsb.bin 2>/dev/null; file ./work/lsb.bin
```

Option B — JPEG container crack (stegseek rockyou, fallback seed):

```bash
timeout 120 stegseek mystery.jpg /usr/share/wordlists/rockyou.txt -xf ./work/out 2>&1 | tail -n 5
# fallback ONLY as the one retry: timeout 60 stegseek --seed mystery.jpg ./work/seed_out
```

Option C — outguess / appended-ZIP / IHDR fix (pick the confirmed one):

```bash
timeout 60 outguess -r mystery.jpg ./work/outguess.txt; cat ./work/outguess.txt 2>/dev/null | head
# OR: dd if=mystery.png of=./work/hidden.zip bs=1 skip=<binwalk_offset> && unzip -l ./work/hidden.zip
# OR: python3 fix_ihdr.py mystery.png ./work/fixed.png
```

Option D — audio spectrogram + signal decode (render, then decode):

```bash
ffmpeg -hide_banner -y -i audio.wav -lavfi showspectrumpic=s=1280x720:mode=combined spec.png
timeout 60 multimon-ng -a DTMF -a MORSE_CW -t wav audio.wav > ./work/signals.txt 2>&1; head ./work/signals.txt
```

ONE option only. Save renderings (`spec*.png`) + binaries to `./work/`.

IHDR height/CRC fix (cropped-image trick): `IHDR` height cropped small,
bottom rows hidden but present. Brute height until CRC validates:

```bash
pngcheck -v mystery.png 2>&1 | grep -Ei 'CRC|height|IHDR' | head
python3 fix_ihdr.py mystery.png ./work/fixed.png  # see library
```

1px-border / coord chains: odd border in `identify`, or coord list in
`strings` -> Pillow row-LSB scan (template below, LSB-first then MSB).

`Reasoning Checkpoint`: extraction exit + `file ./work/*` + flag-pattern
grep? If hit -> Phase 5. If miss -> diagnose (wrong channel/password/
offset?) then ONE corrected retry with changed single parameter.

### Phase 5 — Validation-handoff (prove it, package it)

Goal: reproducible decode + visual proof.

1. Re-run winning command from pristine input — same bytes?
2. `file` + flag-pattern grep, quoted; keep spec/fixed PNG figures.
3. Handoff JSON.

```bash
sha256sum mystery.png audio.wav 2>/dev/null | tee results/stego_src.sha
sha256sum ./work/* 2>/dev/null | tee results/stego_out.sha
file ./work/* | tee results/stego_file.txt
grep -E -o -a -m3 'flag\{[^}]*\}|FLAG\{[^}]*\}|picoCTF\{[^}]*\}' -r ./work/ 2>/dev/null | tee results/stego_grep.txt || true
```

Handoff JSON:

```json
{"chal_id":"STEG-001","true_format":"PNG|JPEG|WAV",
 "method":"zsteg-E|stegseek-rockyou|outguess|spec+multimon|ihdr-fix|qr|zip-carve",
 "params":"b1,rgb,lsb,xy | rockyou | freq 5-12kHz",
 "artifact":"work/lsb.bin","artifact_sha256":"...",
 "command":"timeout 60 zsteg -E \"b1,rgb,lsb,xy\" mystery.png > ./work/lsb.bin",
 "figure":"work/spec.png"}
```

`Reasoning Checkpoint`: re-run identical? artifact typed + grep quoted?
command + params in JSON? If yes -> done; Lead `/validate`. If decode
partial (e.g. bit-order flipped garbage) -> note order tried, `blocked`.

## Tool Table (exact copy-paste commands)

| Task | Command |
|---|---|
| True type | `file mystery.png; file audio.wav` |
| Printable grep | `strings -n 6 mystery.png \| grep -E -o -m5 'flag\{[^}]*\}' \|\| true` |
| Metadata | `exiftool mystery.png \| head -n 40` |
| Appended scan | `binwalk mystery.png \| head -n 20` |
| PNG verify | `pngcheck -v mystery.png` |
| PNG depth | `identify -verbose mystery.png \| head -n 30` |
| zsteg quick | `timeout 60 zsteg mystery.png \| head -n 30` |
| zsteg all | `timeout 120 zsteg -a mystery.png \| tee ./work/zsteg.txt` |
| zsteg extract | `zsteg -E "b1,rgb,lsb,xy" mystery.png > ./work/lsb.bin; file ./work/lsb.bin` |
| steghide info | `steghide info mystery.jpg -p ''` |
| steghide extract | `steghide extract -sf mystery.jpg -p 'PW' -xf ./work/out` |
| stegseek crack | `stegseek mystery.jpg /usr/share/wordlists/rockyou.txt -xf ./work/out` |
| stegseek seed | `stegseek --seed mystery.jpg ./work/seed_out` |
| outguess extract | `outguess -r mystery.jpg ./work/outguess.txt` |
| JPEG carve fallback | `binwalk -e -C ./work/carve mystery.jpg` |
| ZIP list in image | `7z l mystery.png \| head; unzip -l ./work/hidden.zip` |
| ZIP carve | `dd if=mystery.png of=./work/hidden.zip bs=1 skip=<offset> && unzip -o ./work/hidden.zip -d ./work/zip` |
| Spectrogram ffmpeg | `ffmpeg -hide_banner -y -i audio.wav -lavfi showspectrumpic=s=1280x720 spec.png` |
| Spectrogram band | `ffmpeg -hide_banner -y -i audio.wav -lavfi showspectrumpic=s=1280x720:start=5000:stop=12000 spec_hi.png` |
| Spectrogram sox | `sox audio.wav -n spectrogram -o spec_sox.png` |
| Audio info | `soxi audio.wav; sox audio.wav -n stat` |
| Split channels | `sox audio.wav left.wav remix 1; sox audio.wav right.wav remix 2` |
| Subtract tracks | `sox -m left.wav -v -1 right.wav diff.wav; sox diff.wav -n spectrogram -o diff.png` |
| DTMF/Morse | `multimon-ng -a DTMF -a MORSE_CW -t wav audio.wav` |
| QR decode | `zbarimg --raw mystery.png` |
| pyzbar alt | `python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('mystery.png')))"` |
| Zero-width scan | `grep -P -o -m5 '[\x{200B}\x{200C}\x{200D}\x{FEFF}]{4,}' text.txt \|\| true` |
| FFT magnitude | `python3 fft_mag.py audio.wav ./work/fft.png` |

## Code / Payload Library

Pillow LSB template (run AFTER `zsteg -a` narrows channel/order):

```python
# lsb.py — usage: python3 lsb.py mystery.png
from PIL import Image
import sys
im = Image.open(sys.argv[1] if len(sys.argv) > 1 else "mystery.png").convert("RGB")
W, H = im.size
px = im.load()
def bits(order="xy", ch="r", bit=0):
    seq = [(x, y) for y in range(H) for x in range(W)] if order == "xy" else [(x, y) for x in range(W) for y in range(H)]
    ci = "rgb".index(ch)
    return "".join(str((px[x, y][ci] >> bit) & 1) for x, y in seq)
def to_bytes(s):
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s) - 7, 8))
for ch in ("r", "g", "b"):
    for order in ("xy", "yx"):
        raw = to_bytes(bits(order, ch, 0))[:200]
        if sum(32 <= c < 127 or c in (10, 13) for c in raw) > 100:
            print(f"[HIT] ch={ch} order={order} :: {raw[:120]!r}")
            open(f"./work/lsb_{ch}_{order}.bin", "wb").write(to_bytes(bits(order, ch, 0)))
print("[*] else: try bit=1, MSB-first (reverse each byte), or 1px-border row scan")
```

1px-border row scan add-on:

```python
from PIL import Image
im = Image.open("mystery.png").convert("RGB"); W, H = im.size; px = im.load()
for edge in ("top", "left"):
    seq = [(x, 0) for x in range(W)] if edge == "top" else [(0, y) for y in range(H)]
    s = "".join(str(px[x, y][0] & 1) for x, y in seq)
    print(edge, bytes(int(s[i:i+8], 2) for i in range(0, len(s)-7, 8))[:100])
```

IHDR height brute + CRC fix:

```python
# fix_ihdr.py — usage: python3 fix_ihdr.py in.png out.png
import struct, zlib, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())
assert d[16:20] == b"IHDR"
h0 = struct.unpack(">I", d[16+12:16+16])[0]
for h in (h0*2, 600, 800, 1000, 1200):
    c = bytearray(d)
    c[16+12:16+16] = struct.pack(">I", h)
    c[16+17:16+21] = struct.pack(">I", zlib.crc32(c[16+4:16+17]) & 0xFFFFFFFF)
    open(dst, "wb").write(c)
    print(f"wrote height={h} — open {dst}, try taller if still cropped")
    break
```

FFT magnitude (numpy — DTMF/SSTV tone check):

```python
# fft_mag.py — usage: python3 fft_mag.py audio.wav out
import sys, numpy as np, wave
fin, fout = sys.argv[1], sys.argv[2]
w = wave.open(fin); n = w.getnframes(); ch = w.getnchannels()
mono = np.frombuffer(w.readframes(n), dtype=np.int16).reshape(-1, ch).mean(axis=1)
spec = np.abs(np.fft.rfft(mono[:1<<18]))
peaks = sorted(int(p*44100/(1<<18)) for p in np.argsort(spec)[-8:])
print("top freq Hz:", peaks, "(DTMF pairs / SSTV 1-3kHz warble?)")
np.save(fout + ".npy", spec)
```

Whitespace / zero-width decode:

```bash
cat -A text.txt | head -n 10            # trailing spaces/tabs visible as ' $' / '^I'
python3 - <<'EOF'
d = open("text.txt", encoding="utf-8").read()
zw = {"\u200b": "0", "\u200c": "1", "\u200d": " ", "\ufeff": ""}
seq = "".join(zw[c] for c in d if c in zw)
print("zw bits:", seq[:160])
print(bytes(int(seq[i:i+8], 2) for i in range(0, len(seq)-7, 8))[:200])
EOF
```

SSTV note: if spectrogram shows Robot-36-style warble (~1-3 kHz lines)
or `multimon-ng` reports FSK, decode with QSSTV GUI or
`sstv -d audio.wav -o ./work/sstv.png` (pip `sstv`); visually confirm.

## Decision Tree

```text
file says?
+-- PNG/BMP? strings-hit->done; Comment-pw->steghide; Zip@N->carve+recurse;
|   CRC/height-err->IHDR fix; zsteg-hit->zsteg -E; border/coords->Pillow scan; QR->zbarimg/pyzbar
+-- JPEG? seed-hit->rockyou crack; outguess-text->done; else binwalk carve
+-- WAV/MP3? spec text/QR (5-12/>18kHz)->zoom+screenshot; tones->multimon-ng;
|   SSTV warble->sstv/QSSTV; L!=R->sox split/subtract; WAV+seed->stegseek iff seeded
+-- TXT/MD? trailing-ws (cat -A)->decode; zero-width (grep -P)->zw decode
+-- nothing? FFT peaks -> pipeline on inner files -> escalate forensics
```

## AI Automation Notes

- Log one line per pipeline step; Lead routes on it. `timeout` everything
  (`zsteg -a`, rockyou hang); ONE rockyou run, no mutations without hint.
- zsteg: fast -> `-a` -> `-E NAME` for coherent hits only; Pillow grid
  capped 6 combos (`xy/yx` x `r/g/b`) before deeper brute.
- Spectrogram: full-range, then 5-12 kHz re-render; eyeball >=1280px wide.
  `multimon-ng -a DTMF -a MORSE_CW` one call; SSTV only if warble.
- Stop: pipeline + one extraction + one retry -> `blocked` + renders.
  No >2-bit LSB brute, no ffmpeg experiments past start/stop.
- Handoff: format + method + params + command + figure. No params = irreproducible.
- Escalate: inner EXE->`rev`; inner pcap->`forensics`; QR creds->`web-ctf` note.

## Advanced / Hard-Challenge Playbook

When Phases 1-4 yield nothing coherent, hard challenges use one of these
nine families. Triage order is by cost (cheap first): QR-retry ->
frame-assembly -> custom-LSB sweep -> stats-confirmation -> video-diff ->
audio-layers -> whitespace-xformat -> PDF-streams -> font-glyph.
Log one line per family tried; stop a family after its capped probe.

### A. Video frame-diff / XOR chains

Lossy re-encodes (H.264/H.265/VP9) destroy spatial LSBs — payload lives in
(a) non-default streams, (b) one flashed frame, or (c) frame deltas. Probe
container FIRST, pixels last.

```bash
ffprobe -hide_banner -show_streams video.mp4 2>/dev/null | grep -E 'index|codec_name|codec_type|TAG:title'
ffmpeg -hide_banner -y -i video.mp4 -map 0:s -c copy ./work/subs.txt 2>&1 | tail -n 2
ffmpeg -hide_banner -y -i video.mp4 -vn ./work/audio.wav 2>&1 | tail -n 1
mkdir -p ./work/key ./work/frames ./work/thin
ffmpeg -hide_banner -y -i video.mp4 -vf "select=eq(pict_type\,I)" -vsync 0 ./work/key/k%03d.png 2>&1 | tail -n 1
ffmpeg -hide_banner -y -i video.mp4 -vf "fps=1" ./work/thin/t%03d.png 2>&1 | tail -n 1
ffmpeg -hide_banner -y -i video.mp4 -vsync 0 ./work/frames/f%05d.png 2>&1 | tail -n 1
magick ./work/frames/f00001.png ./work/frames/f00002.png -compose difference -composite ./work/diff.png
```

```python
# xordiff.py — python3 xordiff.py f00001.png f00002.png diff.png
import sys
from PIL import Image, ImageChops
d = ImageChops.difference(Image.open(sys.argv[1]).convert("RGB"), Image.open(sys.argv[2]).convert("RGB"))
print("bbox of change:", d.getbbox(), "(None = identical)"); d.save(sys.argv[3])
```

Run the image pipeline on DIFFS (`zsteg diff.png`), not just raw frames; a
one-frame flash is invisible at speed but obvious in `thin/` thumbnails. If
codec is lossy and frames are clean, pivot to container/audio — never brute
pixel LSBs on re-encoded video.

`Reasoning Checkpoint`: non-default streams listed? diff bbox quoted (or
identical)? If diffs empty and audio clean -> leave video, try audio-layers.

### B. Custom LSB schemes (channel order / bit-plane / stride)

Challenge authors beat `zsteg -a` with non-standard layouts: channel order
(RGB/BGR/alpha-only), bit-plane b1-b7 (even plane 5 seen), stride (every
Nth pixel), scan order (xy/yx/serpentine/border), MSB-first, XOR-planes.
Sweep a capped grid AFTER `zsteg -a` finds nothing.

```python
# sweep_lsb.py — capped grid: channels x orders x planes x strides x bit-order
import sys, itertools
from PIL import Image
im = Image.open(sys.argv[1] if len(sys.argv) > 1 else "mystery.png").convert("RGB")
W, H = im.size; px = im.load()
def seq(order):
    if order == "yx": return [(x, y) for x in range(W) for y in range(H)]
    if order == "serp": return [(x if y % 2 == 0 else W-1-x, y) for y in range(H) for x in range(W)]
    return [(x, y) for y in range(H) for x in range(W)]
def bits(ch, order, plane, stride, msb):
    ci = "rgb".index(ch)
    raw = "".join(str((px[x, y][ci] >> plane) & 1) for x, y in seq(order)[::stride])
    out = bytearray()
    for i in range(0, len(raw) - 7, 8):
        byte = raw[i:i+8]
        out.append(int(byte[::-1] if msb else byte, 2))
    return bytes(out)
n = 0
for ch, order, plane, stride, msb in itertools.product("rgb", ("xy", "yx"), (0, 1), (1, 2, 4), (False, True)):
    n += 1
    if n > 72: break  # HARD CAP, then stop and escalate
    raw = bits(ch, order, plane, stride, msb)[:200]
    if sum(32 <= c < 127 or c in (10, 13) for c in raw) / max(1, len(raw)) > 0.85:
        print(f"[HIT] {ch}/{order}/p{plane}/s{stride}/msb={int(msb)} :: {raw[:100]!r}")
        open(f"./work/sweep_{ch}_{order}_p{plane}_s{stride}_{int(msb)}.bin", "wb").write(bits(ch, order, plane, stride, msb))
print("[*] no HIT -> try alpha (RGBA idx 3), XOR-planes bit0(R)^bit0(B), or stats gate (F)")
```

### C. QR error-correction exploitation (damaged-QR rebuild)

QR Reed-Solomon budgets by level: L ~7%, M ~15%, Q ~25%, H ~30% of
codewords. Per block of `e` parity codewords, error decoding repairs up to
`floor(e/2)`; erasure decoding (damage location KNOWN) repairs ~2x that.
Finder/timing/format patterns carry NO parity — if the scanner cannot
orient the symbol, ECC never engages. Repair scaffolding first, data second.

Rebuild ladder (cheapest first):

```bash
zbarimg --raw damaged.png 2>&1 | head -n 5
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('damaged.png')))"
python3 -c "import cv2; d=cv2.wechat_qrcode_WeChatQRCode(); print(d.detectAndDecode(cv2.imread('damaged.png')))"
magick damaged.png -resize 400% -threshold 50% qr_big.png; zbarimg --raw qr_big.png
magick damaged.png -resize 400% -adaptive-threshold 15x15+5% qr_adapt.png; zbarimg --raw qr_adapt.png
magick damaged.png -negate qr_inv.png; zbarimg --raw qr_inv.png
```

Manual repair: (1) pad quiet zone >=4 modules; (2) repaint finder squares
crisp first; (3) fill known-destroyed modules uniformly (all-white if ink
mostly removed — erasure-style guessing beats noisy contrast); (4) unknown
level: assume M 15% — damage clearly past ~1/6 of symbol area -> escalate,
don't repaint for an hour; (5) readers sample module centres only, so
rounded corners / inter-module art are irrelevant.

`Reasoning Checkpoint`: decoding rung quoted? damage fraction vs budget
estimated? Function patterns intact? Rung 5 fails + damage > budget ->
`blocked` with crops.

### D. SSTV / DeepSound audio layers

Spectrogram shows diagonal warble ~1-3 kHz or `multimon-ng` reports FSK ->
SSTV (image-as-audio). Robot-36 (320x240, ~38 s incl. VIS header) is the
common CTF mode.

```bash
ffmpeg -hide_banner -y -i audio.wav -ac 1 -ar 44100 ./work/mono441.wav 2>&1 | tail -n 1
sstv -d ./work/mono441.wav -o ./work/sstv.png 2>&1 | tail -n 3
ffmpeg -hide_banner -y -ss 2 -i audio.wav -ac 1 -ar 44100 ./work/slice.wav 2>&1 | tail -n 1
```

SSTV failure ladder: wrong rate (48 k vs 44.1/11.025 kHz) -> resample;
padding/noise before VIS header -> slice + `-s` offset retry; MP3 lossy
damage -> demand WAV original; unknown mode -> QSSTV/Robot36 auto-detect,
file-replay 1x Loop-off, full frame. Decoded image may BE a barcode ->
section C ladder. Spectrogram text that is ciphertext (Vigenere etc.) with
key past the data chunk or in Title/Comment metadata (expect decoys) ->
`/crypto` handoff with bytes attached.

DeepSound layer: noise-like WAV resisting spectrogram/LSB -> check header
signature, extract hash, crack offline (password becomes the AES key
directly, padded/truncated to 32 B, unsalted — rockyou-class falls fast):

```bash
python3 deepsound2john.py carrier.wav > ./work/ds_hash.txt 2>&1; head ./work/ds_hash.txt
john ./work/ds_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 2>&1 | tail -n 3
```

Generic WAV LSB (no header): capped 12-config sweep (8/16-bit x channel x
LSB/MSB) + sample-LSB chi-square gate (section F) before declaring clean.

### E. Whitespace / zero-width across formats (SNOW concept)

SNOW-concept: trailing spaces/tabs (or zero-width codepoints) encode bits
invisibly — rendered text looks clean, raw bytes carry payload. Never trust
rendered view. Applies to TXT/MD, HTML source, PDF streams (decompressed),
DOCX `document.xml`, code comments.

```bash
cat -A text.txt | head -n 10
grep -P -o -m5 '[\x{200B}\x{200C}\x{200D}\x{FEFF}]{4,}' text.txt || echo NO-ZW
python3 - <<'EOF'
d = open("text.txt", encoding="utf-8").read()
sp_tab = "".join('1' if c == ' ' else '0' for line in d.splitlines() for c in line[line.rstrip(" \t"):])
zw = {"\u200b": "0", "\u200c": "1", "\u200d": " ", "\ufeff": ""}
seq = "".join(zw[c] for c in d if c in zw)
for name, s in (("ws", sp_tab), ("zw", seq.replace(" ", ""))):
    if len(s) >= 8:
        print(name, len(s), bytes(int(s[i:i+8], 2) for i in range(0, len(s)-7, 8))[:160])
EOF
qpdf doc.pdf --stream-data=uncompress doc_u.pdf && grep -a -o -m5 ' \+$' doc_u.pdf | head
unzip -p doc.docx word/document.xml | grep -o -m5 '[\x{200B}\x{200C}\x{200D}\x{FEFF}]\{4,\}' | head
```

Mappings must be VERIFIED per file (space=1/tab=0 is the common default,
variants invert); zero-width 200B=0 / 200C=1 / 200D=separator / FEFF=ignore.
Non-multiple-of-8 lengths -> try MSB-first reversal, then 7-bit ASCII.

### F. Statistical steganalysis (confirmation gates, not guessing)

Classical detectors (chi-square Pairs-of-Values, RS analysis) are
CONFIRMATION gates: they justify continuing a brute or killing an LSB
theory — never a flag source. Learned detectors (SRNet-family, 2025-2026
surveys) beat them on adaptive stego but are out of scope for timed triage.

Gate 1 — PoV equalisation (sequential LSB): embedding equalises each
`(2i, 2i+1)` histogram pair; imbalance near 0 across many pairs =>
suspicious. Random-scatter embedding weakens this test (known limit).
Gate 2 — RS intuition: natural images predict LSBs from the other 7
bit-planes; randomised LSBs break that correlation. Noisy / tiny /
JPEG-recompressed covers give weak statistics (known limit).

Decision rule: flip-rate estimate > ~5% => KEEP digging (section B sweep);
~0% => STOP LSB, pivot families (QR/frames/whitespace/PDF). Between =>
one capped sweep, then pivot.

```python
# pov_gate.py — dependency-free PoV gate (confirmation only)
import sys
from PIL import Image
h = Image.open(sys.argv[1]).convert("L").histogram()
num = den = 0
for i in range(128):
    a, b = h[2*i], h[2*i+1]
    num += abs(a - b); den += a + b
print(f"PoV imbalance: {num/den if den else 1.0:.3f} (near 0.0 = suspicious, >0.4 = likely clean)")
```

### G. APNG / GIF frame assembly

Detect: flat-looking image with anomalous size, `acTL`/`fcTL`/`fdAT`
chunks, `identify` listing many frames, animation tags in `exiftool`,
zero-delay frames.

```bash
identify -format "%f frame=%s delay=%T\n" anim.gif 2>/dev/null | head -n 20
ffmpeg -hide_banner -y -i anim.gif -vsync 0 ./work/af/f%03d.png 2>&1 | tail -n 1
gifsicle --explode anim.gif -o ./work/gf 2>/dev/null || true
```

Assembly patterns in order: (1) single odd frame (scrub thumbnails);
(2) per-frame DELAYS encode data — dump `%T`, read as morse/binary/ASCII;
(3) diff consecutive frames; (4) per-frame PIXEL-COUNT -> byte (count
target-colour pixels per frame -> `chr`); (5) alpha-hidden letters (RGB
differs but alpha=0 -> re-render ignoring alpha); (6) `fcTL` delay bytes
encode ASCII directly.

```python
# apng assembly: counts -> bytes; alpha-hidden -> revealed PNG
import glob
from PIL import Image
out = []
for f in sorted(glob.glob("./work/af/f*.png")):
    im = Image.open(f).convert("RGBA")
    out.append(sum(1 for p in im.getdata() if p[0] > 200 and p[1] < 50 and p[2] < 50))  # adjust colour
print("counts:", out[:60], "\nas-bytes:", bytes(c % 256 for c in out)[:160])
im = Image.open(sorted(glob.glob("./work/af/f*.png"))[0]).convert("RGBA")
bg = (252, 255, 164)  # sample background first; adjust
vis = Image.new("L", im.size, 0)
px, v, (W, H) = im.load(), vis.load(), im.size
for y in range(H):
    for x in range(W):
        if px[x, y][:3] != bg:
            v[x, y] = 255
vis.save("./work/alpha_revealed.png")
```

### H. PDF object-stream hiding

PDF is a container: payloads hide in metadata, unlinked objects, compressed
streams, post-`%%EOF` junk, incremental versions, invisible/overlaid text,
float-operand LSBs. Checklist order:

```bash
strings -a doc.pdf | grep -E -o -m5 'flag\{[^}]*\}|FLAG\{[^}]*\}' || true
exiftool doc.pdf | head -n 30   # Producer/Author/Keywords!
tail -c 512 doc.pdf | xxd | tail -n 8
qpdf doc.pdf --stream-data=uncompress doc_u.pdf && strings -a doc_u.pdf | grep -E -o -m5 'flag\{[^}]*\}' || true
pdfimages -all doc.pdf ./work/pdfimg 2>/dev/null; timeout 60 zsteg ./work/pdfimg-*.ppm 2>&1 | head -n 10
```

Cascaded filters (`FlateDecode`+`ASCIIHexDecode`+`DCTDecode`) defeat raw
`strings` — decompress first. Redaction boxes: remove top object in a PDF
editor. Link annotations may carry escaped-brace URIs.

```python
# pdf_streams.py — decompress stream cascades and grep payload pattern
import re, zlib, sys, binascii
d = open(sys.argv[1], "rb").read()
for i, s in enumerate(re.findall(rb"stream\r?\n(.*?)endstream", d, re.S)):
    s = s.strip()
    for _ in range(3):
        try: s = zlib.decompress(s); continue
        except Exception: pass
        try: s = binascii.unhexlify(b"".join(s.split())); continue
        except Exception: break
    if m := re.findall(rb"flag\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}", s):
        print(f"[HIT] stream {i}:", m[:3])
print("streams scanned")
```

Trailer with `/Prev` => older versions exist: truncate after each `%%EOF`
and re-inspect. Invisible text (`1 1 1 rg` white, `3 Tr` no-render) =>
`pdftotext` reveals what the render hides. Float-operand LSB hiding is
confirmed only by diffing decompressed streams, never by eyeball.

### I. Font-glyph encoding

Custom embedded fonts map codepoints to wrong glyphs: extracted text !=
rendered text. Detect by mismatch (screenshot render vs `pdftotext`); recover
by extracting the font and mapping each glyph outline back to a letter (or
OCR the rendered page). Homoglyph variant (mixed-script lookalikes):
sweep non-ASCII (`grep -P '[^\x00-\x7F]'`), normalise per-character.

```bash
pdftotext doc.pdf ./work/text.txt; head -n 10 ./work/text.txt
mutool draw -F png -o ./work/page.png doc.pdf 1 2>&1 | tail -n 1
```

`Reasoning Checkpoint` (whole playbook): families tried in cost order
with one-line evidence each? First family with positive gate identified?
If two families are positive, order them into a chain (next section)
rather than extracting both at once.

## Multi-Step Chains (abstract patterns)

Hard challenges chain 2-3 techniques; each hop's OUTPUT is the next hop's
INPUT. Validate each hop (`file` + preview) before chaining — never pipe
blindly through three decoders.

Pattern 1 — `png -> height-fix -> zsteg -> password -> steghide`: cropped
PNG + IHDR CRC error -> `fix_ihdr.py` reveals fuller image -> `zsteg -a`
coherent hit yields passphrase-shaped token -> single `stegseek` rockyou
run (confirm via `steghide info`, never capacity line alone). Extract,
`file` output, recurse pipeline on it.

Pattern 2 — `wav -> spectrogram -> SSTV -> QR`: warble bands -> SSTV image
-> barcode (sometimes non-QR symbology) -> section C ladder -> token. High
entropy / cipher-tagged token => `/crypto` handoff, not direct answer.
Eyeball EVERY intermediate (spec PNG, SSTV PNG, barcode crop) — wrong
bit-order or SSTV mode yields plausible-looking garbage.

Pattern 3 — `anim -> frame-diff -> zip-carve -> encrypted-inner`: odd frame
diff carries appended archive (`PK` tail, `7z l`) -> passworded archive =>
`/crypto`, or challenge-strings wordlist first. Inner EXE => `rev`;
capture => `forensics`.

`Reasoning Checkpoint`: each hop validated (type + preview quoted) before
next hop? Intermediate renders saved under `./work/`? Final output typed
with `file`? If any hop is unvalidated -> re-verify, do not chain further.

## Failure-Mode Catalog + Recovery

| # | Failure (detection) | Recovery (one corrected retry) |
|---|---|---|
| 1 | Wrong `steghide`/`stegseek` passphrase (`could not extract`, `wrong password`) | rockyou once, then `cewl`-generated list from challenge text/URLs/metadata; `steghide info` re-check between tries; hint-words from `strings`/`exiftool` FIRST |
| 2 | `zsteg` empty or incoherent (`NO coherent zsteg hit`) | BMP/convert path + custom sweep (section B grid, alpha, planes, stride); check palette/indexed mode; stats gate (section F) decides stop vs continue |
| 3 | Spectrogram shows nothing (wrong range) | Sweep bands: full, 1-4 kHz (SSTV), 5-12 kHz, >18 kHz; `sox` channel split + subtract; resample 44.1 kHz; slice leading padding; FFT-peak check |
| 4 | QR damaged / unscannable (all quick decoders fail) | ECC rebuild ladder (section C): upscale + threshold + invert + WeChat detector + quiet-zone pad + finder repaint; damage-vs-budget estimate caps effort |
| 5 | IHDR CRC fail AFTER height edit (still `CRC error`) | Recalc CRC32 over chunk type+data (`zlib.crc32`), verify width/height endianness (`>I`), re-run `pngcheck`; also check trailing `IEND` + appended bytes |
| 6 | `stegseek --seed` empty but JPEG still suspect | Outguess path (`outguess -r`) + DQT/quant-table look + `binwalk` carve fallback; JPEG spatial-LSB brute is last resort (DCT domain, not pixels) |
| 7 | SSTV decode garbage / `Couldn't find SSTV header` | Resample, slice offset, alternate mode (Robot36 first), file-replay 1x full duration; MP3-sourced audio -> find WAV original |

```bash
cewl http://challenge.local/ -m 3 -w ./work/cewl.txt 2>/dev/null; wc -l ./work/cewl.txt
timeout 120 stegseek mystery.jpg ./work/cewl.txt -xf ./work/out_cewl 2>&1 | tail -n 3
python3 -c "import struct,zlib; d=bytearray(open('./work/fixed.png','rb').read()); print('IHDR ok:', d[16:20]==b'IHDR')"
for band in "20 20000" "1000 4000" "5000 12000" "18000 20000"; do
  set -- $band
  ffmpeg -hide_banner -y -i audio.wav -lavfi showspectrumpic=s=1280x720:start=$1:stop=$2 ./work/spec_$1_$2.png 2>&1 | tail -n 1
done
```

Exactly ONE corrected retry per failure (single changed parameter); after
3 distinct failures -> `blocked` + renders + notes, never a retry loop.

`Reasoning Checkpoint`: failure matched to catalog number? Single changed
parameter named? Retry output quoted? Attempt count updated (3-strike
rule)?

## Version-Drift Guards

Tool flags drift across releases — probe before long runs:

```bash
zsteg --help 2>&1 | head -n 10; stegseek --help 2>&1 | grep -E 'seed|xf' | head -n 5
ls -l /usr/share/wordlists/rockyou.txt* 2>/dev/null || echo "rockyou missing?"
ffmpeg -hide_banner -h filter=showspectrumpic 2>&1 | grep -E 'start|stop|mode' | head -n 5
python3 -c "import PIL; print(PIL.__version__)"
```

Known drift: `zsteg -E` extractor name order (`b1,rgb,lsb,xy`); `stegseek`
arg order (`IMG WORDLIST -xf OUT`) vs standalone `--seed`; rockyou shipped
as `.gz` on some distros; `showspectrumpic` lavfi quoting
(`s=WxH:start=F:stop=F:mode=combined`); Pillow `ANTIALIAS` removed (use
`LANCZOS`), `getcolors()` needs `maxcolors`; pyzbar needs system libzbar;
WeChat detector needs contrib + model files. Log tool versions in hard
handoffs. Guard probe fails -> fix invocation once, never `--force` past.

## Time-Budget Tiers (with stop rules)

Pipeline ORDER is sacred at every tier: `file -> strings -> exiftool ->
binwalk -> format-verify -> tool-specific`. Skipping order burns the tier.

- EASY (<=10 min): baseline (<=3 min) + ONE probe + ONE extraction
  (<=120 s) + validate. Stop: pipeline + 1 extract + 1 retry -> `blocked`.
- MEDIUM (<=30 min): easy + negatives + ONE single-parameter retry +
  capped 6-combo Pillow grid. Stop: no coherent hit -> `blocked` + one
  playbook family queued as note.
- HARD (<=90 min): medium + playbook in cost order (C->G->B->F-gated->
  A->D->E->H->I), chains up to 3 validated hops, stats gates before
  extended brutes. Stop: 90-min cap OR 3 failed families OR 3 strikes ->
  escalate.
- INSANE: NO solo brute past hard cap. Package evidence, escalate via hard
  gate. FORBIDDEN at all tiers: >2-bit LSB brute, mutations without a hint,
  full 1-20 kHz fine sweep (use 4-band), QR repaint past ECC budget,
  ffmpeg chains past start/stop/mode.

`Reasoning Checkpoint`: tier declared at start? Elapsed vs tier cap?
Stop rule triggered (quote which)? Evidence packaged for handoff?

## Escalation Triggers

- `/forensics` FIRST (carve-first): appended offsets, unknown blobs,
  polyglots, PDF `/Prev` versions, second/AV1 video streams, pcap/disk/exe
  inners. Forensics owns bytes-before-meaning.
- `/crypto`: high-entropy / cipher-tagged payload, QR-to-ciphertext,
  encrypted spectrogram text, hint-less passworded archives. Attach exact
  bytes + suspected scheme + why.
- `/rev`: inner file is ELF/PE/bytecode (`Stegosaurus`-style embedding is
  rev in stego clothes).
- Operator (hard gate; keep solving unblocked work): tier budget spent with
  no positive gate; GUI-only tools (QSSTV/phone-app/DeepSound-Windows);
  scope ambiguity; only unbounded brute remains. QR credentials ->
  `web-ctf` note, not operator.
- Never escalate empty-handed: `./work/` renders, stats scores, tried
  families with one-line evidence, exact stop rule hit.

## Worked End-to-End Example (abstract, generic image)

Generic scenario (no real challenge data): one screen-sized PNG rendering
as an ordinary picture.

1. Baseline: `file`=PNG; `strings` no hit; `exiftool Comment` holds a short
   human phrase (possible passphrase — NOTE, don't spend yet); `binwalk`
   clean; `pngcheck` IHDR CRC error + undersized height -> height-trick
   family, not LSB.
2. Confirm + negative: `zsteg` quick shows only incoherent noise (decoy
   rejected); `identify` geometry disagrees with IHDR -> trick CONFIRMED.
3. Exploit (gated): `fix_ihdr.py` (height + CRC recalc) -> fuller image.
   Re-run pipeline on fixed file: `zsteg -a` coherent hit yields
   passphrase-shaped token -> single `stegseek` rockyou run, fallback to
   Comment-hint list (one retry only).
4. Validate: sha256 src+out, `file ./work/*`, flag-pattern grep quoted
   (payload REDACTED as `[payload-redacted]`), handoff JSON
   (`ihdr-fix+zsteg-E+stegseek-rockyou` + params + command + figures).
   Pristine re-run reproduces bytes -> `/validate`.

Lesson: every hop validated (CRC clean -> fuller image -> coherent hit ->
passphrase confirmed) before chaining; failures route to the catalog
(rows 2, 5, 1), never blind chaining.

## Writeup-Distilled Patterns (W1..W80)

Distilled from 400+ real hard stego writeups (manifest:
`knowledge/writeups_mined/stego_manifest.md`; R2 W41..W80 from
`knowledge/writeups_mined/stego_manifest_r2.md`, TOP-UP W81..W82 from
`techniques/writeup-patterns-r2-4.md`). Technique-only. Each pattern lives
in `techniques/` with signals -> steps -> commands -> pitfalls -> sources.
Triage these AFTER the playbook (A–I) when standard gates fail.

| ID | Pattern (file) | One-line trigger |
|---|---|---|
| W1 | chunk-CRC carrier (1) | chunk CRCs all printable ASCII |
| W2 | GIF QR-frames + delay-morse (1) | few unique QRs repeat + 2 delays |
| W3 | domain-format codebook, KSH (1) | game-chart file + version hint |
| W4 | piecewise-XOR + oracle brute force (1) | encoder binary + chunked XOR |
| W5 | syscall-number ASCII (1) | junk-syscall binary + ASCII-range numbers |
| W6 | SDR LoRa chirp decode (1) | I/Q WAV + 2 ms linear sweeps |
| W7 | JPEG unused DQT tables (1) | >2 DQT + "insignificant" hint |
| W8 | F5 DCT ratio gates (1) | confirm DCT stego before brute force |
| W9 | BMP bitplane QR -> steghide (1) | BMP + bit-0 views empty |
| W10 | jigsaw edge-match + gaps (1) | N equal tiles / carved pieces |
| W11 | QR tiles + finder anchors (1) | QR-module blocks, not picture |
| W12 | seed-permutation multi-bitplane QR (1) | noise image + "seed" hint |
| W13 | EXIF thumbnail mask (1) | photo OF text + embedded thumb |
| W14 | value-conditional LSB (1) | flat dark/light areas, zsteg empty |
| W15 | JPEG 8x8 slack pixels (1) | odd dims, viewers crop |
| W16 | stride-grid NN-downscale (1) | huge image + resize hints |
| W17 | RGB-parity bitmap (1) | "pairs/adding colors" hint |
| W18 | coordinate-chain traversal (1) | small ints in G/B channels |
| W19 | single-bit-flip + OCR oracle (1) | almost-opens file, <10 KB |
| W20 | per-frame PLTE concat (1) | square-count GIF frames |
| W21 | nested-resize survivor QR (2) | QR changes after downscales |
| W22 | header-passphrase JPEG (2) | steghide-capable, exiftool clean |
| W23 | repair ladder + overlays (2) | pngcheck names chunk failures |
| W24 | byte-reversed mirror-ZIP (2) | decoy-only docx, oversized |
| W25 | MIDI note-pair bytes (2) | atonal MID, strict on/off pairs |
| W26 | waveform-binary + note-FFT (2) | two wave shapes / melodic audio |
| W27 | custom DTMF + missed tones + clicks (2) | non-standard freqs / dial recording |
| W28 | multi-track cancellation (2) | 2 near-identical audio tracks |
| W29 | per-channel-plane-cycled LSB (2) | "cycles/modular" hint, tools empty |
| W30 | metadata carriers (2) | octal comments / Artist-md5 / Producer |
| W31 | tar-whitespace + ternary-ZW (2) | tar chains / stegsnow-negative empty txt |
| W32 | SSTV decoy + DotCode (2) | SSTV says DEADEND / dot matrix |
| W33 | QR erasure + function-pattern (2) | finder/format damage, erasure math |
| W34 | XQR grid-XOR multiplex (2) | QR-tile grid + XOR hint |
| W35 | PDF 6-way + redaction (2) | annotations / `re` rects / blur |
| W36 | SVG tspan + micro-coords (2) | fat SVG, white/micro text nodes |
| W37 | terminal carriers (2) | ESC_G / ANSI art / braille / Alt-symbols |
| W38 | numeric carriers (2) | int dumps / spreadsheets of numbers |
| W39 | perception-gap visuals (2) | repeating texture / reflection / GIF-square |
| W40 | proven hard chains A–D (2) | multi-hop outputs (validate each hop) |
| W41 | MKV subtitle + embedded font (r2-1) | subtitle track + TTF attachments |
| W42 | H.264 SEI payload + slice fix (r2-1) | SEI type-6 + frame-type corruption |
| W43 | audio frequency-split hide (r2-1) | content only above/below 1kHz |
| W44 | echo hiding cepstrum (r2-1) | normal WAV + cepstral hint + 256 name |
| W45 | phase coding stego (r2-1) | clean spec + phase hint, LSB empty |
| W46 | spread-spectrum PN correlate (r2-1) | noise WAV + PN/chip hint |
| W47 | video blue-channel LSB rows (r2-1) | AVI + insignificant + row number |
| W48 | dual video stream extract (r2-1) | 2+ video streams, one hidden |
| W49 | OOXML track-changes delText (r2-1) | docx incomplete + del elements |
| W50 | OOXML rsid attribute code (r2-1) | odd rsid hex patterns |
| W51 | PDF incremental Prev mining (r2-1) | trailer /Prev + multiple %%EOF |
| W52 | PDF float-operand LSB (r2-1) | unusual float precision in streams |
| W53 | PDF ASCII85 post-marker data (r2-1) | Flate+ASCII85 + data after ~> |
| W54 | printer MIC yellow dots (r2-1) | scan + printer/MIC hint |
| W55 | 3D STL/OBJ geometry + UV (r2-1) | normal render + wireframe inner |
| W56 | blockchain OP_RETURN reassembly (r2-2) | wallet + testnet + OP_RETURN outputs |
| W57 | blockchain value-encoding (r2-2) | wallet, no OP_RETURN, C2 hint |
| W58 | DNS label exfil sampler (r2-2) | pcap DNS + base64 subdomains |
| W59 | DNS EDNS0 paging + RCE (r2-2) | custom DNS + EDNS0 hex |
| W60 | DoH NaCl covert channel (r2-2) | ARM64 Go + DoH + AAAA records |
| W61 | MIC serial chr decode (r2-2) | scan + deda pattern-4 serials |
| W62 | OBJ UV-cluster reveal (r2-2) | OBJ + z-fighting + UV groups |
| W63 | STL inner wireframe text (r2-2) | STL + solid fake text |
| W64 | G-code F-rate hiding (r2-2) | G-code + slicer + F variance |
| W65 | ASIGM adversarial stego (r2-2) | SRNet + WOW + bpp + MDR |
| W66 | SRNet SSIS fine-tune (r2-2) | SSIS low detect + SRNet |
| W67 | INN lost-info perturb (r2-2) | INN embed + SRNet catch |
| W68 | L0 pixel-budget attack (r2-2) | ResNet + pixel cap + server.py |
| W69 | PDF polyglot + ACK + versions (r2-3) | data file + Ruby + blank PDF |
| W70 | PDF EmbeddedFile + carve (r2-3) | EmbeddedFile + ObjStm + fake strings |
| W71 | PDF incremental phishing reuse (r2-3) | 5x %%EOF + same object URIs |
| W72 | OOXML off-page + brainfuck (r2-3) | docx sparse + negative coords |
| W73 | OOXML VBA-xor blackout (r2-3) | docm blackout + vbaProject.bin |
| W74 | OOXML media steghide chain (r2-3) | docx media images, exiftool clean |
| W75 | OOXML vanish + odttf fonts (r2-3) | docx + fontTable + vanish flags |
| W76 | SNOW + COW esolang chain (r2-3) | poem WS + SNOW caps + moo file |
| W77 | ultrasonic dual-morse (r2-3) | audible morse + retune hint |
| W78 | ICMP covert + DTMF hop (r2-3) | pcap TLS noise + few ICMP |
| W79 | KnightCTF multi-hop chains (r2-3) | tar clue + base58 + morse tip |
| W80 | classroom ladder + alien cipher (r2-3) | repo tiers + SOS + JPG cipher |
| W81 | GIF palette-table LSB QR rebuild (r2-4) | palette-mode GIF, pixel LSB empty |
| W82 | USB-capture carve to QR chain (r2-4) | USB-protocol pcap + magic bytes |

`Reasoning Checkpoint`: playbook families A–I exhausted with one-line evidence
each? First W-pattern whose trigger matches quoted? Pattern file read (not just
index)? If W-extract yields partial (bit-order garbage) -> note order tried,
single-parameter retry, then `blocked`.

## EASY-FIRST ladder (2026 training refresh — ordered pipeline that TERMINATES, ≤20 min)
1. Every file: `file; exiftool -a -u -g1; exiftool -b -ThumbnailImage f > thumb.jpg; strings -n8; binwalk -e`.
2. PNG/BMP: `zsteg -a` (never on JPEG); broken PNG → `pngcheck -vtp7`, appended data after IEND, alpha/MSB planes, dimension-vs-CRC brute.
3. JPEG: `steghide info -p ''` → extract; then `stegseek rockyou`; then `outguess -r`; try filename/challenge-name as password BEFORE rockyou.
4. Audio: spectrogram FIRST (`sox f.wav -n spectrogram`; check >20kHz), then `steghide -p ''`, then `wavsteg -b 1000 -n 1..2` (skip header, isolate channels).
5. `zbarimg --raw` every image (QR in spectrograms too); text → `cat -A` + `xxd | grep 200b/200c/200d/feff` (work raw bytes, never re-save).

## R4 field patterns (browser-swarm 2026 — from 67 new writeups)
- CHIP-8 ROM cover: `steghide extract` yields `.ch8` → Octo emulator, play to game-over screen for the flag.
- stepic/openstego: `exiftool` says nothing, `steghide` fails → `stepic -d` / `openstego --extract` before zsteg.
- Password reuse: challenge/filename as steghide password BEFORE rockyou; `pAzzword`-style metadata passwords in EXIF comments.
- Polyglot dd-split: contradictory `file` output → `dd skip` past IEND → view halves separately, leet-join.

---

*Technique-only reference. No real flags contained. Tool syntax verified
 2026-10 against zsteg/steghide/stegseek/outguess docs, ffmpeg
 showspectrumpic filter reference, sox/multimon-ng/zbarimg/pngcheck manuals,
 plus 2025-2026 steganalysis surveys (chi-square/RS confirmation role),
 QR ECC level budgets (L/M/Q/H), SSTV Robot-36 framing, DeepSound header
 tooling, PDF stream-operator hiding research, and APNG frame-assembly
 challenge analyses.*
