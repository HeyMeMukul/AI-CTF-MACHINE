# Stego Writeup-Distilled Patterns, Part 1 — Image / Container Carriers (W1–W20)

Source discipline: every pattern cites 2–3 real URLs actually read during mining
(ctftime writeup page, primary GitHub writeup, or curated technique index whose
event/challenge attribution was verified). Technique-only: no flag or payload values.
These patterns EXTEND `../SKILL.md` — nothing here repeats its pipeline, sweep grid,
QR-ECC ladder basics, or playbook families; each entry is new substance only.

## W1 — PNG chunk-CRC-as-carrier

Recognition: `pngcheck -v` clean, `zsteg -a` incoherent, palette looks random;
`xxd` shows chunk CRC fields are all printable ASCII.
Steps: (1) parse chunks `(len,type,data,crc)`; (2) `struct.pack(">I",crc)` per chunk;
(3) concat in file order, grep printable runs.
```python
import struct
d=open('mystery.png','rb').read(); p=8; out=b''
while p<len(d):
    ln=struct.unpack('>I',d[p:p+4])[0]; out+=struct.pack('>I',struct.unpack('>I',d[p+8+ln:p+12+ln])[0]); p+=12+ln
print(out)
```
Pitfalls: only SOME chunks carry text (others random); CRC is big-endian — little-endian
unpack yields garbage; verify with `pngcheck` that CRCs are VALID (authors set them
consistent). Sources:
- https://github.com/pwning/public-writeup/blob/master/9447ctf2015/steg90-imaged/readme.md
- https://github.com/ctf-wiki/ctf-wiki/blob/master/docs/zh/docs/misc/picture/png.md

## W2 — GIF dual-channel: QR-per-frame + delay-as-morse

Recognition: animated GIF; frames decode (zbarimg) to a handful of UNIQUE QR payloads
that repeat (run-length pattern); `identify -format "%T\n"` shows exactly 2 delays.
Steps: (1) `ffmpeg -i anim.gif frame_%02d.png`; batch-decode all frames;
(2) `... | cut -d: -f2- | uniq -c` → run-lengths → tap-code/letters;
(3) delays→morse (short `.`, long `-`), restricted alphabet per QR hint;
(4) combine both halves per challenge text.
```bash
for x in $(seq 0 88); do zbarimg f_$(printf "%02d" $x).png 2>/dev/null; done | cut -d: -f2- | uniq -c
identify -format "%T\n" anim.gif | tr -d '\n' | tr -d '0' | tr '54' '-.'
```
Pitfalls: QR hint text constrains morse alphabet (don't decode full A-Z); off-by-one
frame counts from disposal methods — extract with `-vsync 0`; confirm both channels
before submitting either half. Sources:
- https://github.com/pwning/public-writeup/blob/master/9447ctf2015/steg170-gife-up-now/readme.md
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md

## W3 — Domain-format semantic codebook (game chart / config dialects)

Recognition: carrier is a game/mod config (KSH beatmap, osu!, SM, JSON level);
README points at a specific file; values look like VALID format tokens, not random.
Steps: (1) find format SPEC + its revision history; (2) diff legacy vs current token
sets (e.g. pre-v1.60 single-letter FX vs `Name;param`); (3) map file's tokens through
the LEGACY codebook; (4) read letters in file order.
```bash
fgrep fx- grv.ksh | php map_legacy.php   # legacy FX letters: S V T W U G H K I L J F P B Q X A D
```
Pitfalls: engine-version hint is load-bearing (wrong revision = wrong codebook);
parameters after `;` are noise — strip before mapping; order is file order, not sorted.
Sources:
- https://github.com/TFNS/writeups/blob/master/2021-01-16-BambooFox/ngsteg/README.md
- https://github.com/m4saka/ksh/blob/master/ksh_format.md

## W4 — Piecewise-XOR + structural-oracle key recovery

Recognition: small encrypted blob + custom encoder binary; reversing shows
`piece[i] ^= sha1(password)[i]`-style per-chunk XOR (20 chunks here, 57 B each).
Steps: (1) re-derive chunking from the binary; (2) per chunk try all 256 keys, keep
keys whose output satisfies a STRUCTURAL oracle (PNG magic → chunk tags → valid
zlib via `decompressobj`); (3) when many keys pass, add a content oracle (row
regularity regex, e.g. 8×00 + 49×(00|FF) pairs); (4) chain oracles piece by piece.
```python
import zlib
for k in range(256):
    cand=bytes(c^k for c in piece)
    try:
        d=zlib.decompressobj().decompress(cand)
        if __import__('re').match(rb'(\x00{8}((\x00\x00)|(\xff\xff)){49})+',d): print('KEY',k)
    except Exception: pass
```
Pitfalls: zlib partial-stream needs `decompressobj`, not one-shot `decompress`;
first piece usually brute-forces via magic; keep per-piece key bytes — the sha1 IS
the password hash, don't re-crack. Sources:
- https://github.com/pwning/public-writeup/blob/master/hitcon2015/forensic250-puzzleng/readme.md
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md

## W5 — Execution-trace numeric carrier (syscall numbers → ASCII)

Recognition: challenge is a noisy BINARY (junk syscalls: getpeername-unconnected,
capget-NULL, syslog-EPERM); `strace` log numbers look ASCII-ranged (50–125).
Steps: (1) `strace -o t.log ./prog`; (2) map each syscall NAME→number
(`ausyscall --dump`); skip entry/exit banner writes; (3) `chr()` the sequence.
```bash
strace -o t.log ./prog >/dev/null 2>&1
grep -o -E '^[a-z_0-9]+' t.log | while read s; do ausyscall --dump | awk -v s="$s" '$2==s{printf "%c",$1}'; done; echo
```
Pitfalls: drop the first/last `write` (banners); 32-bit vs 64-bit tables differ —
confirm arch with `file`; failing calls still count (number is what matters).
Sources:
- https://github.com/pwning/public-writeup/blob/master/9447ctf2015/steg100-binned/readme.md
- https://github.com/dawnadvent/ctf-super-hub-/blob/main/ctf-forensics/steganography.md

## W6 — SDR chirp-spread-spectrum (LoRa) decode from I/Q WAV

Recognition: stereo WAV, channels = I/Q (not L/R); sounds like noise bursts with
~1 s gaps; spectrum shows ~2 ms LINEAR frequency sweeps; SDR metadata (Airspy,
center freq, bandwidth) in strings/comment.
Steps: (1) `ffprobe` + confirm 2ch PCM; (2) complex plot `diff(angle(I+1j·Q))` to see
chirps; (3) identify protocol (LoRa: cyclically-shifted up-chirps, BW 125 kHz,
SF from chirp time `2^SF ≈ Ts·BW`); (4) decode with `gr-lora` GNURadio flowgraph
at matching commit; longest repeated payload wins.
```python
import numpy as np, scipy.io.wavfile as wf
rate,data=wf.read('sig.wav'); c=data[:,0]+1j*data[:,1]
freq=np.diff(np.angle(c)); freq[(freq>np.pi)]-=2*np.pi  # plot to confirm chirps
```
Pitfalls: NEVER treat I/Q as stereo audio (spectrogram lies); SF/BW mismatch =
no decode — estimate both from the plot first; pin gr-lora to a GNURadio-3.8-era
commit. Sources:
- https://github.com/pwning/public-writeup/blob/master/rwctf2023/misc_longrange/README.md
- https://github.com/rpp0/gr-lora

## W7 — JPEG unused quantization tables (DQT 2–15)

Recognition: JPEG renders fine; `steghide info/outguess` empty; hint words like
"insignificant"; `img.quantization` (PIL) or raw `FF DB` walk shows MORE than
tables 0–1.
Steps: (1) list all DQT ids via marker walk (PIL hides some); (2) LSB-read tables
with id ≥ 2 (64 entries each, mind 8/16-bit precision flag); (3) bytes→ASCII.
```python
d=open('c.jpg','rb').read(); p=0
while p<len(d)-1:
    if d[p]==0xFF and d[p+1]==0xDB:
        ln=int.from_bytes(d[p+2:p+4],'big'); tid=d[p+4]&0x0F; print('DQT',tid,'len',ln); p+=2+ln
    else: p+=1
```
Pitfalls: 16-bit tables have 129 B bodies, not 65 — parse precision nibble;
SOF-referenced tables (0,1) are cover, skip them; tables survive recompression,
so re-saved copies still work. Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W8 — F5 DCT-coefficient ratio gates (±1/±2, ±2/±3)

Recognition: JPEG suspect but no tool hits; need CONFIRMATION before/after
DCT-domain brute force.
Steps: (1) dump luminance AC coeffs (jpegio); (2) `r12 = #(±1)/#(±2)`:
clean ≈ 0.25–0.45, F5-modified < 0.15; (3) sparse images (>80% zero coeffs):
`r23 = #(±2)/#(±3)`, modified < 2.5; (4) combined rule
`r12<0.15 or (r12<0.25 and r23<2.5)` → keep digging, else pivot.
Pitfalls: zeros/DC excluded from counts; sparse-image false positives without the
r23 gate; this is a GATE, never a decoder — pair with F5/jsteg extractors.
Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W9 — BMP bitplane QR → steghide password chain

Recognition: BMP (lossless, exact pixels); `zsteg` bit-0-only views empty; hint is
a "gold/challenge" image.
Steps: (1) render bitplanes 0–2 for EACH of R,G,B separately (`((ch>>b)&1)*255`);
(2) eyeball/scan all 9 for QR (often bit 1, not 0); (3) `zbarimg` the hit →
passphrase; (4) `steghide extract -sf challenge.bmp -p <pw>`.
```python
from PIL import Image
im=Image.open('c.bmp'); px=__import__('numpy').array(im)
for ci,ch in enumerate('RGB'):
    for b in range(3):
        Image.fromarray((((px[:,:,ci]>>b)&1)*255).astype('uint8')).save(f'bit_{ch}_{b}.png')
```
Pitfalls: combined-RGB LSB view can HIDE a single-channel-plane QR — always split
channels; BMP alpha (XRGB) is padding, ignore; validate QR reads cleanly before
burning steghide attempts. Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/asdfgh1445/ctf-super-hub/blob/main/ctf-forensics/stego-advanced.md

## W10 — Jigsaw reassembly: edge-match + carve + `gaps` pipeline

Recognition: archive/disk image yields N equal-size tiles; assembled rumors (Santa,
puzzle, pieces); piece size possibly in EXIF.
Steps: (1) carve (`foremost -t png -i disk.img`); (2) `convert +append pieces/*.png
strip.png`; (3) `gaps --image=strip.png --size=<EXIF-size>`; (4) fallback: greedy
edge-difference placement (compat matrices, §W10-script); (5) ROT13-check the text.
```bash
foremost -t png -i disk.img -o pieces
convert +append pieces/*.png strip.png
gaps --image=strip.png --size=273
```
Pitfalls: tiles may be ROTATED (add 4-orientation compat); `gaps` needs exact piece
size — read `exiftool` per piece; reassembled text often ROT13/ciphered → crypto
handoff, not failure. Sources:
- https://ctftime.org/writeup/12662
- https://github.com/nemanja-m/gaps
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md

## W11 — QR tile reconstruction with structural anchors

Recognition: N tiles that are QR-module blocks (not picture pieces);quiet-zone edges.
Steps: (1) small grids (3×3/4×4): brute-force permutations + `zbarimg` each;
(2) larger: anchor FIRST — finder squares to 3 corners, timing stripes between;
(3) edge-bit signatures for the rest; (4) zbarimg only assembled candidates.
Pitfalls: permutation space explodes past 4×4 — anchors are mandatory, not optional;
tiles may be rotated — test 4 orientations per tile; keep quiet zone ≥4 modules on
reassembly or zbarimg fails a correct layout. Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W12 — Seed-permutation + interleaved multi-bitplane QR

Recognition: image looks like random colored noise; square/power-of-2 dims;
"seed/random/signal" hints; seed maybe in EXIF/filename/description.
Steps: (1) `convert RGB→YCbCr`, take Y; (2) `RandomState(seed).shuffle(perm)` visit
order (Fisher-Yates — numpy semantics exact); (3) interleave bitplanes
(bit0[pN],bit1[pN],bit0[pN+1]…); (4) reshape→invert→`zbarimg`.
```python
import numpy as np
from PIL import Image
Y=np.array(Image.open('c.png').convert('YCbCr').split()[0],dtype=np.uint8)
rng=np.random.RandomState(739391); perm=np.arange(Y.size); rng.shuffle(perm)
bits=np.array([ (Y.flat[perm[i//2]]>>(i%2))&1 for i in range(Y.size*2) ],dtype=np.uint8)
Image.fromarray((255*(1-bits[:Y.size].reshape(Y.shape))).astype(np.uint8)).save('qr.png')
```
Pitfalls: `RandomState` ≠ `default_rng` (different streams); try Y first, then
Cb/Cr; brute-force small seed ranges only with a zbarimg oracle per attempt.
Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W13 — EXIF thumbnail as selection mask over visible text

Recognition: photo OF text/whiteboard + JPEG with embedded thumbnail;
thumbnail is low-res version of same scene.
Steps: (1) `exiftool -b -ThumbnailImage big.jpg > thumb.jpg`; (2) OCR the main
photo to a text GRID (same line layout); (3) dark thumbnail pixels (r,g,b<100)
select `grid[y][x]` chars; (4) concat.
Pitfalls: OCR must preserve the grid (positions matter, not just words); thumbnail
aspect ≠ photo aspect — scale grid accordingly; threshold per-image (try 80–120).
Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W14 — Value-conditional LSB (near-black / color-range filter)

Recognition: `zsteg -a` empty on an image with big flat dark/light areas.
Steps: (1) filter pixels by value (`r<=1 and g<=1 and b<=1`, or near-white, or a
hue band); (2) LSB-read ONLY carriers; (3) bytes→ASCII; (4) sweep a few ranges
(near-black, near-white, per-channel-low) before quitting.
```python
from PIL import Image
im=Image.open('c.png'); bits=''
for r,g,b in im.convert('RGB').getdata():
    if r<=1 and g<=1 and b<=1: bits+=str(r&1)+str(g&1)+str(b&1)
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
```
Pitfalls: JPEG artifacts destroy exact ≤1 values — this is a PNG/BMP technique;
near-white variant uses `>=254`; combine with W29 plane cycling if still empty.
Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W15 — JPEG 8×8-block slack pixels

Recognition: JPEG with ODD dimensions (e.g. 253×195); viewers crop, decoders keep
padded blocks (→256×200).
Steps: (1) round dims UP to multiples of 8; (2) force full decode
(`magick in.jpg -define jpeg:size=WxH out.png` or raw DCT dump); (3) read padding
region as bits (black=0/white=1); common framing: magic(2B)+keylen+key+msglen+msg.
Pitfalls: any re-encode/re-save re-pads differently — work on pristine file;
viewers thumbnails lie; confirm slack region is non-random before parsing frames.
Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W16 — Stride-grid pixels via nearest-neighbor downscale

Recognition: huge image (e.g. 4096×3072), hints at interpolation/scale/resize;
zooming shows periodic dots.
Steps: (1) GCD(dims, suspected spacing) → stride (often 8/16); (2) downscale by
stride with NEAREST only (`magick -interpolate nearest-neighbor -interpolative-resize
WxH`); (3) read result; (4) if QR-shaped, zbarimg.
Pitfalls: bilinear/bicubic AVERAGES the carriers away — nearest is mandatory;
stride off-by-one yields static — verify GCD first; WebP carriers need decode to
PNG first. Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W17 — RGB-parity bitmap ((R+G+B)%2)

Recognition: normal-looking image; hints about pairs/couples/adding-colors; LSB
views noisy but parity view structured.
Steps: render `(r+g+b)%2` as 1-bit image; read text/QR.
```python
from PIL import Image
im=Image.open('c.png'); o=Image.new('1',im.size)
for x in range(im.width):
    for y in range(im.height):
        r,g,b=im.getpixel((x,y))[:3]; o.putpixel((x,y),(r+g+b)%2)
o.save('parity.png')
```
Pitfalls: JPEG noise breaks parity — PNG/BMP only; try `(r+g+b+1)%2` (inverted)
and per-pair `(r+g)%2` variants; resize/crop destroys alignment. Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W18 — Coordinate-chain (linked-list) pixel traversal

Recognition: G/B channels hold small structured integers (coordinates), R holds
printable bytes; `strings` may leak a start offset.
Steps: (1) start at (0,0) or hinted pixel; (2) loop: data=R, next=(G,B);
(3) stop at R==0 or revisit; (4) variants: data=B with (R,G)=coords, or
`next = G*256+B` for width>256.
Pitfalls: visited-set mandatory (loops); channel ROLE varies — if R-chain gibbers,
permute roles; start pixel may hide in metadata/EXIF. Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W19 — Single-bit-flip repair + decode/OCR oracle

Recognition: JPEG/PNG that ALMOST opens (decoder errors, thumbnail works);
`0xFF`-not-followed-by-`00`/marker violations pinpoint region.
Steps: (1) narrow region via markers/thumbnail (`exiftool -b -ThumbnailImage`
as validity oracle); (2) flip each bit (`8×filesize` candidates; <10 KB files
only); (3) keep decodable outputs; (4) OCR-scan survivors for text patterns.
```bash
for f in attempt_*.jpg; do tesseract "$f" stdout 2>/dev/null | grep -qiE 'flag|ctf' && echo "HIT $f"; done
```
Pitfalls: full-file 8×N brute force on big files is unbounded — REGION-limit first;
thumbnails decode independently (good oracle, sometimes contain the answer
directly — check W13). Sources:
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://github.com/Purity64/ctf_opencode_skil/blob/main/ctf-forensics/stego-image.md

## W20 — Per-frame metadata concat (GIF PLTE → ELF)

Recognition: GIF with MANY frames (count often a perfect square); frames look
identical/irrelevant; palettes differ.
Steps: (1) iterate frames, re-save each as PNG; (2) walk chunks, concat every
`PLTE` body; (3) `file` the blob (often ELF → run/strings it).
```python
import struct, io
from PIL import Image
def plte(png):
    i=8
    while i<len(png):
        ln=struct.unpack('>I',png[i:i+4])[0]
        if png[i+4:i+8]==b'PLTE': return png[i+8:i+8+ln]
        i+=12+ln
    return b''
pay=bytearray()
g=Image.open('c.gif')
for f in range(g.n_frames):
    g.seek(f); b=io.BytesIO(); g.save(b,'PNG'); pay+=plte(b.getvalue())
open('out.bin','wb').write(pay)
```
Pitfalls: disposal/combine modes can alter re-encoded palettes — use raw frame
access; `n_frames` perfect-square ⇒ also test W-"GIF-palette-QR" reading
(palette-entry→pixel mapping).
GIF local-palette hiding (SAS CTF 2025): frames after the first render RGB (no
own palette) because the payload lives in per-frame LOCAL palettes filled with
blank white — replace every frame palette with random RGB (PIL `putpalette`, or
Go `image/gif` which handles locals correctly) to reveal each part.
Sources:
- https://ctftime.org/writeup/11418
- https://github.com/not-narleeek/ctf-skills/blob/main/skills/ctf-forensics/stego-image.md
- https://ctftime.org/writeup/40254
