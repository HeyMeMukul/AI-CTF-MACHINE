# Stego Writeup-Distilled Patterns, R2 Part 1 — Video / Audio / Document Deep Cases (W41–W55)

Same source discipline as R1. Every pattern cites 2-3 real URLs from the R2 manifest
(`knowledge/writeups_mined/stego_manifest_r2.md`). Technique-only: no flag or payload values.
These patterns EXTEND `../SKILL.md` — nothing here repeats its pipeline or playbook.

## W41 — MKV subtitle + embedded font rendering

Recognition: MKV/MP4 with subtitle track (S_TEXT/ASS or S_TEXT/UTF8) + embedded TTF
attachments; subtitle text looks like normal dialogue but renders differently.
Steps: (1) `mkvmerge -i chal.mkv` list tracks+attachments; (2) `mkvextract attachments
2:fakefont.ttf` extract suspicious font; (3) `mkvextract tracks 2:subs.ass` extract
subtitle; (4) render subtitle text with the embedded font (FontForge metrics window,
KDE Font Viewer, or mpv `--sub-ass-style-overrides=FontName=FakeFont`); (5) flag
appears in rendered glyphs, not in subtitle text bytes.
Pitfalls: default font renders as normal-looking text — the flag is in the GLYPH
MAPPING of the fake font, not the subtitle content; font may be small (64KB) — check
all attachments; mpv style override is fastest confirm.
Sources:
- https://ctftime.org/writeup/38392
- https://github.com/4n86rakam1/writeup/blob/main/IrisCTF_2024/Forensics/Not_Just_Media/index.md
- https://kerszl.github.io/hacking/walkthrough/ctf/ctf-nitectf-BuckSpeak/

## W42 — H.264 SEI user_data payload + slice_type corruption

Recognition: H.264/HEVC video that plays but has corrupted frame types; NALU analysis
shows SEI (nal_unit_type=6) with user_data_unregistered payload; slice_type modified.
Steps: (1) `ffmpeg -i video.mp4 -c:v copy -bsf:v h264_mp4toannexb raw.h264`; (2) parse
NALUs with h26x_extractor; (3) find SEI NALUs (type 6) with UUID + payload; (4) extract
payload bytes after UUID (16 bytes); (5) payload is the hidden data (often frame-type
recovery map or direct flag); (6) rewrap with `ffmpeg -i fixed.h264 -vcodec copy out.mp4`.
Pitfalls: ffmpeg re-encode destroys SEI — always `-vcodec copy`; AnnexB vs avcC
container formats need different start-code handling; payload_size > 255 uses 0xFF
continuation bytes.
Sources:
- https://joooook.github.io/2024/04/29/H264%E7%BC%96%E7%A0%81%E5%88%86%E6%9E%90%E5%8F%8A%E9%9A%90%E5%86%99%E5%AE%9E%E8%B7%B5/
- https://learn.microsoft.com/en-us/openspecs/office_protocols/ms-h264pf/3d5fb9c1-efe8-4092-a60d-5321adce9c2e

## W43 — Audio frequency-split hiding (below/above threshold)

Recognition: WAV with content only above ~1kHz (or only below); spectrogram shows
nothing in the empty band; challenge hints at "low" or "compressed" or "octave".
Steps: (1) `sox audio.wav low.wav lowpass 1000` isolate below 1kHz; (2) `sox audio.wav
high.wav highpass 1000` isolate above; (3) pitch-shift the quiet band up 1-2 octaves
(Audacity Change Pitch, or `sox` rate+resample); (4) listen or spectrogram the shifted
audio; (5) steghide extract from the isolated band if LSB; (6) keepass/flag chain.
Pitfalls: noise covers the hidden signal initially — it wanes at some point; pitch
shift direction matters (up not down); sample rate must match (44.1k vs 48k).
Sources:
- https://blog.ar-lacroix.fr/posts/2025/04/thcon-ctf-2025-foreign-interference-steganography-write-up/
- https://cryptocat.me/blog/ctf/2024/intigriti/forensics/ctf_mind_tricks/

## W44 — Echo hiding cepstrum decode

Recognition: WAV sounds normal but has subtle echo; strings/exiftool hint "cepstral
domain" or "echo"; filename may hint partition count (e.g. 256.wav).
Steps: (1) compute cepstrum: `ifft(log(abs(fft(window))))`; (2) find peaks in cepstrum
→ echo delays d0 (bit 0) and d1 (bit 1); (3) partition signal into windows (filename
hint or brute-force); (4) per window, cepstrum[d0+1] > cepstrum[d1+1] → 0, else 1;
(5) binary → ASCII.
```python
import numpy as np
from scipy.io import wavfile
sig, sr = wavfile.read('audio.wav')
W = 16800  # window size from filename hint
parts = sig[:len(sig)//W*W].reshape(-1, W)
for d0 in range(50):
    for d1 in range(d0+1, 60):
        bits = [0 if np.abs(np.fft.ifft(np.log(np.abs(np.fft.fft(p)))))[d0+1] >
                     np.abs(np.fft.ifft(np.log(np.abs(np.fft.fft(p)))))[d1+1] else 1 for p in parts]
        s = ''.join(map(str, bits))
        txt = bytes(int(s[i:i+8],2) for i in range(0,len(s)-7,8))
        if b'flag' in txt or b'CTF' in txt: print(txt)
```
Pitfalls: window size is critical — wrong size = garbage; delays are sample-level
(not ms); brute-force delay range from cepstrum peak inspection first.
Sources:
- https://blog.osiris.cyber.nyu.edu/is-there-an-echo/
- https://medium.com/@yaslr.enabled/writeup-for-is-there-an-echo-97bb701fb72b

## W45 — Phase coding stego (mid-frequency phase embedding)

Recognition: WAV sounds normal; spectrogram shows no visible text; steghide/LSB empty;
challenge hints at "phase" or academic paper reference.
Steps: (1) segment audio into frames (length = message_length × 8); (2) FFT each
segment; (3) modify phase of mid-frequency bins: phase[bin] = 0 for bit 0, π for bit 1
(or ±π/2); (4) IFFT reconstruct; (5) extraction: read phase of same bins per segment.
Pitfalls: segment boundaries must align exactly; mid-frequency range (not low, not
high) is where embedding survives; phase wrapping at ±π causes bit flips; MP3
destroys phase — demand WAV.
Sources:
- https://arxiv.org/html/2408.13277v2
- https://github.com/ktekeli/audio-steganography-algorithms

## W46 — Spread-spectrum audio (PN sequence correlation)

Recognition: WAV with noise-like content that resists spectrogram; challenge hints
at "spread spectrum" or "PN sequence" or "chip sequence".
Steps: (1) identify chip rate (samples per bit) from autocorrelation peaks; (2)
generate or extract PN sequence (may be in metadata/filename); (3) correlate received
signal with PN sequence per chip window; (4) positive correlation → 1, negative → 0;
(5) binary → ASCII.
Pitfalls: PN sequence must be known or derived (check metadata, filename, challenge
text); chip rate mismatch = all noise; processing gain means signal is below noise
floor — direct listening reveals nothing.
Sources:
- https://github.com/ktekeli/audio-steganography-algorithms
- https://github.com/ljagiello/ctf-skills/blob/main/ctf-forensics/stego-advanced.md

## W47 — Video frame blue-channel LSB (per-frame rows)

Recognition: AVI/MP4 video; challenge hints at "insignificant" + color channel name +
row number ("eighth row"); frames look normal.
Steps: (1) `ffmpeg -i video.avi -vsync 0 frames/f%04d.png`; (2) for each frame, read
blue channel LSB of first N rows only; (3) concatenate bits across frames; (4) detect
PK\x05\x06 (ZIP end) to find payload end; (5) extract ZIP.
```python
import cv2, numpy as np
cap = cv2.VideoCapture('video.avi')
data = b''
while True:
    ret, frame = cap.read()
    if not ret: break
    bits = [frame[y, :, 0] & 1 for y in range(8)]  # blue channel, first 8 rows
    data += bytes(np.packbits(bits))
    if b'PK\x05\x06' in data:
        i = data.index(b'PK\x05\x06')
        cmt_len = int.from_bytes(data[i+20:i+22], 'little')
        data = data[:i+22+cmt_len]
        break
open('out.zip', 'wb').write(data)
```
Pitfalls: channel order in cv2 is BGR (index 0 = blue); row count is per-frame not
total; ZIP end signature detection prevents over-extraction; re-encoded video
destroys LSB.
Sources:
- https://ctf.thaysan.com/ctf-and-writeups/2025-or-hackday/steganographie/well-hidden-message-insignificant-blue

## W48 — Dual video stream extraction (hidden track)

Recognition: MP4/MKV with 2+ video streams (ffprobe shows); one plays normally, other
is hidden; challenge hints at "two presences" or "shadow".
Steps: (1) `ffprobe -show_streams video.mp4` count video streams; (2) `ffmpeg -i
video.mp4 -map 0:v:1 -c copy hidden.mp4` extract second stream; (3) hidden stream may
contain subtitle text, base64 chunks, or visual flag; (4) if subtitles, extract and
concatenate; (5) if base64, assemble chunks and decode.
Pitfalls: second stream may be unplayable/corrupted — extract raw frames; subtitle
timing matters for chunk order; `-map 0:v:1` not `-map 0:2` (stream index vs track).
Sources:
- https://medium.com/@abraria747/cooked-ctf-2025-2f96e549a90f

## W49 — OOXML track changes (w:del hidden text)

Recognition: DOCX opens normally but content seems incomplete; `unzip -p file.docx
word/document.xml | grep -o 'flag{'` finds nothing; file has `<w:del>` elements.
Steps: (1) `unzip report.docx`; (2) `grep -oP '(?<=<w:delText[^>]*>)[^<]+'
word/document.xml` extract deleted text; (3) or open in Word → Review → All Markup;
(4) deleted text appears with strikethrough; (5) concat all delText in document order.
Pitfalls: delText may be split across multiple runs; w:del elements can be nested;
some delText is legitimate revision noise — flag is the coherent message.
Sources:
- https://skillbit.com/blogs/flash-ctf-paper-trail
- https://metactf.com/blog/flash-ctf-paper-trail/

## W50 — OOXML rsid attribute steganography

Recognition: DOCX with unusual editing session IDs; `unzip -p file.docx
word/document.xml | grep 'w:rsid'` shows hex patterns that look like encoded data.
Steps: (1) extract all `w:rsid` attribute values (8 hex chars each); (2) map hex
pairs to ASCII (each rsid = 1 byte); (3) concat in document order; (4) result is
hidden message.
Pitfalls: rsid values are normally random — only some carry payload; Document
Inspector does NOT detect this (passes sanitization); MS-Office re-save regenerates
rsids — work on pristine file.
Sources:
- https://doi.org/10.1007/978-3-642-23300-5_27
- https://doi.org/10.1109/elecom63163.2024.10892148

## W51 — PDF incremental update /Prev version mining

Recognition: PDF with `/Prev` in trailer (multiple versions); older versions contain
content that was "removed" in newer versions.
Steps: (1) `qpdf --qdf doc.pdf doc_qdf.pdf` decompress; (2) find all `%%EOF` offsets;
(3) truncate file after each `%%EOF` to get older versions; (4) `pdftotext` each
version; (5) diff versions to find hidden/removed content; (6) also check for
orphaned objects not referenced in latest xref.
Pitfalls: incremental updates append — older versions are prefixes; xref tables may
be linearized (PDF 1.5+) — use `qpdf --object-streams=disable`; removed content may
be in uncompressed older streams.
Sources:
- https://static.sstic.org/challenge2025/Valentino/solution_Valentino_Ricotta.pdf
- https://doi.org/10.48550/arxiv.2405.00865

## W52 — PDF stream operator float-operand LSB

Recognition: PDF renders normally; `strings` clean; decompressed streams show float
operands with unusual precision (e.g. 30.15 instead of 30.1).
Steps: (1) `qpdf --stream-data=uncompress doc.pdf doc_u.pdf`; (2) regex-extract all
float operands from stream operators (c, v, y, l, m, re, cm, i, M, w, G, g, K, k, rg,
RG, sc, SC, scn, SCN, Tc, Td, TD, Tf, TL, Tm, Ts, Tw, Tz, TJ, d0, d1); (3) for each
float, remove decimal point → integer → LSB of integer = hidden bit; (4) concat bits
→ bytes → ASCII.
Pitfalls: only 32 of 73 PDF operators accept float operands; percentage change per
operand varies (TJ needs 15%, m needs 0.05%); integer operands (Tc, Tw, Tz) are NOT
viable; this is a GATE — confirm with stats before brute.
Sources:
- https://doi.org/10.48550/arxiv.2405.00865

## W53 — PDF ASCII85 post-end-marker data

Recognition: PDF with FlateDecode+ASCII85Decode filter chain; decoded stream has
legitimate content but `~>` end marker is followed by MORE base85 data.
Steps: (1) decompress FlateDecode first; (2) find ASCII85 data between `~>` markers;
(3) decode the FIRST base85 stream (legitimate, may be decoy); (4) decode the SECOND
base85 stream after the first `~>` (hidden); (5) second stream may be another image,
hex data, or nested filter chain.
Pitfalls: PDF parsers ignore data after `~>` — this is the hiding mechanism; multiple
`~>` markers may exist (chain of hidden streams); second stream may need further
decoding (hex → another image).
Sources:
- https://static.sstic.org/challenge2025/Valentino/solution_Valentino_Ricotta.pdf

## W54 — Printer MIC yellow-dot forensics

Recognition: scanned PDF/PNG of printed document; challenge mentions printer/MIC/yellow
dots; document looks normal but has faint yellow dot pattern.
Steps: (1) `pdftoppm scan.pdf scan -png` render pages; (2) enhance yellow channel
(increase contrast, isolate yellow hue); (3) `deda_parse_print scan-01.png` detect dot
pattern; (4) read serial number, timestamp, manufacturer from decoded output; (5)
serial digits → ASCII (chr(serial)) may spell flag.
Pitfalls: scan resolution must be ≥300dpi for dot detection; multiple pages may have
different patterns — check all; Epson vs HP vs Xerox have different dot layouts;
`deda_parse_print` may need contrast enhancement first.
Sources:
- https://ctftime.org/writeup/30489
- https://github.com/Natounet/YellowDotDecode
- https://repository.root-me.org/St%C3%A9ganographie/EN%20-%20Printer-Steganography-Peter-Buck-2018.pdf

## W55 — 3D model (STL/OBJ) geometry + UV map hiding

Recognition: STL/OBJ file that renders as normal 3D object; wireframe view shows
inner structure; UV map has unusual coordinate clusters.
Steps: (1) open in Blender/3dviewer.net; (2) check wireframe for inner geometry
(Aztec code, text, QR); (3) for OBJ: inspect UV coordinates — small manual clusters
vs large auto-generated rectangles; (4) select small UV islands → reveals text on
model faces; (5) texture may be irrelevant — flag is in geometry/UV mapping; (6)
for STL: cut through solid to reveal inner code.
Pitfalls: z-fighting indicates coplanar surfaces (UV clusters); texture image may
be decoy — flag is in vertex/UV data; STL has no UV — inner geometry is the channel;
Blender wireframe mode reveals what solid rendering hides.
Sources:
- https://mariuszbartosik.com/cyberspace-ctf-2024-3d-obj-write-up/
- https://shiltemann.github.io/CTF-writeups-public/writeups/Hackvent_2019/day-02-triangulation.html
- https://ctftime.org/writeup/4750
