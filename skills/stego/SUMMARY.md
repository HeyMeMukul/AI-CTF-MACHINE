# stego SUMMARY (quickref)

ORDER (never reorder): `file` -> `strings|grep flag{` ->
`exiftool` -> `binwalk` -> `pngcheck/identify/soxi` -> tool-specific.

Baseline: `file; strings -n6|head; strings|grep -Eo flag\{...\}; exiftool|head;
binwalk|head; pngcheck -v; xxd head/tail`.
Audio: `soxi/ffprobe; exiftool; binwalk`.

Confirm: PNG `timeout 60 zsteg img|head`, `identify -verbose`, PIL size/mode.
JPEG `steghide info -p ''`, `stegseek --seed`, `outguess -r img /tmp/out`.
Audio `ffmpeg -i a.wav -lavfi showspectrumpic=s=1280x720 spec.png`,
`sox a.wav -n stat`, `multimon-ng -a MORSE_CW -a DTMF -t wav a.wav`.
QR `zbarimg --raw`; ZIP `7z l`; zw `grep -P '[\x{200B}...]'`.
Trailing bytes: IEND offset vs file end (`PK` = appended ZIP).
`identify -verbose` geometry/depth; `pngcheck` CRC err = IHDR trick.

Negative: zsteg garbage lines != hit (need coherent/file/zlib);
`steghide info capacity` != embedded (`--seed` decides);
spectrogram music != payload (need 5-12kHz or >18kHz edges + channel check).

Exploit ONE <=120s: (A) `zsteg -a|tee` then `zsteg -E "b1,rgb,lsb,xy">lsb.bin`;
(B) `stegseek img rockyou.txt -xf out` (retry `--seed` only);
(C) `outguess -r` / `dd skip=OFF` zip-carve / `fix_ihdr.py` height+CRC;
(D) ffmpeg spec + `multimon-ng -a DTMF -a MORSE_CW`.
Border bits: Pillow `y==0` row LSBs. FFT: numpy rfft peaks for tones.
SSTV: `sstv -d`/QSSTV if warble.
Band zoom: `showspectrumpic=s=1280x720:start=5000:stop=12000`.
Stereo: `sox a.wav left.wav remix 1` / `remix 2`, diff via `sox -m`.
Whitespace: `cat -A` (` $`/tabs); zw map 200B=0 200C=1.

Validate: sha256 src+out, `file`, grep flag-pattern, keep spec/fixed PNG,
handoff JSON (format+method+params+cmd+figure).
INNER exe->rev, pcap->forensics. No brute past 2 LSB bits / 1 rockyou run.
Technique-only, no real flags.

HARD playbook (cost order): QR-rebuild -> APNG/GIF frames -> custom LSB
sweep (ch/order/plane/stride, 72-cap) -> PoV stats gate -> video diff/XOR
-> SSTV/DeepSound -> ws/zero-width -> PDF streams -> font-glyph.
Video: `ffprobe -show_streams` FIRST; `fps=1` thin; diff frames, zsteg diffs.
QR: ECC L7/M15/Q25/H30%; ladder zbar->pyzbar->WeChat->upscale/threshold/
invert; quiet zone>=4; finder first; damage>~1/6->stop.
APNG: `%T` delays; per-frame pixel-count->chr; alpha=0 reveal; fcTL bytes.
SSTV: resample 44.1k, slice padding, Robot36 first; DeepSound:
`deepsound2john.py`+john. ws: `cat -A`, zw map 200B=0/200C=1.
PDF: `qpdf --stream-data=uncompress`, cascade-decode, `/Prev` versions,
`pdfimages`+zsteg, invisible-text via pdftotext.
Stats = confirmation only (flip>~5% keep, ~0% pivot).
Chains (validate each hop): png->ihdr->zsteg->steghide;
wav->spec->SSTV->QR; anim->diff->zip->crypto.
Failures: bad-pw->rockyou->cewl | zsteg-empty->sweep | spec-empty->4-band
sweep | QR-dead->ECC ladder | CRC-still-bad->recalc | seed-empty->outguess.
Drift: `zsteg -E` names, stegseek arg order, rockyou .gz, lavfi quoting,
Pillow LANCZOS, libzbar. Probe `--help` first.
Tiers: easy<=10m / med<=30m / hard<=90m / insane->escalate. 3 strikes->blocked.
Escalate: carve->/forensics, cipher->/crypto, exe->/rev, else operator+evidence.

W-patterns (techniques/W1..W40, post-playbook): CRC-carrier struct.pack; GIF
dual-channel (QR run-length + %T morse); KSH-legacy codebook; XOR-oracle 256/chunk;
syscall# ASCII; LoRa I/Q chirps+gr-lora; unused-DQT>=2; F5 r12<0.15; BMP planes 0-2
per-channel->steghide; gaps --size (EXIF); QR anchors->permute; RandomState-seed+Y;
thumb-dark-mask; value-filter LSB; JPEG slack (round8); NN-downscale stride;
parity bitmap; coord-chain (visited-set); bitflip+OCR (<10KB); PLTE-concat;
survivor-pixel; xxd-header passphrase; repair ladder (magic/case/PCRT/overlay);
reverse-ZIP; MIDI pairs; wave-binary/note-FFT; custom-DTMF grid+click-count;
track-null diff; R0G1B2-cycle; metadata octal/Producer; tar-WS+ternary-ZW;
SSTV-decoy+DotCode; QR-erasure(pad+reedsolo); XQR-grid-XOR; PDF 6-way; SVG
tspan/micro-viewBox; Kitty/ANSI/braille/Alt; numeric rebuild; stereogram-shift;
chains A-D hop-validated. Manifest: knowledge/writeups_mined/stego_manifest.md.
R2 W41..W80 (manifest_r2, 409 hard, 0% overlap): SEI-NALU copy + subtitle-FakeFont
mkvextract; freq-split lowpass/pitch + echo-cepstrum d0d1 + phase-midbin + PN-correlate;
blue-row per-frame + dual-stream -map; OOXML delText/rsid + PDF Prev/float/ASCII85 + MIC
deda chr(serial) + 3D UV-island/STL-wireframe/G-code-F; OP_RETURN order + value-octets;
DNS 4th-label/EDNS0-offset/DoH-AAAA; polyglot-ACK-1337 + EmbeddedFile + docx-vanish-odttf;
SNOW-COW + ultrasonic-dual + ICMP-DTMF + Knight-base58-DeepSound/morse-lower + UWSP-tiers;
ML: ASIGM-JSMA + SSIS-finetune-trade + INN-lostinfo + L0-sparsity-anneal.
