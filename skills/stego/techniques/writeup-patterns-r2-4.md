# Stego Writeup-Distilled Patterns, R2 Part 4 — TOP-UP Families (W81–W82)

Same source discipline as R1–R2. Every pattern cites 2-3 real URLs from the R2 manifest
(`knowledge/writeups_mined/stego_manifest_r2.md`). Technique-only: no flag or payload values.
These patterns EXTEND `../SKILL.md` — nothing here repeats its pipeline or playbook.

## W81 — GIF palette-table LSB QR rebuild

Recognition: GIF/QR renders partially drawn or blank, position markers present but body
missing; `identify` shows palette mode; pixel LSB sweeps (section B) find nothing because
the payload is NOT in the pixels — it is in the global color-table bytes.
Steps: (1) confirm palette mode (`identify -verbose` / `img.mode == "P"`); (2) dump the
256-entry table; (3) extract LSB of each R/G/B byte → bit string (768 bits); (4) size the
QR from visible markers (e.g. 29x29 = 841 cells minus 3x49 marker cells = 694 data cells);
(5) fill body cells around markers, invert if corners suggest it; (6) `zbarimg` verify.
```python
from PIL import Image
img = Image.open("chall.gif")
pal = img.getpalette()
bits = "".join(str(pal[i] & 1) for i in range(len(pal)))
print(len(bits), bits[:96])
```
Pitfalls: pixel-plane tools are blind here by construction — check the TABLE first;
inversion (black/white swap) is common — try both; 768 table bits vs 694 needed means
trailing bits are padding, not a second layer. Sources:
- https://0xdf.gitlab.io/hackvent2024/medium
- https://mobeigi.com/blog/security/capture-the-flag/hacking-lab/hackvent/2024/day-4/
- https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf

## W82 — USB-capture carve → image → QR chain

Recognition: pcap/pcapng dominated by USB (URB_BULK/URB_INTERRUPT), not TCP; challenge
mentions USB skills, storage, or adapters; `strings` shows filenames plus magic bytes.
Steps: (1) filter `usb` in Wireshark, separate BULK (file transfer) from INTERRUPT
(keystrokes — usually a decoy here); (2) carve embedded files: `foremost -i cap.pcapng`
or manual magic-byte carve (PNG `89504E47`, gzip `1F8B`); (3) run the image pipeline
on carved output — recovered PNG often IS a QR; (4) section C ladder on the QR.
```bash
tshark -r usb.pcapng -Y usb -T fields -e usb.capdata | head
foremost -i usb.pcapng -o ./work/usbcarve
zbarimg ./work/usbcarve/png/*.png
```
Pitfalls: INTERRUPT packets invite a keystroke-parse rabbit hole — check packet COUNT
first (single digits = decoy); carved archives may nest (tar→gz→file); validate each
hop (`file` + preview) before chaining. Sources:
- https://ctftime.org/writeup/39990
- https://ctftime.org/writeup/39841
- https://medium.com/@devsharmaCTF/nullcon-hackim-ctf-goa-2025-cracking-the-misc-challenges-f00ffaa7e191
