---
name: imported-stego-detection
description: Carrier-aware stego triage: metadata, appended data, LSB, palette, audio spectrogram, QR, and password-protected embeds.
category: stego
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-steganography-detection
license: Apache-2.0
ctf_domains: [stego, forensics]
status: imported
---

# Steganography detection pipeline (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-steganography-detection). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A challenge gives an image/audio/video file and the flag is hidden in pixels, metadata, audio, or an appended archive.

## Signals

- PNG/JPEG/BMP
- WAV/MP3/FLAC
- QR
- suspicious metadata
- file size mismatch

## Preconditions

- original bytes preserved
- carrier format identified

## CTF workflow

1. `file`, `exiftool`, `pngcheck`, `binwalk`, and `strings` first; record dimensions, palette, and appended bytes.
2. Try `zsteg -a image.png`, `steghide info/extract`, `stegseek`, and LSB bit-plane views; preserve the original.
3. For audio, render a spectrogram (`sox ... spectrogram`), inspect Morse/DTMF, and check metadata/cover art.
4. For QR/barcodes, `zbarimg`/`qrtool`; for archives, try the challenge password or a small wordlist.

## Falsifier

No appended data, no LSB signal, no metadata anomaly, and no audio/QR payload; the carrier may be a decoy.

## Pitfalls

- re-saving destroys LSB
- JPEG recompression
- palette vs truecolor
- password-protected embeds
- audio channel order

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-steganography-detection
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
