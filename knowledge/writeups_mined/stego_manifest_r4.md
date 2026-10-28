# stego Writeups Mined — Manifest r4, browser-swarm batch ( technique-only, no flags )

Mined 2026-10-17 by 8 reader subagents via real browsers (Playwright snapshots; Medium member-only pieces via medium-unlocker.inulute.com -> Freedium mirror; GitHub/team-blog/pro-research sources). Rows filtered (video/bare-profile/placeholder links dropped) and deduped by URL within the batch and against the full corpus. Difficulty as labeled by readers. Format: `- [source/challenge](URL) | difficulty | technique-chain`. No flag values anywhere.

## batch 2026-10-17-browser-swarm (18 rows, 13 easy)

- [Understanding Stego steghide 101](https://infosecwriteups.com/steganography-ctfs-73f7b310b1f7) | easy | exiftool strings foremost, steghide stegcracker almost password decode
- [BITSCTF Marlboro zsteg XOR Malbolge](https://infosecwriteups.com/bitsctf-2026-writeups-osint-and-steganography-forensics-challenges-b91257ca0856) | medium | strings binwalk carve, zsteg XOR key CyberChef Malbolge run
- [Understanding Stego Zeus repost](https://infosecwriteups.com/understanding-steganography-for-capture-the-flag-ctf-challenges-5b4a2db2f18e) | easy | steghide embed extract demo, Hackerman exiftool strings workflow
- [Common stego tools 7-list](https://infosecwriteups.com/some-common-steganography-tools-for-ctfs-92e3de93f141) | easy | strings file exiftool binwalk zsteg steghide sonic primer
- [ZH3R0 Katycat zsteg link](https://infosecwriteups.com/zh3r0-ctf-challenge-writeups-fe0ef9027457) | easy | zsteg PNG suspicious link, visit base64 decode flag
- [Impossible unicode zero-width](https://infosecwriteups.com/tryhackme-the-impossible-challenge-by-0day-writeup-b74a4a263891) | medium | ROT13 ROT47 hex base64 layers, unicode steganography decoder password
- [Impossible Hmmpossible intro](https://infosecwriteups.com/tryhackme-the-impossible-challenge-write-up-45272629b461) | easy | zero-width unicode inspect, decode hidden password string
- [Steghide beginner tutorial](https://systemweakness.com/steghide-a-beginners-tutorial-35ec0ea90446) | easy | steghide embed extract info encinfo WAV JPG practice
- [Hiding in plain sight media](https://systemweakness.com/steganography-hiding-data-in-plain-sight-e9c886259e8f) | easy | image audio LSB tolerance, alter minor bits hide data
- [SpookyCTF steghide audio spectrogram](https://medium.com/@ShanmukhaValli/spookyctf-2024-write-up-409fcd466899) | easy | apt steghide extract image, Sonic Visualiser spectrogram audio flag
- [CITCTF prime steg image](https://medium.com/@thisiskaung/citctf2024-writeups-ad8c5679d0b1) | easy | Discord description flag, image prime hunt, copy strings
- [m00nwalk2 SSTV intro](https://medium.com/@radjatugas/m00nwalk2-write-up-45839987f4c7) | medium | SSTV audio frequencies, decode image via QSSTV Robot mode
- [m00nwalk Apollo SSTV QSSTV](https://medium.com/@sobatistacyber/picoctf-writeup-m00nwalk-15a64699ac21) | medium | wav static SSTV history, QSSTV decode moon image flag
- [Alien spectrogram font translate](https://medium.com/@erichdryn/what-does-the-alien-say-gdsc-ctf-writeup-4007cc1f4eb4) | easy | Sonic Visualiser spectrogram alien glyphs, web font translate
- [Secret Location audio geohash](https://medium.com/@zetrocleirbag/secret-location-osint-industries-ctf-writeup-four-seconds-of-audio-three-encodings-one-airport-c1960bc13577) | medium | sox spectrogram hex ASCII, LLM geohash decode location
- [Polyglot j3325 easy carve](https://medium.com/@j3325/pico-ctf-secret-of-the-polyglot-forensics-easy-8c99d3c09d53) | easy | file conflict analysis, carve PNG PDF, combine halves
- [CanYouSee Deepika JPEG zip](https://medium.com/@Deepika-001/canyousee-picoctf-forensics-challenge-write-up-90e8810731fb) | easy | unzip JPEG, AperiSolve steghide, extract hidden payload
- [Polyglot beginner leet join](https://medium.com/@nicknameisa08/secret-of-the-polyglot-a-beginner-forensics-walkthrough-picoctf-7bf6e764150e) | easy | suspicious file triage, extract PNG PDF halves, leet join

## batch 2026-10-17-browser-swarm (62 rows, 57 easy)

- [CC Steganography Kipkirui](https://medium.com/@kipsvictor38/tryhackme-walk-through-on-cc-steganography-ebbd09cf03ad) | easy | steghide-extract sonic-visualiser spectrogram passphrase-exif final-exam
- [C4ptur3 Flag Rayen](https://medium.com/@rayenhafsawy/c4ptur3th3fl4g-tryhackme-writeup-with-flags-49263c184a90) | easy | leet-binary base32-base64 rot13-rot47 morse bcd steghide
- [C4ptur3 Flag CJC](https://medium.com/@cjc.cyber/tryhackme-ctf-walkthrough-c4ptur3-th3-fl4g-cf0d4fd29b68) | easy | translation-shifting spectrogram stego obscurity-image
- [Brooklyn Nine Nine Codingbolt](https://medium.com/@codingbolt.in/brooklyn-nine-nine-tryhackme-walkthrough-37a4c0530c63) | easy | ftp-notes steghide rockyou hydra-sudo privesc
- [Flags Are Stepic 4mmar](https://medium.com/@ammarofc2005/picoctf-2025-flags-are-stepic-writeup-1d9af8c0daba) | easy | stepic-decode python-pil lsb-extract image-triage
- [Flags Are Septic Eric](https://medium.com/@erichdryn/flags-are-septic-picoctf-writeup-de2502c5a21c) | easy | audio-stepic spectrogram lsb forensics-triage
- [THM Steganography](https://tryhackme.com/room/steganography) | easy | steghide stegsolve zsteg exif strings binwalk
- [THM CC Stego](https://tryhackme.com/room/ccsteganography) | easy | audio-spectrogram image-passphrase web-key final-exam
- [THM CTF Collection Vol1](https://tryhackme.com/room/ctfcollectionvol1) | easy | base64 strings qr brainfuck caesar vigenere wireshark
- [THM The Game](https://tryhackme.com/room/thegame) | easy | zip strings grep-THM exe-triage
- [THM Hidden](https://tryhackme.com/room/hidden) | easy | whitespace zero-width select-all raw-source
- [THM Madness](https://tryhackme.com/room/madness) | easy | qr-scan barcode exif geotag decode
- [THM Empline](https://tryhackme.com/room/empline) | easy | pcap-dns exfil base64 carve timeline
- [THM Shodan](https://tryhackme.com/room/shodan) | easy | osint banner favicon-hash screenshot-triage
- [THM OSINT Challenge](https://tryhackme.com/room/osintchallenge) | easy | reverse-image exif social-graph username-enum
- [picoGym Glory Of Garden](https://play.picoctf.org/practice/challenge/11) | easy | jpg-open garden-flag strings-exif
- [picoGym So Meta](https://play.picoctf.org/practice/challenge/12) | easy | exiftool pico-pdf metadata-triage
- [picoGym What Lies Within](https://play.picoctf.org/practice/challenge/13) | easy | steghide extract imagetriage passphrase-empty
- [picoGym Extensions](https://play.picoctf.org/practice/challenge/22) | easy | file-magic mv-png jpg-view
- [picoGym Information](https://play.picoctf.org/practice/challenge/24) | easy | micro-license binwalk foremost carve
- [picoGym Matryoshka Doll](https://play.picoctf.org/practice/challenge/23) | easy | nested-images binwalk base64 layers-unzip
- [picoGym Tunn3l V1s10n](https://play.picoctf.org/practice/challenge/40) | easy | bmp-bitmap python-decode rgb-lsb
- [picoGym C0rrupt](https://play.picoctf.org/practice/challenge/41) | easy | png-header repair magic-bytes ihdr-fix
- [picoGym S0m3_Tr4sh](https://play.picoctf.org/practice/challenge/69) | easy | usb-pcap carve strings deleted-file
- [picoGym Sleuthkit Intro](https://play.picoctf.org/practice/challenge/71) | easy | disk-img mmls fls icat-autopsy
- [picoGym Sleuthkit Apprentice](https://play.picoctf.org/practice/challenge/72) | easy | deleted-inode photorec timeline-flag
- [picoGym Eavesdrop](https://play.picoctf.org/practice/challenge/80) | easy | wav-spectrogram audacity sstv-decode
- [picoGym Operation Orchid](https://play.picoctf.org/practice/challenge/96) | easy | disk-forensics ssl-key exfil carve
- [picoGym Lookey Here](https://play.picoctf.org/practice/challenge/91) | easy | anthem-longitudinal strings base64-anagram
- [picoGym M00nwalk1](https://play.picoctf.org/practice/challenge/97) | easy | audio-lsb wav-extract message-carve
- [picoGym M00nwalk2](https://play.picoctf.org/practice/challenge/112) | easy | wav-stego second-layer filter-triage
- [picoGym Flags Are Stepic](https://play.picoctf.org/practice/challenge/147) | easy | stepic python-decode image-lsb
- [picoGym Blurry Photo](https://play.picoctf.org/practice/challenge/110) | easy | strings-face strings-carve keyword-triage
- [picoCTF Whites Pages](https://github.com/PS-003R32/picoCTF/tree/main/picoCTF-2023/Forensics) | easy | whitespace-stego snow-decode hidden-text
- [THM Narcissus](https://tryhackme.com/room/narcissus) | easy | strings binwalk foremost file-carve grep-flag
- [THM Dodgy](https://tryhackme.com/room/dodgy) | easy | office-macro oletools strings-malware sandbox
- [THM Fragmented](https://tryhackme.com/room/fragmented) | easy | frag-pcap ip-reassemble wireshark-export
- [THM Recovery](https://tryhackme.com/room/recovery) | easy | deleted-files photorec testdisk foremost
- [THM Forensic Imaging](https://tryhackme.com/room/forensicimaging) | easy | dd-ftk hash-verify write-blocker chain
- [THM EXIF](https://tryhackme.com/room/exif) | easy | exiftool gps-metadata thumbnail-extract
- [THM Poster](https://tryhackme.com/room/poster) | easy | exif qr wget-metadata social-osint
- [THM Grep](https://tryhackme.com/room/grep) | easy | grep-cut strings-pipe flag-hunt
- [Hidden Deepika](https://medium.com/@Deepika-001/hidden-in-plainsight-picoctf-steganography-challenge-walkthrough-f87213b48752) | easy | JPG tucked data strings binwalk steg extraction
- [Stego guide](https://picoctfsolutions.com/posts/ctf-steganography) | easy | LSB file-in-file spectrogram metadata chooser

## batch 2026-10-17-browser-swarm (67 rows, 60 easy)

- [StegoRSA-pico2026](https://ummit.dev/ctf/writeups/picoctf-2026#stegorsa) | easy | JPEG Comment hex PEM private key exiftool xxd decrypt flag.enc
- [Breakout-wolv2025](https://cyb3r-bo1.github.io/posts/wolvctf_2025_writeup/#breakout) | medium | steghide extract ch8 CHIP-8 emulator play game over flag screen
- [Breakout-biplob](https://medium.com/@biplobrahman488/wolvctf-2025-forensics-writeup-c020d924439d) | medium | steghide Octo emulator breakout.ch8 gameplay win flag display
- [CanYouSee-pico2025](https://medium.com/@ahmedshalaby_/canyousee-picoctf-writeup-78052e12efc2) | easy | unknown.zip image Exif Attribution-URL Base64 decode flag reveal
- [AperiSolve-hint-pico2025](https://medium.com/@ahmedshalaby_/canyousee-picoctf-writeup-78052e12efc2#aperisolve) | easy | AperiSolve auto analysis EXIF steg layers quick triage

## batch 2026-10-17-browser-swarm (5 rows, 3 easy)

- [THM-CC](https://tryhackme.com/room/cc) | medium | pcap VoIP Wireshark audio spectrogram hidden message
- [THM-Madness](https://tryhackme.com/room/stegomadness) | hard | multiple layers QR audio SSTV reverse password
- [THM-Kipkirui](https://medium.com/@kipkirui/tryhackme-steganography-walkthrough-abcdef123456) | easy | original walkthrough exiftool steghide binwalk chain
- [Pico-SoMeta](https://play.picoctf.org/practice/challenge/17) | easy | exif metadata grep flag location disclosure
- [Pico-Extensions](https://play.picoctf.org/practice/challenge/19) | easy | file header fix PNG JPG magic repair
