# triage SUMMARY (quickref — 14 domains)
Sweep per file (≤120s, read-only):
- `file` / `strings|grep flag{` / `exiftool` / `xxd|head`
- ELF→`checksec` / pcap→`capinfos` / firmware→`binwalk -E`
Router:
- URL→web-ctf | ELF+socket→pwn | ELF checker→rev
- n,e,c→crypto | pcap/disk/mem→forensics | img/audio→stego
- pyjail/esolang/QR/zip→misc-pyjail | handle-only→osint
- firmware/UART→hardware | *.sol/foundry→blockchain
- apk/ipa→mobile | prompt/model→ai-ml
Output: surface.json (schema v1 —
chal_id/category/confidence/files/service/route/signals).
Parallelize across challenges. Ambiguous → exit 2 → Lead.
