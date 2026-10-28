# Stego Writeup-Distilled Patterns, R2 Part 2 — Covert Channels / Physical / ML (W56–W68)

Same source discipline as R1. Every pattern cites 2-3 real URLs from the R2 manifest
(`knowledge/writeups_mined/stego_manifest_r2.md`). Technique-only: no flag or payload values.
These patterns EXTEND `../SKILL.md` — nothing here repeats its pipeline or playbook.

## W56 — Blockchain OP_RETURN memo reassembly

Recognition: challenge mentions wallet, testnet, moving money; mempool explorer shows OP_RETURN outputs; payload split across many tx.
Steps: (1) ID address type (Bech32 tb1q testnet vs mainnet); (2) walk tx history in mempool; (3) collect OP_RETURN outputs in block plus tx order; (4) strip size params, concat, base64 or gzip decode.
```bash
# mempool testnet walk, then OP_RETURN collect in order; bitcoin-abe sqlite path:
# sqlite3 abe.db "select quote(txout_scriptPubKey) from txout_detail where quote(txout_scriptPubKey) like \"X'6a%\" ORDER BY block_height,tx_pos;"
```
Pitfalls: order is block_height plus tx_pos, not arrival; zero-conf mempool tails missing from chain — fetch via listtransactions; size-prefix bytes are not payload. Sources:
- https://w0y.at/writeup/2016/10/28/ekoparty-ctf-2016-fbi-300.html
- https://medium.com/@mussharat08/while-participating-in-ritsec-ctf-2025-i-came-across-a-challenge-in-the-miscellaneous-category-c9b7bf336a02
- https://github.com/phempshall/ctf-dfir-steganography

## W57 — Blockchain value-encoding (non-OP_RETURN)

Recognition: wallet extracted but no OP_RETURN; challenge hints botnet plus backup C2; values look structured.
Steps: (1) list wallet tx values (satoshis); (2) map pairs via Akamai-style decoder (hex slices to octets, insert order); (3) OSINT the research article to confirm byte order; (4) rebuild IP.
```python
octets=[]
for txn in wallet_values:
    octets.insert(0,str(int(hex(txn)[2:4],16))); octets.insert(0,str(int(hex(txn)[4:6],16)))
print('.'.join(octets))
```
Pitfalls: hex slice positions differ per chain (P2WPKH 20B vs P2WSH 32B); dummy-address memo split uses OP_RETURN plus fake outputs — handle both. Sources:
- https://github.com/phempshall/ctf-dfir-steganography
- https://www.paulhempshall.com/blog/free-dfir-steganography-ctf-challenges/
- https://infosecwriteups.com/tcp1p-ctf-blockchain-callenge-writeup-94b7ebe1464c

## W58 — DNS label exfil with repetition sampler

Recognition: pcapng mostly DNS queries; subdomains look base64; same labels repeat; cybertalents-style target domain.
Steps: (1) `tshark -r dns.pcapng -Y dns -T fields -e dns.qry.name`; (2) per-label count, keep every 4th occurrence; (3) concat to b64, decode; (4) CyberChef from-base64 cross-check.
```bash
tshark -r dns.pcapng -Y dns -T fields -e dns.qry.name | awk -F'[.]' '/cybertalents.com/ {seen[$(NF-2)]++; if(seen[$(NF-2)]==4){printf "%s",$(NF-2); delete seen[$(NF-2)]}}'
```
Pitfalls: penultimate label only (NF-2), not full qname; 4 is per-challenge — verify by b64 alphabet validity; duplicate queries are reliability, not noise. Sources:
- https://medium.com/@panahifarah/ctf-write-up-decoding-hidden-exfiltration-via-dns-queries-creepy-dns-f30fc5067488
- https://medium.com/@joonhaobek/lnc-ctf-2025-secure-the-network-write-up-15a3f6de4f7e
- https://infosecwriteups.com/c0c0n-ctf-2025-writeup-97d6c66026f7

## W59 — DNS EDNS0 offset paging plus spider plus RCE

Recognition: custom DNS server, EDNS0 in hex, TXT answers paged, HTML with embedded domains, /proc plus Fernet hints.
Steps: (1) parse EDNS0 opcode 101 payload as ASCII offset, page 255B at a time; (2) spider TXT domains via regex, CNAME 0x0005 for realpath; (3) path-traversal read server files; (4) Fernet-decrypt subroutine, opcode 75 shell, nscd cache poison to root.
```bash
# opcode 101 with ASCII offset payload; CNAME query is 0x0005 vs TXT 0x0010
python3 -c "print(bytes.fromhex('323035'))"  # offset check
```
Pitfalls: old Wireshark misparses EDNS0 — use hex; /proc files return first 255B only; key file prefix is `.key_` via locatedb, not brute. Sources:
- https://medium.com/etticblog/hackfest24-write-up-galactica-dnsnet-bb06742fc37c
- https://ctfbase.com/writeup/20250425_umdctf_insider_info
- https://aerobytes.io/writeups/tunnel-vision-o5/

## W60 — DNS-over-HTTPS NaCl covert (HELLO-META-CHUNK)

Recognition: ARM64 Go binary, DoH endpoint, AAAA records carrying data, base32-hex labels, opcodes plus seqIDs.
Steps: (1) rev frameAsAAAARecords (16B: 1B index plus 15B data); (2) HELLO ECDH plus SecretBox session; (3) META 64B plus 16B tag, 4x56-char labels; (4) CHUNK 124B seqIDs to completion, handle early-finished.
```python
import struct
hdr=struct.pack(">HHHHHH",0,0x0100,1,0,0,0)  # QDCOUNT 1, QTYPE 28 AAAA
```
Pitfalls: base32-HEX not standard base32; server nonce byte-swap bug — mirror it; DoH content-type must be dns-message. Sources:
- https://aerobytes.io/writeups/tunnel-vision-o5/
- https://medium.com/etticblog/hackfest24-write-up-galactica-dnsnet-bb06742fc37c
- https://ctfbase.com/writeup/20250425_umdctf_insider_info

## W61 — Printer MIC yellow-dot serial decode

Recognition: scanned PDF or PNG of printed doc, printer or MIC hint, faint yellow pattern, 300dpi-plus scan.
Steps: (1) `pdftoppm scan.pdf scan -png`; (2) blue-channel enhance, `deda_parse_print` per page; (3) collect serial fields, strip leading zeros, `chr()` each; (4) concat in page order.
```bash
pdftoppm scan.pdf scan -png
for x in $(seq -w 1 34); do echo -n $(python3 -c "print(chr($(deda_parse_print scan-$x.png | grep serial | cut -d '-' -f2 | sed 's/^0*//')))"); done; echo
```
Pitfalls: need 300dpi-plus lossless; Epson vs Xerox vs HP layouts differ; timestamps may be decoy 42-pattern — serials carry payload. Sources:
- https://github.com/0xcyberpj/My-Writeup/blob/main/csawctf2021/mic-writeup.md
- https://ctftime.org/writeup/30246
- https://ctftime.org/writeup/23421

## W62 — 3D OBJ UV-map cluster reveal

Recognition: OBJ plus MTL plus texture, normal render clean, z-fighting glitches, UV map has two coordinate groups.
Steps: (1) open in 3dviewer.net or Blender; (2) inspect UV map — small manual islands vs large auto rectangles; (3) select small islands only (or delete large), reveal text faces; (4) texture is decoy — payload is geometry plus UV.
Pitfalls: z-fighting is the cue, not a bug; texture replace test confirms decoy; official solution may use different selector — both valid. Sources:
- https://github.com/OfficialCyberSpace/CSCTF-2024
- https://0xd13a.github.io/ctfs/rc3ctf2016/graphic-design/
- https://medium.com/@forwardsecrecy/hackmethod-august-2017-challenges-write-up-51a6ecbd3520

## W63 — 3D STL inner geometry plus wireframe

Recognition: STL solid view shows picture or fake text, category says rev but file is mesh, header triangle count large.
Steps: (1) `xxd challenge.stl | head` check 80B header plus count; (2) Blender solid vs wireframe toggle; (3) cut-through solid to expose inner Aztec or text; (4) clean plus B/W plus rotate before decode.
```bash
xxd challenge.stl | head -n 5
# 50B per triangle: normals plus vertices plus attr
```
Pitfalls: first visible text is often fake — always wireframe; STL has no UV — inner geometry is the channel; tiny text needs zoom, not slice. Sources:
- https://medium.com/@edemzayaniyt/mojo-jojo-ctf-reverse-engineering-underneath-challenge-a-hidden-flag-in-a-3d-model-23b4d11a0ab7
- https://blog.csdn.net/weixin_73049307/article/details/143781821
- https://github.com/OfficialCyberSpace/CSCTF-2024

## W64 — 3D G-code feed-rate hiding

Recognition: G-code or RTF with slicer meta, renders as logo, hint letter plus riddle, F-codes vary.
Steps: (1) simulate print to rule out path payload; (2) `grep -Eoh 'F[01][0-9]{2}.' gcode.txt` collect F values; (3) strip F plus dots, `awk chr`; (4) G-code viewer cross-check.
```bash
grep -Eoh 'F[01][0-9]{2}.' gcode.txt | sed 's/F//' | tr -d '.' | awk '{printf "%c",$1}'; echo
```
Pitfalls: F is feed-rate — sim-immune, not path; Slic3r header is noise; TCP-stream G-code needs ncviewer, not text grep first. Sources:
- https://medium.com/@forwardsecrecy/hackmethod-august-2017-challenges-write-up-51a6ecbd3520
- https://hackmd.io/@CHW/Skj3dx1E0
- https://blog.csdn.net/weixin_73049307/article/details/143781821

## W65 — ML-evasion adversarial stego (ASIGM)

Recognition: steganalysis mentions SRNet YeNet XuNet, WOW HILL baseline, bpp levels, MDR plus PSNR plus SSIM.
Steps: (1) pick JSMA saliency pixel-set SP raising non-stego probability; (2) embed message into subset of SP in single noise insert; (3) measure MDR plus PSNR plus SSIM vs WOW and ADS-WOW; (4) enlarge cover if SP insufficient.
Pitfalls: two-step adv-then-embed breaks message — single-process mandatory; low bpp inflates MDR — compare at same bpp; truncation needs learnable-noise layer. Sources:
- https://doi.org/10.3390/electronics14040764
- https://doi.org/10.3390/electronics14224422
- https://doi.org/10.1109/icassp49660.2025.10888052

## W66 — SRNet fine-tune for spread-spectrum (SSIS)

Recognition: SSIS detection low vs WOW HILL S-UNIWARD, SRNet residual model, payload 0.125-0.5bpp, PE plus confusion matrix.
Steps: (1) baseline SRNet on WOW HILL S-UNIWARD plus SSIS; (2) fine-tune on SSIS sets, watch 60to88 accuracy climb; (3) accept WOW PE regression as specialization cost; (4) propose multi-task to retain generality.
Pitfalls: fine-tune overfits SSIS — report other-method drop; larger payloads gain more — test all bpp; false-negative drop 217to16 is the headline, not accuracy alone. Sources:
- https://doi.org/10.3390/s24237815
- https://doi.org/10.3390/electronics14224422
- https://doi.org/10.3390/electronics14040764

## W67 — INN lost-info adversarial stego

Recognition: invertible-NN embed-extract, high visual quality but SRNet catches it, rounding truncation loss mentioned.
Steps: (1) use INN lost info plus cover gradient to craft perturb; (2) add learnable noise layer for rounding; (3) verify SRNet drop 96to51 at 0.2bpp plus extraction intact; (4) compare to TSNet StegFormer baselines.
Pitfalls: invertibility vs security tradeoff — measure both; black-box generated images need separate test; gradient-plus-lost-info must combine, not either. Sources:
- https://doi.org/10.1109/icassp49660.2025.10888052
- https://doi.org/10.3390/electronics14040764
- https://doi.org/10.3390/s24237815

## W68 — L0-constrained adversarial ML (pixel-budget)

Recognition: ResNet binary classifier, pixel-change cap (e.g. 30), server.py x-y-r-g-b protocol, sparsity plus annealing writeup.
Steps: (1) differentiable L0 approx d-square over d-square-plus-eps; (2) sparsity threshold adapt (up on adv, down on clean); (3) Linf-normalize grads, cosine annealing, clamp 0-1; (4) emit changed pixels only, count check.
```python
l0_approx=(d.square()/(d.square()+0.001)).mean(); adv_loss=(-bce_loss+l0_approx)
```
Pitfalls: pixelwise approx variants differ — test both; threshold init matters (0.3 seen); 25k steps needed — don't early-stop. Sources:
- https://segal.sh/blog/attack-of-the-worm/
- https://doi.org/10.3390/electronics14224422
- https://www.dkly.net/blog/post/ctf-cit-2025-write-up-blank-image-steganography
