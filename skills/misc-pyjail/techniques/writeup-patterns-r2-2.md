# Misc-Pyjail Writeup-Distilled Patterns R2, Part 2 — Constraint Categories (W52–W66)

Continues Part 1 (W37–W51). Same discipline: signals → steps → payloads →
pitfalls → 2–3 R2-manifest URLs. Technique-only, no flag values.

## W52 — PHP eval-sandbox + disable_functions chains

Signals: `eval($input)` after `htmlentities+addslashes+addcslashes`; giant
`disable_functions` from `phpinfo`; `open_basedir`; `mail()`/`putenv` still alive;
`create_function` with commented-out call.
Steps: (1) quoteless/digitless synthesis: `chr(count(array(null,…)))` per char +
`implode(file(...))` — payload contains no slashable runes so filters pass it
through byte-identical; (2) `create_function` breakout: close the generated
`}` early, XOR-string your function names (`'WUDU^F'^'000000'` = `getenv`);
(3) disable_functions: `putenv(LD_PRELOAD=.so)+mail()` (sendmail loads your
constructor), or `LD_PRELOAD` via `proc_open` env arg, or procfs PLT rewrite;
`open_basedir`: curl `file://` wrapper, `CURLFile`/filter-chain to CN-EXT;
(4) read with `highlight_file(glob("fl*txt")[0])` when `.`/`a` are filtered.
Pitfalls: `mail()` needs sendmail installed or it hangs (getuid-hijack stalls);
`preg_match('/\bfunc\s*\(/')` dies to `$var('...')` variable-function calls.
Sources:
- https://ctftime.org/writeup/40427
- https://blog.kengwang.com.cn/archives/668/
- https://theromanxpl0.it/posts/2025/07/cornctf-2025-phpislovephpislife-3/

## W53 — Regex / DFA oracle puzzles

Signals: user-supplied REGEX matched against a secret with timeouts; 1-char source
edits; random lookahead-heavy patterns with 5s/round; "regex golf" scoreboards.
Steps: (1) ReDoS-timing oracle: `(?=.{i}$)(((.*)*)*)*salt` — length first, then
per-char, timeout(≥2s)=match; (2) regex-CACHE oracle: flip one `\` so interpolation
opens AND a `/o`-style cache pins YOUR pattern for the server's own flag check —
substring oracle per char; (3) synthesis rounds: parse `(?=.{i}[class])`,
backrefs, count-constraints into per-position charsets, `re.fullmatch`-verify
locally before sending; (4) DFA construction: remainder-states + state-elimination
(greenery) for div/mod/CRC predicates; PCRE recursion (`(?1)`, backrefs) for
parity/palindrome/multiply golf levels.
Pitfalls: catastrophic patterns also DoS YOUR solver — cap each probe;
`/o`-style caches persist per-process: re-order probes so the FIRST compile is yours.
Sources:
- https://ctf.zeba.dev/2025/openecsc/misc/ruby-matcher/writeup/
- https://kalawy.medium.com/regex-hacking-redos-cyborg-cybertalents-challenge-write-up-82418d62f1d7
- https://github.com/USTC-Hackergame/hackergame2024-writeups/tree/master/official/%E5%BC%BA%E5%A4%A7%E7%9A%84%E6%AD%A3%E5%88%99%E8%A1%A8%E8%BE%BE%E5%BC%8F
- https://kevin.fish/writeups/c5cdfd92faf2b3938497dfcf6bb219dd

## W54 — Git-object puzzles

Signals: `.git` exposure, `git patch`/`diff` inputs, submodule/`fsmonitor`
configs, `rev-list` vs `checkout` flows, corrupt packs, `protocol.file.allow`.
Steps: (1) patch-input jails: submit a `git diff` that edits the CHECKED file
itself (drop the `diff --git`/`index` lines; remove lines until accepted);
(2) submodule RCE: `protocol.file.allow=always` + nested-submodule `.git/config`
carrying `fsmonitor`/`post-checkout` — only the TOP config is inspected;
(3) ref-confusion: branch named as a full SHA beats the hash at `checkout`
(`rev-list` only resolves commits); (4) carving: `verify-pack -v` → `cat-file -p`
every object; dumb-protocol (`info/refs` + direct `/objects/xx/yy`) when smart
fails; force-push-hidden data via compare-view ranges.
Pitfalls: submodule payloads need the EXACT git version behavior (CVE-2024-32002
vs CVE-2025-48384 differ); `git checkout <sha>` prefers branches — verify locally.
Sources:
- https://github.com/jailctf/challenges-2025/blob/master/seven7seven/solve/README.md
- https://blog.gehaxelt.in/p/l3ak-ctf-2025-writeups-2025-07-13/
- http://platypwnies.de/writeups/2025/gpn/misc/check-this-out/
- https://kevin.fish/writeups/75ac9eafe11fe7645efe6edc414971e8

## W55 — procfs / sysfs / container escapes

Signals: arbitrary-FILENAME + offset writes; RO filesystems with writable
`/proc`; deleted-flag webservers with `Range:` reads; nsjail/Docker with host
PIDs visible; postgres `COPY ... FROM PROGRAM`.
Steps: (1) write-anywhere → `/proc/self/mem`: loop-patch (`call` LSB → `_start`),
code-cave shellcode, GOT redirect, restore — byte-at-a-time; (2) read-anywhere →
`/proc/self/maps` + ranged reads of `/proc/self/mem` (Range-header or fd-offset);
(3) RO-fs nsjail: `/proc/pid/mem` shellcode injection → `memfd_create`/`execveat`
fileless ELF → setuid-`.so` via truncated env path → `core_pattern`/`modprobe`
crash-callback for the host read; (4) container+DB: postgres `COPY FROM PROGRAM`
`mkdir/mount /dev/vda` then read the host disk; /proc/sys writes when allowed.
Pitfalls: `/proc/self/mem` needs `seek` before write and mapped addresses only —
parse `maps` first; `core_pattern` needs a crashing helper AND host-side handler.
Sources:
- https://ctftime.org/writeup/40397
- https://www.skullsecurity.org/2025/bsidessf-2025-accan-and-drago-daction-pwn-your-own-memory
- https://westonbelk.com/writeups/2024-utctf/Home%20on%20the%20Range.html
- https://jkrshnmenon.github.io/blog/2025/asisctf25fileno/

## W56 — eBPF verifier-confusion + probe jails

Signals: custom eBPF helpers, patched verifiers, `fexit`/kprobe programs with
maps dumped via `bpftool`, BPF probes that kill flag-readers, sudoers-backdoor hints.
Steps: (1) find the verifier lie: `MEM_RDONLY` arg that IS written (constant-folding
breaks), 32-vs-64 min/max confusion (`scalar32_rol`), range-invariant violations —
craft the (verifier=0, runtime=1) register, then OOB via `skb_load_bytes` length
confusion; (2) UAF maps: `delete` without clearing + shared map IDs across probes,
race the re-fill; (3) probe-jails: enumerate what the probe actually hooks
(open vs read) and pick an unhooked path (`_posixsubprocess`-equivalents at the
BPF layer: direct helpers); (4) backdoor reversing: `bpftool prog dump` +
map-decode (XOR'd trigger strings) then satisfy the trigger (cwd/`grinch`).
Pitfalls: verifier bugs are kernel-version-pinned — match the EXACT `v6.x.y`;
`bpftool` needs privileges the challenge grants — confirm before theorizing.
Sources:
- https://unvariant.pages.dev/writeups/aliyunctf-2025/pwn-beebee/
- https://0xffff.one/d/2190
- https://ortiz.sh/linux/2024/09/05/VULNBPF-CHAL-01.html
- https://metactf.com/blog/flash-ctf-berkeley-baubles/

## W57 — Chess-engine trust exploits

Signals: stockfish/python-chess services, client-side eval reporting, mate-in-N
positions with UI gates, `/api/move` endpoints.
Steps: (1) never play fair first: try `0000` (null move) — side-swap bugs turn
the engine against itself; (2) inject into engine channels: newline-smuggled UCI
(`setoption name Debug Log File value <template>`) = file write → template SSTI;
(3) client-trust: send the EVAL yourself (`eval -99999`), or POST the winning move
directly past UI popups (`preMoveCheck` is cosmetic); (4) pollution-gated sequels:
when the gate moves server-side (`unlocked` flag), pollute it via the settings
merge (`constructor.prototype`, not `__proto__`).
Pitfalls: fake-flag chat messages mean the REAL flag is elsewhere (env/file) —
read `run-docker.sh`/Dockerfile equivalents before celebrating.
Sources:
- https://kevin.fish/writeups/2f279fff831a5be3d6b5fbb8a6d86057
- https://exploitnotes.hashnode.dev/tryhackme-foolmate-writeup
- https://exploitnotes.hashnode.dev/tryhackme-fool-s-mate-revenge
- https://nightxade.github.io/ctf-writeups/writeups/2024/Vishwa-CTF-2024/crypto/lets-smother-the-king.html

## W58 — Minesweeper / slots / hash-grind games

Signals: minesweeper boards over sockets, slot machines with balance targets,
sha-repeating-char requirements, ZK color-commitment games.
Steps: (1) minesweeper: linearize (`a13+a22+…=b23`) and solve sparse
(`scipy.sparse`) — or XSLeaks the bot's board one tile at a time (redirect-limit
oracle) and replay seeds locally (seed-reuse = full-board recompute);
(2) slots: clone the RNG (MT19937-128 via OCR'd debug output; ChaCha-seed-0 replay;
timestamp-seed clock-sync; custom-XORShift z3 on symbol ranges) then bet only on
predicted wins — or farm +EV multipliers statistically; (3) hash-grinds: mine the
repeating-char preimage (Bitcoin-lowest-hash trick) rather than "solving" anything;
(4) ZK games: type-confusion on commitment inputs (`("a",-1)` vs `("a-",1)` same
hash) + pipeline requests to beat round limits.
Pitfalls: OCR'd RNG outputs need error-correction before cloning; statistical
farming needs a bankroll model — cap attempts before the service boots you.
Sources:
- https://gopherhack.com/posts/bitsctf2025-minesweeper-2/
- https://ptrstr.github.io/posts/nsec-2025-hit-the-jackpot/
- https://ctftime.org/writeup/39297
- https://medium.com/@random1106/corctf-2025-sudoku-writeup-46675773f62b

## W59 — CRC / checksum grind puzzles

Signals: CRC16+CRC8 double checks with "try harder" on exact match; CRC-framed
control servers; CAN logs with checksum bytes; IHDR dimension repairs.
Steps: (1) non-crypto checksums = brute-forceable: same-length random search for
CRC16+CRC8 collisions (2^24 work, not 2^128 thinking); (2) content recovery:
`zip-CRC32` + sizes → brute-force file bytes without the password; IHDR
`width×height` 4095² CRC match for dimension repair; (3) protocol checksums:
recompute with the given `gateway_proto` (don't reverse the polynomial by hand);
CAN: brute-force the 1 secret byte (0x00–0xFF), not the whole frame.
Pitfalls: CRC-brute length must EXACTLY match (padding changes everything);
`pngcheck` first — only brute-force dimensions if the CRC actually mismatches.
Sources:
- https://ctftime.org/writeup/40028
- https://www.cnblogs.com/JasonJHu/p/19105292
- https://www.dhjeong.kr/articles/icanhack-nl
- https://medium.com/@jalilayed/tryhackme-crc-me-if-you-can-industrial-intrusion-ctf-de94a9ff2e27

## W60 — Rule-bot / scripted-service tricks

Signals: chatbots that render (Jinja/SSTI), word-guessing bandits with hash
commitments, settings/profile merges, interview oracles, compare-view flags.
Steps: (1) render-bots: feed template syntax THROUGH the bot's pipeline
(`{{xxid.zs.system("sh")}}` via replace-games); (2) bandit games: satisfy the
PREFIX check only (`match`, not `fullmatch`), then arbitrary content; commit to
hashes you compute, never the server's; (3) merge endpoints: `constructor.prototype`
over `__proto__`, then replay the gated action; (4) compare-view: force-push hides
nothing — diff the pushed range directly.
Pitfalls: LLM-bots are a different skill (prompt-injection) — this pattern is for
RULE-based bots only; bandit services rate-limit — pipeline, don't sleep-loop.
Sources:
- https://blog.wm-team.cn/index.php/archives/81/
- https://hackmd.io/@iru7NsehRf-RHH8iUuJSPw/rkAl6xG0Jl
- https://github.com/rehackxyz/REUN10N/blob/main/CTF-writeups/2025/no-hack-no-ctf-2025/misc-gitgit.md

## W61 — PoW gates + high-round oracle solvers

Signals: `sha256(XXXX+suffix)==target` handshakes, hashcash banners, 1000-question
quizzes, multi-round guessing with salt commitments.
Steps: (1) parse precisely: hex-vs-bits, prefix-vs-SUFFIX target, charset —
`sha256(XXXX+suffix)` is a 4-char brute force, not a mining job; (2) hashcash CLI
(`hashcash -mCb<bits>`) for standard gates, local `solve_pow` stub otherwise,
120s cap — past that, the SPEC parse is wrong; (3) quiz loops: `solve.py` template,
answer-from-history, 200-round cap, 2 reconnects; (4) commitment games: compute
your hashes FIRST, answer lengths honestly, exploit the LENGTH channel.
Pitfalls: never GPU-scale a PoW before re-reading the banner — 9/10 stalls are
spec misreads (bits vs bytes, prefix vs suffix).
Sources:
- https://enoch.host/archives/qwb-2025-wp
- https://github.com/rehackxyz/REUN10N/blob/main/CTF-writeups/2026/0xl4ugh-ctf-v5/misc-hashcashslash.md
- https://github.com/rehackxyz/REUN10N/blob/main/CTF-writeups/2025/uoftctf/misc-mathtest.md

## W62 — QR repair + polyglot / document chains

Signals: QR with hands/finder damage, triangle-shuffled QR + generator script,
masked-QR validators, MP4-sized PNGs, gzip files that parse as PDFs, quine dirs.
Steps: (1) QR repair ladder: QRazyBox structure check → transplant finders at the
RIGHT version/alignment → paint-clean overlays → Reed-Solomon re-decode (don't stop
at first-decode-fail); exotic geometries (DCT-compressed, Arnold-scrambled,
triangle-cut) need their inverse BEFORE decode; masked-QR validators need the
mask re-applied, not removed; (2) polyglot ladder: `file` + `xxd` magic at EVERY
offset → `binwalk -e` carve each → ffprobe the image (MP4 hiding) → steghide the
extracted JPG with the video-derived password; (3) gzip-comment PDFs: the comment
IS the polyglot seam — parse with the strictest parser, not the most lenient;
(4) quines: run, don't read — output-of-output is the check.
Pitfalls: finder-transplant at the wrong version decodes NEVER — count timing
modules first; `binwalk -e` on huge images is slow — scope with `-l` first.
Sources:
- https://emree-1.github.io/posts/newyearctf2025-broken-qrcode/
- https://l0serqianxia.github.io/blog/2025/10/15/h3ctf2025-writeup/
- https://ctftime.org/writeup/39670
- https://ctf-flags.dev/competitions/v1t-ctf-2025/polyglot/
- https://blog.wm-team.cn/index.php/archives/86/

## W63 — Zip / bkcrack / nested-archive ladders

Signals: ZipCrypto-STORE entries, 12-char "uncrackable" passwords, `.7z` second
stages, vmdk/disk images holding zips, triage dumps with duplicate files.
Steps: (1) Store + known header (PNG/`<!DOCTYPE`) → bkcrack keys in minutes;
Deflate → recompress YOUR plaintext at `-mx0..9` until Z-reduction bites;
nested-ZIP → predict inner filenames (PK header + 8.3 names) instead of
brute-forcing; (2) partial-plaintext: `-o OFFSET -x HEX` with 12 known bytes
ANYWHERE (LSB channels, base64 tails); (3) second-factor archives: recovered keys
→ `--bruteforce ?p` the 12-char password for the `.7z` stage; (4) source the
plaintext creatively: OneDrive duplicates, `vmdk`-mounts, `.bash_logout` CRCs.
Pitfalls: `-c` and `-p` must align to the SAME entry; Deflate needs the SAME
compressor level — matrix all 10; `bkcrack -U` rewrites passwords, `-D` decrypts.
Sources:
- https://mariuszbartosik.com/buckeye-ctf-2024-reduce_recycle-write-up/
- https://badoption.eu/blog/2025/04/07/zipcrack.html
- http://blog.jgc.org/2024/09/cracking-old-zip-file-to-help-open.html
- https://medium.com/@DieLoop/write-up-the-watcher-cyberyard-6e2c94a32026
- https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/misc/dualzip

## W64 — Esolang JIT / OOB + dialect golf

Signals: custom bf/befunge runtimes (not stock), RWX `.text`, tape INTEGER types,
word-token dialects, `exec()`-of-output servers, ≤200-char limits, Headache/whitespace
variants.
Steps: (1) OOB first: `>`/`<` without bounds → GOT/return-address walk
(puts-leak → strlen→system; 1-byte call-target overwrite AFTER shellcode lands);
(2) int16-immediate sign-flips: overwrite the `\x00` high byte to swing jumps
negative into your input; (3) dialect golf: base-value tape setup + delta tweaks
for `exec(input())` loaders under the char cap — use a real BF golf generator,
never hand-roll; (4) word-dialects: token-map to bf, run, complete the lyric/poem
second stage; (5) variant alphabets (`NBSP/CR/VT/FF` whitespace): byte-histogram
BEFORE reaching for a stock interpreter.
Pitfalls: OOB writes land RELATIVE to the tape — recompute per-binary, never reuse
offsets; JIT `0xff` bytes decode as instructions — disassemble YOUR emitted bytes.
Sources:
- https://phreaks2600.fr/blog/swamp-2025-tinybrain/
- https://jacobnewman.ca/ctf/damctf25
- https://metactf.com/blog/flash-ctf-pikalang/
- https://thebusfactor-writeups.vercel.app/posts/2025-07-28-bfjail-writeup
- https://mindcrafters.xyz/writeups/bcactf-6-skibidi/

## W65 — Blind measurement channels (no-output jails)

Signals: templates that never print, redacted stdout (block glyphs), exception-eating
`except:` loops, prompt-counting services, wide-range alphabets admitting block chars.
Steps: (1) format-string measurement: `{0[N].__len__}` turns a char into an ADDRESS
repr; `addr%4096` is ASLR-invariant — read hex digits via width-spec padding
(`{0:{0[K]}×3}`) and probe lengths with a no-op (`{0[L]:.0}{0}` raises iff
out-of-range); recurse hex letters via THEIR singletons; (2) redaction-glyph
jails: banned-quote/no-bracket exec with censored stdout — exfil THROUGH what the
censor lets pass (non-word chars, block-glyph-safe channels), mapping filters
first; (3) length/side channels: XOR'd length prints, `len(all)`-style
self-referential checks — attack the CHECKER, not the secret.
Pitfalls: one-shot oracles (connection dies per probe) need the no-op probe FIRST
or the budget explodes; redaction maps are allowlists — enumerate with `chr()` sweeps.
Sources:
- https://blog.roblab.us/jailctf-2026-format-write-up/
- https://medium.com/@mhayder1964/jailctf-2026-writeups-8c593833daed
- https://github.com/rehackxyz/REUN10N/blob/main/CTF-writeups/2024/CyberSpaceCTF/Misc/redacted.md

## W66 — Arcade / puzzle-game + official game sources

Signals: Tetris/slot/bank/shop/caterpillar/vim minigames with score/flag thresholds,
official `solve.py` + challenge repos, timestamp-derived secret paths.
Steps: (1) play the rules, not the game: board-as-memory (Tetris cells = shellcode
bytes, win() trampoline), timestamp→secret-path recompute (solve small, derive
large), balance/threshold farming (+EV or exact-overwrite); (2) reuse the BINARY:
seed-reuse = full recompute locally; engine quirks (spawn-no-despawn) = physics
exploits; (3) official sources first: `solution/writeup.md`, `solve/solve.py`,
challenge.js are ground truth for mechanics — read before scripting.
Pitfalls: game RNG is usually timestamp/seed-reused — check BEFORE writing a bot;
score thresholds may be unreachable fairly — verify the math, then cheat the state.
Sources:
- https://ctf.mt/writeup/tetrx-dc33-quals/
- https://github.com/dicegang/dicectf-quals-2025-challenges/blob/main/misc/convenience-store/solution/writeup.md
- https://github.com/DownUnderCTF/Challenges_2025_Public/tree/main/misc/for_golf_hard
- https://github.com/WheeledCord/DownUnderCTF-2025-Writeup/tree/main/ductfbank-1
