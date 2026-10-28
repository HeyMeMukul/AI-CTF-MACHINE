# Crypto CTF — Quickref (~40 lines)

1. Classify first: `file`, PEM? hex/b64/bigint? `n` bits? `e`? #cts? ECB dupes?
2. `openssl rsa -pubin -in key.pub -text -noout` confirms RSA envelope.
3. `hashid hashes.txt` before any cracking; keep top-2 candidates.
4. ECB test: decode → 16-B blocks → `len(blocks) != len(set(blocks))` = ECB.
5. CyberChef Magic order: B64 → Hex → URL → ROT13 → XOR-brute → Magic(d=3).
6. RSA auto first: `timeout 120 RsaCtfTool --publickey key.pub --private`
7. Targeted next: `--attack wiener fermat hastads factordb --private`
8. From n/e: `RsaCtfTool -n <n> -e <e> --private`; decrypt: `--decryptfile ct.bin`
9. Small n (≤512b): `sage -c "factor(n)"` / `yafu "factor(n)"` / factordb API.
10. e=3 ×3 cts same m → Hastad CRT+cuberoot (L2). Same n, e1≠e2 → egcd (L3).
11. Many n → batch `gcd`; `gcd(c,n)≠1` → `p` found directly.
12. Wiener: big e + small d → `--attack wiener`; Boneh-Durfee = Sage-only note.
13. Partial p/d, stereotyped msg → Coppersmith/partial attacks (bounded, Sage).
14. ECB → cut-paste; CBC oracle → `padbuster URL CT 16 -encoding 2`
15. CTR/GCM nonce reuse → `C1^C2=P1^P2` crib-drag with `flag{`.
16. `H(secret||msg)` extend → `hashpump -s <sig> --data <o> -a <a> -k 14`
17. ECC reused r → recover k,d; `E.order()` in Sage; anomalous = note only.
18. Classical order: Caesar26 → XOR256 → Atbash → Vigenere → Rail2-6 → Morse.
19. `hashcat -m 0` MD5 / 100 SHA1 / 1400 SHA256 / 3200 bcrypt / 16500 JWT.
20. `john --format=Raw-MD5 --wordlist=wl.txt hashes.txt; john --show ...`
21. Libs: `long_to_bytes`, `gmpy2.iroot`, `sympy.factorint`, z3 BitVec skeleton.
22. Gated exploit: ONE step ≤120s, ≤3 tries, then `blocked`, new artifact path.
23. Validate: fresh `solve.py` + flag regex `flag\{[^}]+\}` + versions logged.
24. Unverified: featherduster subflags vary — check `--help` on-box.
25. Pollard p-1: smooth p-1 → `--attack pollard_p_1`; small q → `smallq`.
26. Mersenne/pastctf shapes → `mersenne_primes pastctfprimes`; dump: `--dumpkey`.
27. Create pubkey: `RsaCtfTool --createpub -n <n> -e <e>`; multi-key: `"*.pub"`.
28. hash_extender alt: `--data <o> --signature <s> --append <a> --secret 14 --format all`.
29. john formats: `john --list=formats | grep -i sha`; show: `john --show hashes.txt`.
30. Vigenere: Kasiski distance → keylen → frequency per column; quipqiup for substitution.
31. Affine: brute a (coprime 26) × b (26); Bacon/Polybius/Morse via CyberChef Magic.
32. Pipeline: 0:file/hashid/ECB (30s) → 1:Magic (60s) → 2:RsaCtfTool auto (120s).
33. Pipeline ctd: 3:targeted attacks → 4:oracle/crib → 5:hashcat-top10k → 6:classical.
34. MCP: `magic_decode` first; CTF-MCP `rsa_decrypt/caesar_brute/xor_brute/hash_identify`.
35. Negative: wrong-key fail + wrong-encoding fail required before flag claim.
36. Evidence: skill id, commands+timeouts, input hashes, attempt count, local-only flag.
37. Timeout wrapper: prefix EVERY attack with `timeout 120`; log exit codes.
38. Scope: technique-only, bounded wordlists (≤10k), no unbounded lattice jobs.
39. H1 Coppersmith: unknown bits `u <= bits(n)/e - 8` → Sage `small_roots(X=2^u)`; verify `pow(m,e,n)==c`.
40. H2 Boneh-Durfee: big e + small-d hint + Wiener failed + n≤2048b → Sage `(m,t)` lattice, cap 2 tries.
41. H3 Franklin-Reiter: same n/e, `m2=a*m1+b` EXACT → `gcd(x^e-c1,(a*x+b)^e-c2)`; random b' must fail.
42. H4 Hastad CRT: same m, e=3, ≥3 coprime n → CRT + exact `iroot`; inexact root = missing sample.
43. H5 ECDSA: same r → `k=(z1-z2)/(s1-s2)`, `d=(s1*k-z1)/r`; few-bit leaks need 50-100+ sigs for HNP lattice.
44. H6 Padding oracle: split confirmed → byte-at-a-time 15→0, ~128 queries/byte; guard pad==1 false-valid.
45. H7 CBC bitflip: `Cprev_new[i]=Cprev[i]^want[i]^orig[i]`; IV variant for block 0; one-shot forge.
46. H8 z3 custom cipher: exact BitVec width, one constraint per pair, UNSAT = misread source.
47. H9 MT untwist: source-confirmed generator → 624 words → untemper → predict + confirm one output.
48. H10 Shamir: ≥threshold shares → Lagrange `f(0)` mod p; verify on held-out share.
49. Chains: broadcast-CRT (A) / ECB cut-paste→bitflip (B) / oracle-decrypt→forge (C); one gate per link.
50. Failures F1-F7: factordb→yafu / flags→`--help` / no-Sage→pure-python / rate-limit→slow+jitter / endian-sweep.
51. Drift: on-box `--help` authoritative (RsaCtfTool/hashcat/padBuster); log `sage --version` + lib versions.
52. Tiers: easy ≤15m / medium ≤45m / hard ≤2h (ONE lattice, background) / insane → checkpoint + escalate.
53. Escalate: `/rev` compiled cipher or 2× UNSAT; `/misc` carrier pre-layer; operator for net-ban/restarts.
54. E2E RSA: baseline PEM+n-bits → confirm gcd/Wiener-neg → gated auto-attack → `solve.py` + regex handoff.
55. Writeup patterns W1-W30 (SKILL.md index; W13+ in techniques/writeup-patterns-1.md): bivariate/multivariate Coppersmith (W1/W2), linear-pad broadcast (W3), small-msg root first (W4), suffix-length sweep (W5), short-pad→FR chain (W6).
56. Oracle ladder: Wiener→Boneh-Durfee (W7), Bleichenbacher fast-path (W8), Manger triage on length oracles (W9), LSB binary-search (W10), Bellcore gcd (W11), smooth p-1/p+1/Fermat (W12).
57. HNP needs K-scaling + `m >= n_bits/leaked_bits` samples (W13); poly-nonce recurrence eliminate coeffs (W14); crafted nonce collision `00`vs`0000` (W15); anomalous curve order==p → Smart (W16).
58. Param-tamper checklist (W17), DH Lim-Lee static-key CRT (W18), CBC-R forge `Cprev'=I^want` (W19), CBC-MAC splice (W20), GCM GHASH root solve (W21).
59. HLE keylen differential 8..64 (W22); JWT order none→HMAC(`-m 16500`)→kid→jku (W23); CTR xor-delta no-oracle forge (W24).
60. MT untwist backward for past outputs (W25); z3 Untwister when `samples*bits>>19937` marginal (W26); seed-brute-first rule (W27); truncated-LCG lattice (W28).
61. Shamir shapes: threshold-1/dup-x/x=0 query/unauth shares (W29); structured-prime modified-BD equation patch (W30).
62. R2 lattice/ECDSA (W31-W36, r2-1.md): univariate epsilon/X re-tier + length-sweep (W31); dinv-shift trivariate backgrounded (W32); HNP BKZ/Babai + MSB/LSB flip (W33).
63. R2 ECDSA beyond basics: GLV/invalid-curve smooth-CRT under query budget (W34); twist ladder order triage (W35); singular nodal/cuspidal branch test + Sage log (W36).
64. R2 oracle diaries: Bleichenbacher single-interval + trimmers with query budget (W37); Manger triage-first ~1100 queries (W38); LSB calibrate-direction then n_bits loop (W39).
65. R2 symmetric: CBC diary pad==1 re-confirm then CBC-R `Cprev'=I^want` (W40); GCM GHASH reflection test + 3rd-sample verify (W41); GCM partial-to-full keystream offset-aware (W42).
66. R2 hash/PQ/stream: MD5 cpc.sh + SHA-0 weakness + subset-sum length fix (W43); LWE Kannan+Babai re-encrypt verify (W44); ChaCha first-segment slice + counter brute-force (W45).
67. R2 state/PRNG: RC4 permutation-locate + reverse PRGA from last byte (W46); xs128+ z3 + NaN-collapse table (W47); LCG Hensel lift + geometric-sum c (W48).
68. R2 sharing/cipher triage: seed-first then init inversion, mirror call order (W49); Shamir roots-of-unity collapse + intersect (W50); noisy-share Groebner + multi-prime CRT (W51).
69. R2 custom-cipher/RSA: Feistel meta-characteristic + structures + peel (W52); SPN DDT + slimgb meet-in-middle (W53); smooth-group Fermat/p-1/p+1/ECM escalate (W54).
70. R2 chains: short-pad Coppersmith then FR 2-gate budget (W55); CTR xor-delta + Poly1305 r/s truncation window (W56); Lim-Lee static-key CRT (W57).
71. R2 remainder: low-density knapsack LLL (W58); poly-nonce/ECLCG elimination (W59); linear-pad broadcast exact-r + `pow(r,-3,n)` check (W60).
72. R2 manifest: 459 NEW hard rows (407 ctftime + 52 blogs), 0% R1 overlap, 2024-2026 focus; SKILL.md 1088 lines, r2-*.md bodies hold snippets.
