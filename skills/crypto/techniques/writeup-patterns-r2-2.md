# Writeup-Distilled Patterns R2-2 — Oracle Automation, GCM, Hash, PQ, Stream (W41..W50)

Continuation of `skills/crypto/SKILL.md` section `## Writeup-Distilled Patterns`.
Technique-only: conditions, steps, snippets, pitfalls, source URLs. No flags or plaintexts.
Mined from `knowledge/writeups_mined/crypto_manifest_r2.md` (459 rows, 2026-10-16), disjoint from R1.

### W41 — GCM GHASH root recovery (Sage GF(2^128), reflection + third-sample verify)
- Condition: Two same-`(key,nonce)` AES-GCM pairs with tags/lengths observable; goal is tag forgery, not key recovery.
- Steps: 1. Difference tags to cancel `E_k(Y0)`, leaving `H`-polynomial over `GF(2^128)` (GCM modulus `x^128+x^7+x^2+x+1`). 2. Root-find `H` (Cantor-Zassenhaus/Sage `.roots()`), test both bit-reflection conventions against known tag. 3. Verify recovered `H` on a third same-nonce sample before forging; model short-tag truncation in the equation.
- Snippet: ```python
  # Sage: F.<x> = GF(2^128, modulus=x^128+x^7+x^2+x+1)
  # build D(H) = T1-T2-GHASH_diff(C1,C2,H) == 0 ; H = D.roots()[0][0]
  ```
- Pitfalls: reflection convention flips every root — test both; single-nonce-use deployments need a different path; dual-key variants need per-key `H` plus linear-system solve (not single `H`).
- Sources: https://frereit.de/aes_gcm/ , https://jia.je/ctf-writeups/2025-12-02-blackhat-mea-ctf-final-2025/tampering-detection-system.html , https://zenn.dev/asusn/articles/bf685fc0de5075

### W42 — GCM keystream crib-drag diary (partial-to-full, offset-aware)
- Condition: Same key+nonce ciphertexts with partial known plaintext at same offsets (aligned key-value logs, `Hello`-prefix); stream offset matters (decrypt resets to 0, encrypt may continue).
- Steps: 1. Recover partial keystream at known offsets (`ks=p^c`), complete the other plaintext, re-derive full keystream. 2. Confirm offset: only the first-segment keystream forges reset-stream decrypts (second-segment-only fails). 3. Encrypt target with full keystream slice, forge tag via W41, submit once.
- Snippet: ```python
  ks = bytes(a ^ b for a, b in zip(c1, p1))  # at known offsets only
  p2frag = bytes(a ^ b for a, b in zip(c1_plus_c2, ks_padded))
  ```
- Pitfalls: misaligned second plaintext is uncommon in the wild but fatal here — offsets must match exactly; compression-oracle pre-step (CRIME-style) leaks nonce/tag first on `zippy`-style services; one-shot forge per target.
- Sources: https://medium.com/@malkhoori/aes-gcm-nonce-reuse-writeup-7d5a92b599cb , https://kore.one/glacierctf-2025-aes-zippy-challenge-writeup/ , https://www.schneier.com/blog/archives/2024/06/demo-of-aes-gcm-misuse-problems.html

### W43 — Hash combiner break (chosen-prefix + SHA-0 expansion weakness)
- Condition: Verifier checks only digest of attacker-influenced document (cert/PDF/zip) on MD5/SHA-1, or custom SHA-1 with `W[j]=xor` (no `ROL1`) expansion.
- Steps: 1. Chosen-prefix MD5: pad prefixes to 64-byte boundary, run `hashclash/cpc.sh`, append common suffix (Merkle-Damgard state-keep). 2. SHA-0-shape: craft two-block collision with identical first block, differing second block, verify `encrypt(m1)==encrypt(m2)`. 3. Truncated/bespoke hashes: birthday on intermediate states plus subset-sum length fix instead.
- Snippet: ```bash
  ./cpc.sh prefix1.bin prefix2.bin   # -> prefix1.bin.coll, prefix2.bin.coll
  fastcoll -p prefix.txt             # identical-prefix case only
  ```
- Pitfalls: identical-prefix tooling does not solve chosen-prefix (different problems); SHA-1 chosen-prefix (SHAmbles) is usually out of CTF budget — prefer MD5 route; format must tolerate opaque collision bytes (comments/unused fields).
- Sources: https://sinapsi.wiki/w/ctf-crypto/p/hash/chosen-prefix-collision/ , https://medium.com/@kyoungminroh01/hacksium-busan-2025-preliminaries-writeup-sha-sha-sha-crypto-1d208f939bb4 , https://gniot.fr/2025/03/03/ctf-writeup.html

### W44 — Post-quantum-adjacent LWE lattice decoding (Kannan embedding)
- Condition: `C_i=Q_i*m+R_i*r_i+S_i*s_i (mod p)`-style concealed linear system or LWE samples with small secrets/noise; modulus and dimensions known.
- Steps: 1. Reduce multi-hole HNP to single HNP per theorem (compute `lambda` via continued fractions). 2. Kannan embedding: lattice from `(A_i,q)` rows scaled by noise bound, target from observations; LLL/BKZ + Babai. 3. Verify recovered secret by re-encrypt/verify, not by vector shortness alone.
- Snippet: ```python
  # Sage: B = embedding lattice from A rows scaled by noise bound; v = Babai(B, target)
  # secret = v[-1] mod q; verify by re-encrypting one sample
  ```
- Pitfalls: `B_min`/`mu` mis-set yields plausible wrong secrets — verify by re-encrypt; dimension grows fast (background it); 256-bit curves with tiny leaks and few dozen sigs means pivot, not more tuning.
- Sources: https://ctftime.org/writeup/40993 , https://ctftime.org/writeup/40942 , https://ctftime.org/writeup/41030

### W45 — ChaCha reduced-round / stream-reuse (counter brute-force, offset slice)
- Condition: ChaCha20 with key/nonce reuse across messages, or custom single-round ChaCha with known key and unknown 32-bit counter; known plaintext available.
- Steps: 1. Reuse case: `ks=c^p` at known offsets; note encrypt-continues vs decrypt-resets offset (only first-segment slice forges). 2. Reduced-round case: fix sample nonce, brute-force counter regenerating 64-byte blocks until ASCII `CTF{`-shape appears. 3. Verify by decrypting full target, not prefix alone.
- Snippet: ```python
  ks = bytes(c ^ p for c, p in zip(ct[:len(target)], pt[:len(target)]))
  forged = bytes(t ^ k for t, k in zip(target, ks))
  ```
- Pitfalls: wrong-segment keystream (second message slice) fails every time — use first segment; Poly1305 `r/s` under same reuse needs separate GF(`2^130-5`) root solve with truncation brute-force; single-round ciphers still need exact state layout (constants/key/counter/nonce words).
- Sources: https://github.com/CTF-STeam/ctf-writeups/tree/master/2025/GoogleCTF/crypto-numerology , https://medium.com/@kyoungminroh01/byuctf-2025-writeup-crypto-real-smooth-396fa28ee2da , https://nightxade.github.io/ctf-writeups/writeups/2024/BCA-CTF-2024/crypto/cha-cha-slide.html

### W46 — RC4 stack-state reversal (permutation locate, reverse PRGA)
- Condition: Binary leaks RC4 `S` array post-encryption (stack dump, malloc-adjacent buffer) plus ciphertext of structured plaintext; key itself absent.
- Steps: 1. Locate `S` as 256 consecutive bytes with each value exactly once (sliding-window count). 2. Recover last keystream `K=ct[-1]^pt[-1]`, find `t=S.index(K)`, solve `j` from `t=(S[i]+S[j])%256` with `i=len(msg)`. 3. Walk backwards: `swap(S[i],S[j]); j=(j-S[i])%256`, per-byte `t`, `K`, `pt=ct^K`.
- Snippet: ```python
  k = enc[-1] ^ flag_last_byte; t = S.index(k)
  i = len(enc); j = S.index((t - S[i % 256]) % 256)
  # then per step: S[i],S[j]=S[j],S[i]; j=(j-S[i])%256
  ```
- Pitfalls: `i` is per-iteration counter (`len(msg)` at end), not buffer index — off-by-one kills the chain; KSA-variant ciphers (extra key-mix into `j`) need variant reversal, not stock PRGA; confirm permutation window before reversing (garbage `S` = garbage plaintext).
- Sources: https://merkletr.ee/ctf/2024/heroctf/state , https://kishoreramk.medium.com/nova-ctf-2024-mystical-cryptic-state-reversal-4460173e9279 , https://writeups.csirt.muni.cz/content/htb/Challenges/crypto-the-last-dance/

### W47 — xorshift128+ V8/Node state recovery (z3 + NaN-collapse table)
- Condition: `Math.random()`-derived tokens/codes (floored `CONST*random()`), or old Node10 double-state build with `13371337` warmup draws and tiny hints.
- Steps: 1. Model xs128p as z3 `BitVec(64)` pair with exact shift/rotate constants, constrain floored outputs. 2. Old-Node path: build dictionary table for hint pairs assuming consecutive-NaN state (probability `~2^-24`, warmup helps). 3. Recover `(s0,s1)`, predict next output, confirm one live output before exploiting; backward-step for past targets.
- Snippet: ```python
  from z3 import BitVec, Solver
  s0, s1 = BitVec('s0', 64), BitVec('s1', 64)
  # add xs128p step constraints per observed Math.floor(CONST*random()) output
  ```
- Pitfalls: floor truncates to 53-bit doubles (not raw words) — model the conversion; version-specific `init` mapping (seed→state differs); warmup-iteration count must be mirrored exactly or state desyncs.
- Sources: https://soon.haari.me/2025-kalmarctf/ , https://github.com/cyberstudentsfoundation/Advent-of-CTF/blob/main/2024/Day%2018%20-%20trng/README.md , https://github.com/ljagiello/ctf-skills/blob/HEAD/ctf-crypto/prng.md

### W48 — Truncated-LCG cascade (Hensel lift + geometric-sum solve)
- Condition: 64-bit LCG stream cipher (`x'=a*x+c mod 2^64`, `a%8==5`, `c` odd) with persistent state, extra-block quirk (`<=` vs `<`), same-plaintext multiple samples.
- Steps: 1. Collect 16-20 same-plaintext samples in one session; derive first-block states via known prefix. 2. Solve `A*(x2-x1)==x3-x2 (mod 2^64)` for `A=a^s` (handle `gcd`), Hensel-lift `a` from mod-8 residue 5 to 64 bits. 3. Geometric-sum `S=1+a+..+a^(s-1)` to solve `c`, regenerate OTP, verify flag format.
- Snippet: ```python
  d2, d1 = (x2-x1) % M, (x3-x2) % M; g = __import__('math').gcd(d2, M)
  A0 = ((d1//g) * pow(d2//g, -1, M//g)) % (M//g)  # then lift a^s==A mod 2^64
  ```
- Pitfalls: extra-block stride miscount desyncs everything (account `used+extra`); big-endian byte extraction only; `s=ceil(len(ct)/8)` per-sample stride, not global constant.
- Sources: https://0xmshal.medium.com/hatagawa-ii-crypto-challenge-writeup-035c0ca16cb0 , https://medium.com/@marlithor_cyber/hatagawa-i-writeup-black-hat-mea-ctf-2025-quals-ba5285d2ddda , https://ctftime.org/writeup/41078

### W49 — Go/Python random (seed-first, init inversion, call-order mirror)
- Condition: PRNG outputs observed but 624-word requirement unmet; seed may be narrow (timestamp/PID) or default OS-seeded; language-specific `seed()` mapping.
- Steps: 1. Seed brute-force first (narrow window replay per candidate, match one output). 2. Few-output path: `init_by_array` inversion without brute force. 3. Only then full clone/symbolic; mirror exact call sequence (interleaved draws desync naive replay); CSPRNG (`os.urandom`/`secrets`) ends this path.
- Snippet: ```python
  import random
  for cand in range(t0, t1):
      r = random.Random(cand)
      if r.getrandbits(32) == observed:
          print('seed', cand); break
  ```
- Pitfalls: Python version changes `seed()` mapping (v1 vs v2 for str/bytes); `Random(None)` uses OS entropy (never brute-forceable); palindromic/constant MT states need `init_by_array` source read, not generic clone.
- Sources: https://github.com/ljagiello/ctf-skills/blob/HEAD/ctf-crypto/prng.md , https://everykalax.hateblo.jp/entry/2024/04/29/115024 , https://github.com/ImaginaryCTF/ImaginaryCTF-2025-Challenges/blob/main/Crypto/feistier-network/challenge/solve/writeup.md

### W50 — Shamir threshold misuse (x=0, duplicate-x, threshold-1, subgroup order)
- Condition: Shares `(x,y)` over known prime `p` with one of: threshold-1, duplicate `x`, user-supplied `x` evaluation, or attacker-chosen threshold `t` with `(p-1)%t==0`.
- Steps: 1. Threshold-1: any single share is the secret. 2. `x=0` directly; if blocked query `t`-th roots of unity (`x_i^t==1`) collapsing `a0+at` to one unknown, Lagrange-solve, intersect two sessions. 3. Duplicate-`x`: solve two evaluations for coefficients. Verify on held-out share; `GF(2^m)` needs different Lagrange.
- Snippet: ```python
  def lagrange_zero(shares, p):
      s = 0
      for i, (xi, yi) in enumerate(shares):
          num = den = 1
          for j, (xj, _) in enumerate(shares):
              if i != j: num, den = num*(-xj) % p, den*(xi-xj) % p
          s = (s + yi*num*pow(den, -1, p)) % p
      return s
  ```
- Pitfalls: 1-indexed prose vs 0-indexed wire (confirm with two known shares); share compression (only `y` sent) misaligns interpolation; `x` values may be shuffled (multiplicity-fingerprint de-shuffle first).
- Sources: https://blog.sceleri.cc/posts/sekai-ctf-2025-writeup/ , https://jia.je/ctf-writeups/2025-08-16-sekaictf2025/ssss.html , https://zayn.id.vn/posts/2024/2024-10-26-isitdtu-quals/
