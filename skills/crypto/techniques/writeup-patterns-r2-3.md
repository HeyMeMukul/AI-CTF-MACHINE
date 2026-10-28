# Writeup-Distilled Patterns R2-3 — Sharing, Feistel/SPN, RSA Triage (W51..W60)

Continuation of `skills/crypto/SKILL.md` section `## Writeup-Distilled Patterns`.
Technique-only: conditions, steps, snippets, pitfalls, source URLs. No flags or plaintexts.
Mined from `knowledge/writeups_mined/crypto_manifest_r2.md` (459 rows, 2026-10-16), disjoint from R1.

### W51 — Noisy Shamir recovery (Groebner product + CRT reassembly)
- Condition: Server returns multiset of noisy shares per query (one clean `P(x)` hidden among `noise*factor` variants), same `x` per answer set, degree `<=4`, secret larger than `p`.
- Steps: 1. Per query build `F(a)=prod_i(P(x;a)-y_i)==0 (mod p)` (vanishes via clean share). 2. Collect `>=30` equations, Sage `Ideal(eqs).groebner_basis()`, read `a0` from univariate basis element. 3. Repeat over distinct primes until product exceeds secret size, `crt()` residues to integer, bytes-decode.
- Snippet: ```python
  poly = sum(unknowns[i]*x**i for i in range(5))
  eqs.append(prod(poly - y for y in ys))  # one factor is zero
  G = Ideal(eqs).groebner_basis()
  ```
- Pitfalls: degree miscount needs more equations (collect 30, not minimal 5); int64-overflow lbs (`numpy` balanced-mod) need lattice variant, not pure Groebner; single-prime residue is `secret mod p` only — CRT required.
- Sources: https://metactf.com/blog/flash-ctf-shanoisemir/ , https://blog.tanglee.top/2024/07/15/HITCON-CTF-2024-Qual-Crypto-Writeup.html , https://www.0xatticus.com/posts/hitcon2023/hitcon2023_share/

### W52 — Custom Feistel differential trail (meta-characteristic + structures + peel)
- Condition: Custom Feistel (modular-addition branches, non-invertible round fn) with chosen-plaintext oracle, data limit (e.g. 7M pairs) and time limit.
- Steps: 1. Find 2-round meta-characteristic skipping every second round fn; enumerate differences (1000-sample test) plus rotations for `p`-just-under-usable. 2. Combine linearly-independent differences into input structures (`2^k` pairs per `2^k` queries). 3. Filter by truncated distinguisher, peel last round by key-guess counting, walk key-schedule backwards, verify master key on multiple plaintexts.
- Snippet: ```python
  # enumerate input diff d: test P[d -> d'] over round fn with 1000 random keys
  # structure: for independent d1,d2: queries {x, x^d1, x^d2, x^d1^d2} give 6 pairs
  ```
- Pitfalls: server input restrictions (e.g. MSB-must-be-0) force partial structures — recompute pair counts; Markov probability is key-averaged approximation, expect variance in right-pair counts; single-pair key filter leaves millions of candidates — use `~7` right pairs for balance.
- Sources: https://ecsc2024.it/openECSC/round-3/writeups/juniorfeistel , https://ctftime.org/writeup/39786 , https://ctftime.org/writeup/39775

### W53 — Custom SPN differential + Groebner fallback (DDT-guided)
- Condition: Custom SPN/Feistel with algebraic S-box over `GF(2^n)` (inverse-map plus affine terms), known-plaintext online oracle with time cap; differential may be thin.
- Steps: 1. Build S-box DDT, pick high-probability `d->d'` characteristic, collect `~500` pairs, peel last round by partial-decrypt counting. 2. Fallback: meet-in-the-middle Groebner (plaintext forward half, ciphertext backward half, degree-8 relations) with `singular:slimgb`. 3. Extract `z_i-blah` univariate elements, verify on fresh blocks (FEAL-4 worker pattern).
- Snippet: ```python
  I = Ideal(relations)  # degree-8 meet-in-the-middle relations
  G = I.groebner_basis(algorithm='singular:slimgb')
  ```
- Pitfalls: full forward/backward relations hit degree `~20` (never finishes) — always meet-in-middle; default `groeber` too slow, `slimgb` required; differential vs brute-force crossover differs per cipher size — check reference table before committing.
- Sources: https://dagurb.com/basedsbox/ , https://systemslibrarian.github.io/crypto-lab-biham-lens/ , https://ctftime.org/writeup/39786

### W54 — RSA smooth-group triage (Fermat gap + p-1/p+1/ECM escalation)
- Condition: `n` up to 1024+ bits with one smooth-side prime or tiny `|p-q|`; factoring is not only for small `n`.
- Steps: 1. `isqrt` gap check (seconds). 2. Pollard `p-1` with `B` escalating `1e5->1e6` (yafu pipeline or RsaCtfTool `pollard_p_1`). 3. Williams `p+1` if `p-1` fails but smoothness hinted; ECM dominates wall-time (bound it, medium-tier job). Confirm by division, standard decrypt.
- Snippet: ```bash
  timeout 120 yafu "factor(<n>)"
  timeout 120 RsaCtfTool --publickey key.pub --attack fermat,pollard_p_1 --private
  ```
- Pitfalls: multi-prime (`too many primes`) needs cofactor trial-divide after first factor; `eclipse`-style multi-prime still falls to same ladder; ECM without bound blows the tier budget — cap and pivot to protocol attacks.
- Sources: https://ctftime.org/writeup/41085 , https://ctftime.org/writeup/41082 , https://ctftime.org/writeup/41079

### W55 — Franklin-Reiter chained from short-pad Coppersmith (two-gate budget)
- Condition: Same `(n,e)` two ciphertexts with SHORT unknown pad difference (e.g. MD5-derived 16-byte suffix); direct FR impossible (diff unknown).
- Steps: 1. Gate 1: Coppersmith short-pad with `X=2^padbits` to recover `diff`. 2. Gate 2: FR poly-gcd `gcd(x^e-c1,(x+diff)^e-c2)` for `m`. 3. Verify both residues; wrong `X` is the usual failure (measurable pad length).
- Snippet: ```python
  h = (x + known_pad_poly)**e - c1          # small_roots(X=2**128) -> diff
  g1 = x**e - c1; g2 = (x + diff)**e - c2   # Franklin-Reiter gcd -> m
  ```
- Pitfalls: two lattices/oracles in series need separate budgets; multiplicative (not additive) pad voids affine FR model — re-derive; sympy quotient-domain gcd is fragile, Sage `Zmod(n)` gcd preferred.
- Sources: https://ctftime.org/writeup/41084 , https://ctftime.org/writeup/41081 , https://ctftime.org/writeup/41080

### W56 — CTR malleability + ChaCha-Poly1305 r/s under nonce reuse
- Condition: CTR ciphertext with attacker-influenced span and acting endpoint (no oracle), or ChaCha20-Poly1305 with nonce reuse leaking `r,s` reuse.
- Steps: 1. CTR: align via known-prefix cribs, `C_new[i]=C[i]^orig[i]^want[i]` at offsets only, submit once. 2. Poly1305: from two `(msg,tag)` pairs build `delta` polynomial over `2^130-5`, root-solve `r` (brute-force truncation bits `±2^5` window), solve `s`, forge tag. 3. Misalignment means re-probe (one-bit probe first), not wrong key.
- Snippet: ```python
  forged = bytearray(ct)
  for i, (o, w) in zip(offsets, zip(orig_span, want_span)):
      forged[i] = ct[i] ^ o ^ w
  ```
- Pitfalls: GCM-tagged CTR forgery breaks tags (CTR-only path); bit- vs byte-level offsets differ on packed protocols; Poly1305 truncation adds uncertainty bits — brute-force window required.
- Sources: https://hackmd.io/@tsuneki/ByHd_rU31x , https://medium.com/@kyoungminroh01/byuctf-2025-writeup-crypto-real-smooth-396fa28ee2da , https://writeups.csirt.muni.cz/content/htb/Challenges/crypto-the-last-dance/

### W57 — DSA/DH parameter tampering + Lim-Lee static-key CRT
- Condition: Server accepts client/challenge `(p,q,g)` without validation (non-prime `q`, smooth `p-1`, `g=1`/`p-1`, reused `(p,g)`); static-key reuse enables active attack.
- Steps: 1. Factor `p-1`, compute element orders of `g`; trivial `g=p-1` (order-2) first. 2. Active Lim-Lee: craft small-order public keys per smooth factor, learn secret mod each via oracle, CRT-combine. 3. Passive: Pohlig-Hellman on weak-randomness transcript. Confirm key reuse (ephemeral-only is not vulnerable).
- Snippet: ```python
  import sympy
  fac = sympy.factorint(p-1)
  for prime, _ in fac.items():
      if pow(g, (p-1)//prime, p) == 1:
          print('small subgroup order divides', prime)
  ```
- Pitfalls: `q` non-prime silently breaks DSA-nonce math — validate primality first; per-residue retry/majority on noisy oracles before CRT; peer public value must be replayed exactly.
- Sources: https://taichiaudit.com/blog/elliptic-curve-attacks-small-subgroup , https://ilchen.github.io/cryptopals/ , https://ctftime.org/writeup/41093

### W58 — Low-density knapsack LLL (short-vector subset recovery)
- Condition: Knapsack/subset-sum with low density (`d<0.94`), weights and target sum known; brute force infeasible.
- Steps: 1. Build lattice from weights with target-sum row (Lagarias-Odlyzko / CJLOSS), LLL-reduce. 2. Scan short vectors for 0/1 subset matching target. 3. Verify subset sum exactly before claiming.
- Snippet: ```python
  # Sage: B = knapsack lattice from weights + target row; for row in B.LLL(): check 0/1 subset
  ```
- Pitfalls: high-density knapsacks resist LLL (density check first); BKZ may be needed over plain LLL; multiple short vectors are normal — verify each against target sum.
- Sources: https://ctftime.org/writeup/41032 , https://ctftime.org/writeup/41031 , https://ctftime.org/writeup/41030

### W59 — ECDSA polynomial-nonce recurrence (ECLCG lattice refinement)
- Condition: Nonces from secret polynomial LCG `s_i=f(s_{i-1})` of known degree over prime field, tokens `t_i=x*(s_i+u_i)^-1` leak; `>=degree+1` samples.
- Steps: 1. Write `s_i=x*inv(t_i)-u_i`, substitute into recurrence, eliminate coefficients (Algorithm-2 style) to single high-degree equation in `x`. 2. Root-find over field, back-substitute, predict held-out token. 3. ECLCG variant: lattice over combined ECDSA+LCG unknowns instead of pure elimination.
- Snippet: ```python
  # Sage: s_i(x) = x*inv(t_i) - u_i ; polys = [s_{i+1} - f(s_i)]; G = Ideal(polys).groebner_basis()
  ```
- Pitfalls: degree miscount (update-order off-by-one) gives empty variety; modular-inverse `gcd==1` check required; multiple `(x,coeffs)` roots normal — disambiguate via held-out prediction.
- Sources: https://ctftime.org/writeup/41078 , https://ctftime.org/writeup/41068 , https://ctftime.org/writeup/41063

### W60 — Linear-padded broadcast unblinding (exact-r reconstruction)
- Condition: `e=3`, ciphertexts `(m*r)^3` or `(m*256^t+pad)^3` with computable blinding `r` (geometric sum, power of 256) from source.
- Steps: 1. Reconstruct `r` exactly (summation bounds matter), check `gcd(r,n)==1`. 2. Unblind `m^3=c*r^-3 mod n`, integer cube root, bytes decode. 3. Verify each part by re-encrypt before concatenation.
- Snippet: ```python
  m3_cubed = c * pow(r, -3, n) % n
  m, exact = gmpy2.iroot(m3_cubed, 3)
  assert exact
  ```
- Pitfalls: summation-bounds off-by-one gives garbage root (never force `iroot`); small-message first (`m^e<n` direct root) before broadcast machinery; endianness sweep on garbled-but-exact roots.
- Sources: https://ctftime.org/writeup/41057 , https://ctftime.org/writeup/41056 , https://ctftime.org/writeup/41055
