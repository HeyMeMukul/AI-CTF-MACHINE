# Writeup-Distilled Patterns R2-1 — Lattice Refinements + ECDSA Beyond Basics (W31..W40)

Continuation of `skills/crypto/SKILL.md` section `## Writeup-Distilled Patterns`.
Technique-only: conditions, steps, snippets, pitfalls, source URLs. No flags or plaintexts.
Mined from `knowledge/writeups_mined/crypto_manifest_r2.md` (459 rows, 2026-10-16), disjoint from R1.

### W31 — Coppersmith univariate refinement (epsilon/X re-tier, length-sweep)
- Condition: H1-shape (small `e`, known prefix) but first `small_roots` run returns empty; unknown-bit estimate `u` is within `bits(n)/e` yet no roots. Needs re-tier, not new hypothesis.
- Steps: 1. Recompute `X = 2^u` from measured lengths (never reuse stale `X`). 2. Retry with `epsilon=1/15` (once) then `epsilon=1/30` sweep over suffix-length `i` in `range(0,100)` building `f_i(x)=(prefix(i)+x)^e-c`. 3. Decode every root, verify `pow(m,e,n)==c`.
- Snippet: ```python
  for i in range(100):
      m = bytes_to_long(prfx + b'\x00'*i + b'}')
      P, x = PolynomialRing(Zmod(n), 'x').objgens()
      for r in ((m + x)**e - ct).small_roots(X=2**(8*i), epsilon=0.05):
          cand = (m + int(r)) % n
          assert pow(cand, e, n) == ct
  ```
- Pitfalls: epsilon is a starting value, not gospel; bound `X` must track current `i`; one `(epsilon,i)` retry then background the lattice while solving other links.
- Sources: https://ctftime.org/writeup/41120 , https://ctftime.org/writeup/41112 , https://ctftime.org/writeup/41085

### W32 — Bivariate Herrmann-May with dinv shift (background discipline)
- Condition: Two hints (top bits of `dinv` and of `p+q`) with same shift `z`; stock univariate fails; trivariate lattice is slowest tier.
- Steps: 1. Build `f(k,x,y)=(1+k*(n+1-((hpq<<z)+y)))*((h<<z)+x)-e` over `Zmod(n)`. 2. Bounds `(e,2^z,2^z)`; run heuristic multivariate solver backgrounded with long timeout. 3. Recover `d=inv((h<<z)+x0,n)`; verify decrypt prefix structure.
- Snippet: ```python
  P, (k, x, y) = PolynomialRing(Zmod(n), 3).objgens()
  f = (1 + k*(n+1-((hpq << z)+y)))*((h << z)+x) - e
  roots = coppersmith_multivariate_heuristic(f, (e, 2**z, 2**z), 1.0)
  ```
- Pitfalls: shift `z` off-by-one kills all roots (recompute from hint bit-lengths); `k`-bound `e` assumes `d~=phi` scale; never queue a second trivariate without new evidence.
- Sources: https://ctftime.org/writeup/41112 , https://ctftime.org/writeup/41085 , https://ctftime.org/writeup/41084

### W33 — HNP refinement (BKZ/Babai fallback, MSB/LSB flip, sample rule)
- Condition: `m` ECDSA sigs with per-nonce leak `B` bits (MSB/LSB/small-nonce); first LLL returns short-but-wrong vectors. Need `m >= n_bits/leaked_bits` samples.
- Steps: 1. Reduce to `k_i=t_i*d+a_i (mod n)`; build `(m+2)x(m+2)` basis scaled by `K=2^B`. 2. LLL, scan rows for `d`; on failure run Babai nearest-plane then BKZ before declaring under-sampled. 3. Verify every candidate via `d*G==Pub` (also `n-d`).
- Snippet: ```python
  from sage.all import *
  def hnp_candidates(t, a, n, B):
      m = len(t); K = 2**B
      M = Matrix(QQ, m+2, m+2)
      for i in range(m): M[i,i] = n
      for i in range(m): M[m,i] = t[i]; M[m+1,i] = a[i]
      M[m,m] = K/n; M[m+1,m+1] = K
      for row in M.LLL():
          yield int(round(row[m]*n/K)) % n
  ```
- Pitfalls: unscaled lattice is the top time sink; MSB vs LSB flips which rows carry modulus weight; identical-`r` pairs mean plain reuse (no lattice); endianness of `h_i` breaks all rows.
- Sources: https://ctftime.org/writeup/41111 , https://blog.bordes.me/ledger-donjon-ctf-2020-smpc-signature.html , https://blog.cryptohack.org/ecdsa-side-channel-attack-projective-signatures-donjon-ctf-writeup

### W34 — ECDSA GLV / invalid-curve (unvalidated point, small-order CRT)
- Condition: ECDH/ECDSA service accepts attacker point without on-curve check (custom `Curve` class, x-only input, missing `containsPoint`); same addition law across `b`-family.
- Steps: 1. Vary `b`, compute `E.order()`, factor, keep curves with `2^40`-smooth composite order and `cof>=2^50`. 2. Send small-order point `G`, receive `S=G*priv`, solve `dlog` per factor (Pohlig-Hellman). 3. CRT-combine residues to full priv; verify by recomputing shared secret.
- Snippet: ```python
  while True:
      b = randint(1, p); E = EllipticCurve(GF(p), [a, b])
      fac = prime_factors(E.order())
      good = [f for f in fac if f.nbits() <= 40]
      if prod(good).nbits() >= 50:
          G = E.gen(0) * (E.order() // prod(good)); break
  ```
- Pitfalls: 4-query budgets need `>=2^50` per query (use composite smooth orders, not prime); confirm server uses same `a` law off-curve; `g=p-1`/identity edge cases first.
- Sources: https://www.hackthebox.com/blog/business-ctf-2022-400-curves-write-up , https://blog.stellarvector.be/writeups/2023/lakectf/keysharer , https://ilchen.github.io/cryptopals/

### W35 — Twist attack on single-coordinate ladder
- Condition: Montgomery-ladder ECDH takes x-only input, no on-curve check; twist has small smooth factors. Attacker confined to original+twist classes.
- Steps: 1. Compute twist order `p+1+t`, factor, find small-order twist points. 2. Send twist x-coordinate, learn `priv mod l_i` via key-distinguishing oracle per factor. 3. CRT-combine; verify against known transcript before scaling.
- Snippet: ```python
  # Sage: Et = EllipticCurve(GF(p), [A, B_twist]); print(Et.order().factor())
  # per small factor l: send x of order-l twist point, brute-force residue from oracle
  ```
- Pitfalls: twist-secure curves (`h,h'` tiny) void this path — check twist order first; x-only input gives exactly two classes (original+twist), not arbitrary `b`-family; cofactor clearing (`*h`) blocks small-subgroup part.
- Sources: https://safecurves.cr.yp.to/twist.html , https://taichiaudit.com/blog/elliptic-curve-attacks-small-subgroup , https://ctftime.org/writeup/41093

### W36 — Singular-curve ECDLP reduction (nodal vs cuspidal branch)
- Condition: Sage `EllipticCurve(GF(p),[a,b])` fails to init or DLP looks trivial; discriminant `4a^3+27b^2==0 (mod p)`; `b` possibly unknown.
- Steps: 1. Solve `b` from singularity (`b^2=-4a^3/27`), pick branch where `Gx^3+a*Gx+b` is quadratic residue. 2. Find singular point `3x0^2+a==0`; cuspidal maps to additive group (division), nodal maps to multiplicative group (`psi(P)=(y-m(x-x0))/(y+m(x-x0))`, `m^2=3x0`). 3. Solve `psi(Q)=psi(G)^flag` via `discrete_log`, test all sign combos, verify `Qx`.
- Snippet: ```python
  # Sage: F = GF(p); b_sols = ((-4*F(a)**3)/27).sqrt(all=True)
  # nodal: m = (3*x0).sqrt(); psi_G = (Gy-m*(Gx-x0))/(Gy+m*(Gx-x0)); flag = psi_Q.log(psi_G)
  ```
- Pitfalls: cuspidal-first assumption fails on nodal (and vice versa) — test both; `int()` cast needed for Sage `Integer.to_bytes`; wrong `b` branch gives non-residue `Qx` (re-pick, don't re-attack).
- Sources: https://ctftime.org/writeup/40367 , https://medium.com/@0xy4c1n3/worldwide-ctf-faulty-curve-challenge-writeup-cryptography-782a26fc6595 , https://ctftime.org/writeup/41093

### W37 — Bleichenbacher automation diary (single-interval, trimmers, budget)
- Condition: PKCS#1 v1.5 validity oracle; small/medium key skips step-2b; 1024-bit keys cost hundreds of thousands of queries.
- Steps: 1. Blind only if `c` non-conforming. 2. Jump straight to step-2c single-interval search (`r_i>=2(b*s-2B)/n`), never linear-scan 2b. 3. Optional fractional `(u/t)` trimmers to shrink `M0` before first search; narrow to one point, unblind with `s0^-1`.
- Snippet: ```python
  B = 2**(8*(k-2)); M = [(2*B, 3*B-1)]
  s = (n + 3*B - 1)//(3*B)   # first search start; step-2c jumps only
  ```
- Pitfalls: error-string vs timing oracles need separate calibration; OAEP on same key does not save v1.5; budget `queries*delay` before starting (rate-limit re-tier per F4).
- Sources: https://ctftime.org/writeup/41084 , https://ctftime.org/writeup/41083 , https://ctftime.org/writeup/41082

### W38 — Manger length-oracle refinement (triage-first, ~1100 queries)
- Condition: RSA oracle leaks BYTE LENGTH of `m*s mod n` (not validity bit); Bleichenbacher code converges nowhere here.
- Steps: 1. Triage with 3-5 probes: valid/invalid bit goes to W37, length/integer size goes here. 2. Interval from `2^(8(L-1))<=m*s<n<2^(8L)` with same `s^e` lever; majority-vote each length (noisy). 3. Strip padding only after single-value convergence.
- Snippet: ```python
  # Manger interval per query L: lo, hi = 2**(8*(L-1)), 2**(8*L)-1
  # same multiply-by-s^e lever as Bleichenbacher, different interval math
  ```
- Pitfalls: running the wrong oracle script wastes the whole budget — triage first; length oracles are noisier (majority-vote); ~1100 queries/minutes is normal for CTF keys, not a stall signal.
- Sources: https://ctftime.org/writeup/41083 , https://ctftime.org/writeup/41082 , https://ctftime.org/writeup/41081

### W39 — LSB/parity oracle binary search (calibrated direction)
- Condition: Oracle leaks one BIT of `m*s mod n` per query (parity/LSB/interval membership); works on unpadded textbook RSA.
- Steps: 1. Calibrate direction on known plaintext (MSB-vs-LSB inversion flips every bit). 2. Start `[0,n)`, per bit query `c*2^e`, narrow to lower/upper half. 3. After `n_bits` queries read `m`, verify by re-encrypt.
- Snippet: ```python
  lo, hi = 0, n
  for _ in range(n.bit_length()):
      c2 = c * pow(2, e, n) % n
      lo, hi = (lo, (lo+hi)//2) if oracle(c2) == 0 else ((lo+hi)//2, hi)
  ```
- Pitfalls: exactly `n_bits` sequential queries — rate limits kill it (re-tier); multiplier needs `gcd(2,n)==1` (fine for odd `n`); direction confusion inverts everything — calibrate, don't re-derive.
- Sources: https://ctftime.org/writeup/41082 , https://ctftime.org/writeup/41081 , https://ctftime.org/writeup/41079

### W40 — CBC padding-oracle automation diary + CBC-R forge
- Condition: CBC service splits padding-valid vs invalid (strings/codes/timing); goal extends from decrypt to valid forgery.
- Steps: 1. Confirm split by flipping last byte. 2. Byte-at-a-time 15→0 (`forged[j]=inter[j]^pad`), ~128 queries/byte, re-confirm `pad==1` ambiguity by corrupting adjacent byte. 3. Forge via `C_prev'=I^want` (IV variant for block 0), submit once; random-token control must fail.
- Snippet: ```python
  forged = bytearray(bs)
  for j in range(i+1, bs): forged[j] = inter[j] ^ pad
  # iterate forged[i] over 0..255 until oracle valid; inter[i]=found^pad; plain[i]=inter[i]^prev[i]
  ```
- Pitfalls: false-valid corrupts whole suffix (restart block on detection); `want` must include PKCS#7 bytes block-aligned; tool-first (`padbuster`) before hand-roll; checkpoint per byte under rate limits.
- Sources: https://ctftime.org/writeup/41080 , https://ctftime.org/writeup/41079 , https://github.com/jiegec/ctf-writeups/blob/master/docs/2025-12-19-hkcert-ctf-2025-quals/poc.md
