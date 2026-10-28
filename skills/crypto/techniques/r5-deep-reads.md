# R5 deep reads — crypto (10 complete articles, browser-read 2026-10-17)

## 1. TCP1P ThatOneRSA (bivariate Coppersmith)
- READ: `z=567`, `h=int(dinv>>z)`, brute `k` in `trange(8500,e)`, bounds `(2^z,2^z)`, m=2 d=1.
- CHAIN: shift back → `PR.<x,y>=PolynomialRing(Zmod(n))` → `f=(1+k*(n+1-(hpq+y)))*(h+x)-e` → bivariate small_roots → resultant → `d=pow(h+x,-1,n)` → decrypt; trivariate avoids k-loop.
- GOTCHA: k unknown in (0,e) → brute force; resultant==0 → skip k, retry.
- REUSE: MSB-leak of dinv and p+q → bivariate mod-n equation + Coppersmith + k enumeration.

## 2. Crypton Coppersmith README
- READ: `f(x)=(m+x)^e-c`, `XX=ceil(N^((beta^2/dd)-epsilon))`, cites David Wong video + Howgrave-Graham paper.
- CHAIN: stereotyped `f=(m+x)^e-c,beta=1` or factor-known `f=x-qbar,beta=0.5`, `epsilon=beta/7` → `small_roots` → test printable/factor.
- GOTCHA: epsilon must be ≤beta/7 or bound overshoots and LLL returns nothing; polynomial must be monic.
- REUSE: Any `N^(1/e)`-sized unknown → univariate small_roots template with beta 1 or 0.5.

## 3. mimoo coppersmith.sage (Howgrave-Graham builder)
- READ: `coppersmith_howgrave_univariate(pol,modulus,beta,mm,tt,XX)` with `matrix_overview`; TEST1 1024-bit/Kbits=200/e=3; TEST2 hidden=200/beta=0.5.
- CHAIN: shifted polys → integer matrix → `LLL()` → rebuild short poly → roots → keep if `gcd(modulus,result)>=modulus^beta`.
- GOTCHA: Verify `X^(n-1)<N^(beta*m)` and LLL-bound inequality; tune `mm=ceil(beta^2/(dd*eps))`, `tt=floor(dd*mm*(1/beta-1))`.
- REUSE: Verbatim Howgrave-Graham lattice builder for any monic univariate modular root with known beta/XX.

## 4. amyy45 RSA pico set (shared prime)
- READ: `nc verbal-sleep.picoctf.net 52950`, multiple N,e,c pairs; `math.gcd` across pairs finds shared p.
- CHAIN: Reconnect to collect pairs → pairwise gcd → `p` → `q=N//p` → phi → `d` → `long_to_bytes(pow(C,d,N))`.
- GOTCHA: Single N useless; needs flawed keygen reusing one prime across connections.
- REUSE: Multi-RSA service → batch-GCD ALL moduli before touching factoring.

## 5. SKIPPED — NCC ECDSA nonce bias (redirect, no body)

## 6. Cryptohack RSA track
- READ: Starter `101^17 mod 22663`; 150-bit semiprime; tracks Salty/Modulus-Inutilis/Everything-is-Big/Crossed-Wires/Endless-Emails; refs Boneh Twenty-Years.
- CHAIN: pow → phi → factor (small/ECM/manyprime) → small-e (Hastad/Wiener/Boneh-Durfee) → bespoke/null padding → signing-server/blinding/Pedro oracles.
- GOTCHA: `N=p` (phi `N-p`) and `N=p^2` (phi `p(p-1)`) variants; Ron-was-Wrong needs batch-GCD+OAEP.
- REUSE: RSA ladder: basics → factoring → small-e → shared-prime → padding → signature-oracle.

## 7. Cryptohack DH track
- READ: `p=991,g=209` inverse; `p=28151` smallest generator; NIST 3072-bit; Parameter-Injection + Export-grade sockets; AES-from-shared `decrypt.py`.
- CHAIN: `A=g^a`, `S=B^a` → SHA256/AES decrypt → MITM inject `g=1/p-1` forcing `S=1/0` → Pohlig-Hellman if `p-1` smooth → static-client reuse.
- GOTCHA: Safe prime `p=2q+1` blocks Pohlig; additive-group variant turns DLP into division — detect group type first.
- REUSE: DH checklist: inverse → generator-order → pubvals → MITM-parameter → smooth-order → key-reuse.

## 8. Cryptohack AES track
- READ: 11 round keys; S-box `GF(2^8)` inverse + affine; `ShiftRows/MixColumns`; files `matrix2bytes/add_round_key/sub_bytes/diffusion`; ECB-oracle/CTrime/Pad-Thai/GCM tracks.
- CHAIN: bytes2matrix → add_round_key → inv sub/shift/mix → reversed-key decrypt → modes in order: ECB cut-paste → CBC bitflip/IV-reuse → CTR nonce-reuse → padding-oracle → GCM-forgery.
- GOTCHA: Row- vs column-major matrix; final round skips MixColumns; decrypt-only CBC/ECB confusion enables oracle.
- REUSE: Build AES decrypt once, then attack mode misuse in fixed order ECB→CBC→CTR→padding→AEAD.

## 9. Cryptohack ECC track
- READ: `E:Y^2=X^3+497X+1768 mod 9739`, `P(8045,6936)`, `[1337]X=(1089,6931)`, Montgomery `2^255-19`, ProSign3/PS3, LadderLeak.
- CHAIN: point-neg/add formulas → double-and-add/Montgomery-ladder → ECDH `S=[nA]QB`+SHA1(x) → smooth-order/invalid-curve/small-subgroup → ECDSA nonce-reuse/bias → side-channel.
- GOTCHA: `p≡3 mod 4` sqrt shortcut and `±y` x-sharing only hold on stated curves; invalid-curve needs point validation.
- REUSE: ECC ladder: ops → scalar-mult → ECDH → bad-curve → ECDSA-nonce → ladder/power side-channel.

## 10. Cryptohack lattices track
- READ: `/lattices/` redirects; full track under `/post-quantum/`: Gauss `m=round(v1·v2/v1·v1)`, Gram-Schmidt μ, LWE `b=<A,S>+Δm+e`, Kyber1024 pubkey-size question.
- CHAIN: vectors/norm → det/vol → Gram-Schmidt → Gauss-2D → hidden-lattice → Backpack-LLL → LWE high/low-bits → noise-free linear → bounded-noise LLL.
- GOTCHA: Stale URL redirects; orthogonal ≠ orthonormal (5 s.f. float); SVP exact only dim≤4, else LLL approx.
- REUSE: Lattice path Gauss-2D → det/vol → LLL → Coppersmith → LWE-denoise; use post-quantum path when /lattices/ 404s.

## 11-12. SKIPPED — 0xdf blacksky + houseplant (HTTP 404 both)

## 13. DiceCTF BBBB (LCG-forced small-e)
- READ: LCG `X_{n+1}=aX+b mod p` 1024-bit; force `e=11` via `a^5=1` roots; `T≈2.0625→T=3`; `L=42`.
- CHAIN: solve `x^5-1` roots → seeds `[11,…]` → reconnect until 3 keys share e=11 (~125 tries) → CRT combine randomized-pad ciphertexts → `small_roots` with unknown-length brute `L in 30..43`.
- GOTCHA: Fixing all 5 exponents costs 3125; 3 suffice via T-bound; reject `a=1` trivial root + colliding seeds.
- REUSE: Force small-e broadcast: plant LCG cycle roots, CRT-combine, Coppersmith with length brute force.

## 14-15. SKIPPED — Pusty kcipher (subpath 404), picoCTF practice 70 (login/DNS-gated)
