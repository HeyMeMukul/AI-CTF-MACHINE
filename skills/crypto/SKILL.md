---
name: crypto-ctf
description: In-depth CTF cryptography solver — classifier-first RSA/symmetric/ECC/classical/hash pipeline with exact tool commands.
category: crypto
phase: "1-3"
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Crypto CTF Skill — Classifier-First Decryption Pipeline

> Technique-only. No real flags. Well-known tools only:
> RsaCtfTool, SageMath, CyberChef, openssl, featherduster,
> factordb.com, yafu, hashcat, john, hashid, hashpump, hash_extender.

## Mental Model

1. Crypto CTFs are **classifier problems first, math problems second**.
2. Most solves come from recognizing the *envelope*, not breaking the primitive.
3. The envelope is one of five families:
4. `RSA / public-key` — PEM, DER, `n/e/c` bigints, multi-ciphertext sets.
5. `Symmetric / oracle` — ECB/CBC/CTR/GCM, padding oracles, nonce reuse.
6. `ECC / discrete-log` — small curves, nonce reuse, anomalous curves.
7. `Classical / encoding` — Caesar, Vigenere, RailFence, Morse, Base-family chains.
8. `Hash / password` — MD5/SHA/bcrypt/JWT, crack or extend, never invert.
9. Golden rule: **measure before attacking** — bit-length, `e`, block size.
10. A 256-bit `n` is factorable; a 2048-bit `n` with random primes is not.
11. `e=3` with 3+ ciphertexts is Hastad; `e=65537` with one ciphertext is not.
12. Duplicate 16-byte blocks in hex means ECB; random-looking output does not.
13. Small parameters mean math attack; large parameters mean protocol attack.
14. Protocol attacks: oracle reuse, nonce reuse, cut-and-paste, extension.
15. Encoding chains resolve with CyberChef Magic before any custom script.
16. RSA resolves with `RsaCtfTool --private` auto-attack before hand-rolled Sage.
17. Hashes resolve with `hashid` identification before `hashcat`/`john`.
18. Every decode attempt must preserve the raw artifact for re-baselining.
19. Timeouts bound everything: classify in 60s, auto-attack in 120s slices.
20. One gated exploit step at a time; validate with a fresh decrypt, never assume.
21. If output matches `flag\{[^}]+\}` or `CTF\{[^}]+\}` pattern, hand off immediately.
22. Never brute-force unbounded keyspaces; cap wordlists and iterations.
23. Document n/e/c bit-lengths, tool version, and exact command for the writeup.

## Workflow

### Phase 1 — Baseline (capture normal behavior first)

1. Inventory challenge files: `ls -la challenge/` and record sizes.
2. `file` every artifact: `file challenge/*`.
3. Detect PEM armor: look for `-----BEGIN`.
4. Detect DER: `openssl asn1parse -inform DER -in key.der`.
5. Detect hex vs base64 vs decimal bigint vs raw bytes.
6. Record exact string length and alphabet of each ciphertext blob.
7. Extract RSA parameters if present: `n`, `e`, `c`, `p`, `q`, `d`, `dp`, `dq`.
8. Compute `n` bit-length: `python3 -c "print(int(N).bit_length())"`.
9. Record `e` value: common are `3`, `17`, `257`, `65537`, large/random.
10. Count ciphertexts sharing one `n`, or keys sharing one modulus set.
11. ECB test: split hex/base64-decoded bytes into 16-byte blocks, count duplicates.
12. Hash test: match length+alphabet against hash regex table (see tools).
13. Encoding test: try `base64 -d`, `base32 -d`, `xxd -r -p`, URL-decode once.
14. Capture service behavior if networked: banner, prompt, error strings.
15. Save baseline to `results/crypto_baseline.txt` with hashes of inputs.
16. Do NOT launch any attack in this phase.

Reasoning Checkpoint: evidence = file types + n bits + e + block-duplicate result → confidence HIGH/MEDIUM/LOW → proceed to Confirmation or stop if scope mismatched.

### Phase 2 — Confirmation (minimal proof the primitive works)

1. Confirm RSA envelope: `openssl rsa -pubin -in key.pub -text -noout`.
2. Confirm DER fallback: `openssl rsa -inform DER -in key.der -text -noout`.
3. Confirm `n` factors trivially only if small: test `sage -c "factor(n)"`.
4. Confirm close primes only via `isqrt` gap check, do not full-Fermat yet.
5. Confirm Hastad precondition: count `c_i` with same plaintext and `e=3`.
6. Confirm common-modulus precondition: same `n`, distinct `e1 != e2`.
7. Confirm Wiener precondition: `e` large, `d` suspected small (`d < n^0.25/3`).
8. Confirm ECB: at least one repeated 16-byte block on attacker-controlled input.
9. Confirm CBC oracle: flip last byte, observe padding-error vs MAC-error split.
10. Confirm CTR/GCM reuse: two ciphertexts under same key+nonce/IV.
11. Confirm hash type: run `hashid` and keep top-2 candidates only.
12. Confirm classical: run Caesar brute (26 shifts) and eyeball English score.
13. Confirm CyberChef Magic candidate on a COPY of the blob, not the original.
14. Record which single attack condition fired; all others remain hypotheses.
15. If nothing fires, widen to encoding-chain brute-everything script (bounded).

Reasoning Checkpoint: evidence = single confirmed precondition (e.g. duplicate ECB block / hashid top hit / e=3 x3 cts) → confidence HIGH/MEDIUM/LOW → proceed to Negative or re-baseline if ambiguous.

### Phase 3 — Negative (2+ controls that should FAIL)

1. Control 1 — wrong-key decrypt: alter one byte of key/IV, expect failure/garbage.
2. Control 2 — wrong-encoding decode: base64-decode a hex blob, expect failure.
3. Control 3 — RSA negative: try Wiener flags when `d` is known-large, expect no key.
4. Control 4 — ECB negative: random plaintext with no repeated blocks shows no duplicates.
5. Control 5 — padding negative: unmodified ciphertext must NOT trigger padding error.
6. Control 6 — hash negative: wrong wordlist/word must NOT crack; verifies oracle honesty.
7. Control 7 — classical negative: ROT13 of known-English must score worse than ROT0.
8. Control 8 — Coppersmith negative: random-prefix stereotyped attack must fail fast.
9. Log each control: command, exit code, output hash, why failure was expected.
10. If any control unexpectedly SUCCEEDS, the model is wrong — re-baseline.
11. Do not proceed with more than one unverified hypothesis.
12. Keep artifact paths unique per attempt to avoid cross-contamination.

Reasoning Checkpoint: evidence = 2+ expected failures observed → confidence HIGH/MEDIUM/LOW → proceed to gated Exploit or stop if controls contradict the hypothesis.

### Phase 4 — Exploit (gated, ONE step, ≤120s)

1. Select exactly ONE attack from the RSA matrix / symmetric / hash plan below.
2. Default RSA first step: `RsaCtfTool --private` auto-attack, timeout 120s.
3. Default symmetric first step: single decrypt or single oracle query batch, ≤120s.
4. Default classical first step: bounded brute-everything script, ≤120s.
5. Default hash first step: `hashcat` dictionary with small wordlist, ≤120s.
6. Enforce timeout on every command: prefix with `timeout 120`.
7. Write recovered plaintext/key to a NEW file, never overwrite inputs.
8. If step times out: ONE corrected retry (fix flags/path), then ONE alternate method.
9. After 3 total attempts on this step, mark `blocked` and hand off, keep solving other work.
10. No mass brute force: wordlists ≤ 10k entries unless validator explicitly allows.
11. No destructive actions: no service DoS, no unbounded Sage lattice jobs.
12. Stop on first plausible plaintext; do not chain further exploits in this phase.

Reasoning Checkpoint: evidence = recovered bytes/key OR timeout log → confidence HIGH/MEDIUM/LOW → proceed to Validation-handoff or declare blocked after 3 attempts.

### Phase 5 — Validation-handoff (what a fresh validator must re-run)

1. Provide `solve.py` that re-derives the flag from challenge artifacts alone.
2. State expected flag regex: e.g. `flag\{[^}]+\}` (generic, technique-only).
3. List exact re-run commands: classifier command + exploit command + decrypt command.
4. State service state needed: static files vs live oracle URL/port.
5. Include negative re-check: wrong key must fail when validator re-runs.
6. Record tool versions: `RsaCtfTool --help | head`, `hashcat --version`, `sage --version`.
7. Record attempt count, timeouts hit, and artifact paths.
8. Redaction: flags stay local; handoff contains regex, not the flag value.
9. If live service restarted or binary changed, validator must re-baseline first.

Reasoning Checkpoint: evidence = solve.py output matches flag regex on fresh run → confidence HIGH/MEDIUM/LOW → close task or loop back to Baseline on mismatch.

## Tool table (exact copy-paste commands)

| Purpose | Exact command |
|---|---|
| File type baseline | `file challenge/*` |
| PEM pubkey inspect | `openssl rsa -pubin -in key.pub -text -noout` |
| PEM privkey inspect | `openssl rsa -in key.priv -text -noout` |
| DER parse | `openssl asn1parse -inform DER -in key.der` |
| DER pubkey inspect | `openssl rsa -pubin -inform DER -in key.der -text -noout` |
| n bit-length | `python3 -c "n=int(open('n.txt').read().strip(),0); print(n.bit_length())"` |
| ECB duplicate-block test | `python3 -c "import base64; b=base64.b64decode(open('ct.b64').read()); print(len(b), len(set(b[i:i+16] for i in range(0,len(b),16))))"` |
| Base64 decode | `base64 -d blob.b64 > blob.raw; xxd blob.raw \| head` |
| Hex decode | `xxd -r -p blob.hex > blob.raw` |
| Hash identify | `hashid -m '5d41402abc4b2a76b9719d911017c592'` |
| Hash identify file | `hashid hashes.txt` |
| CyberChef Magic (manual recipe order) | `From_Base64 -> From_Hex -> ROT13 -> XOR_Brute -> Magic` in CyberChef; try `Magic` with depth 3 first |
| RsaCtfTool auto-attack | `timeout 120 RsaCtfTool --publickey key.pub --private` |
| RsaCtfTool decrypt raw file | `timeout 120 RsaCtfTool --publickey key.pub --decryptfile ct.bin` |
| RsaCtfTool decrypt integer | `timeout 120 RsaCtfTool --publickey key.pub --decrypt <int_c>` |
| RsaCtfTool from n/e | `timeout 120 RsaCtfTool -n <n> -e <e> --private` |
| RsaCtfTool Wiener | `timeout 120 RsaCtfTool --publickey key.pub --attack wiener --private` |
| RsaCtfTool Fermat | `timeout 120 RsaCtfTool --publickey key.pub --attack fermat --private` |
| RsaCtfTool Hastad | `timeout 120 RsaCtfTool --publickey key.pub --attack hastads --private` |
| RsaCtfTool factordb | `timeout 120 RsaCtfTool --publickey key.pub --attack factordb --private` |
| RsaCtfTool small-q / mersenne / pastctf | `timeout 120 RsaCtfTool --publickey key.pub --attack smallq mersenne_primes pastctfprimes --private` |
| RsaCtfTool comfact (n1,n2 share p) | `timeout 120 RsaCtfTool --publickey key1.pub --attack comfact_cn --private` |
| RsaCtfTool all (bounded) | `timeout 120 RsaCtfTool --publickey key.pub --attack all --timeout 100 --private` |
| RsaCtfTool create pubkey | `RsaCtfTool --createpub -n <n> -e <e>` |
| RsaCtfTool dump key | `RsaCtfTool --publickey key.pub --dumpkey` |
| Sage small-n factor | `timeout 120 sage -c "n=<n>; print(factor(n))"` |
| yafu factor | `timeout 120 yafu "factor(<n>)"` |
| factordb lookup | `curl -s "http://factordb.com/api?query=<n>"` |
| openssl s_client probe | `echo \| timeout 20 openssl s_client -connect <host>:<port> -showcerts` |
| CBC padbuster decrypt | `timeout 120 padbuster "http://<host>/app?UID=<CT>" "<CT>" 16 -encoding 2 -cookies "AUTH=<CT>"` |
| CBC padbuster encrypt | `timeout 120 padbuster "http://<host>/app?UID=<CT>" "<CT>" 16 -encoding 2 -plaintext "ADMIN=1"` |
| Hash length extension (hashpump) | `hashpump -s '<sighex>' --data '<orig>' -a '<append>' -k 14` |
| Hash length extension (hash_extender) | `hash_extender --data '<orig>' --signature '<sighex>' --append '<append>' --secret 14 --format all --table` |
| hashcat MD5 | `timeout 120 hashcat -m 0 hashes.txt wordlist.txt --force` |
| hashcat SHA1 | `timeout 120 hashcat -m 100 hashes.txt wordlist.txt --force` |
| hashcat SHA256 | `timeout 120 hashcat -m 1400 hashes.txt wordlist.txt --force` |
| hashcat bcrypt | `timeout 120 hashcat -m 3200 hashes.txt wordlist.txt --force` |
| hashcat JWT HS256 | `timeout 120 hashcat -m 16500 jwt.txt wordlist.txt --force` |
| john crack | `john --format=Raw-MD5 --wordlist=wordlist.txt hashes.txt` |
| john show | `john --show --format=Raw-MD5 hashes.txt` |
| exiftool metadata | `exiftool -a -G1 blob.jpg` |
| featherduster classic check | `featherduster --auto blob.txt` |
| XOR brute single-byte | `python3 -c "b=open('ct.raw','rb').read(); [print(hex(k), bytes(x^k for x in b[:60])) for k in range(256)]" \| head -40` |

## Payload / code library

### L1 — Classifier snippet (PEM/DER/hex/b64/bigint, ECB test)

```python
import base64, binascii, re, pathlib
def classify(blob: str):
    blob = blob.strip()
    out = {}
    out['len'] = len(blob)
    if '-----BEGIN' in blob:
        out['type'] = 'PEM'
    elif re.fullmatch(r'[0-9a-fA-F\s\n]+', blob) and len(re.sub(r'\s','',blob)) % 2 == 0:
        out['type'] = 'HEX?'
    elif re.fullmatch(r'[A-Za-z0-9+/=\n]+', blob) and len(blob) % 4 == 0:
        out['type'] = 'B64?'
    elif re.fullmatch(r'\d+', blob):
        out['type'] = 'BIGINT?'
        out['bits'] = int(blob).bit_length()
    else:
        out['type'] = 'RAW/TEXT?'
    return out
def ecb_dupes(raw: bytes, bs=16):
    blocks = [raw[i:i+bs] for i in range(0, len(raw), bs)]
    return len(blocks), len(set(blocks))
print(classify(pathlib.Path('blob.txt').read_text()[:4000]))
```

### L2 — RSA: Hastad broadcast e=3 (CRT + integer cube root)

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2
# Condition: same m, e=3, 3+ distinct (n_i, c_i) pairs.
def hastad(pairs):
    # pairs = [(n, c), ...]
    from sympy.ntheory.modular import crt as sym_crt
    ns = [n for n, c in pairs]
    cs = [c for n, c in pairs]
    M, x = sym_crt(ns, cs)  # x^e combined
    m, exact = gmpy2.iroot(int(x), 3)
    assert exact
    return long_to_bytes(int(m))
```

### L3 — RSA: common modulus (egcd) — same n, e1 != e2

```python
from Crypto.Util.number import long_to_bytes
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)
def common_modulus(n, e1, e2, c1, c2):
    _, a, b = egcd(e1, e2)
    m1 = pow(c1, a, n) if a > 0 else pow(pow(c1, -1, n), -a, n)
    m2 = pow(c2, b, n) if b > 0 else pow(pow(c2, -1, n), -b, n)
    return long_to_bytes((m1 * m2) % n)
```

### L4 — RSA: Wiener small-d via continued fractions (sketch)

```python
from fractions import Fraction
def convergents_cf(e, n):
    # Use RsaCtfTool --attack wiener first; this is a manual fallback.
    def cf(a, b):
        while b:
            q = a // b
            yield q
            a, b = b, a - q * b
    seq = list(cf(e, n))
    # test each convergent k/d: check (e*d-1) % k == 0 etc.
    return seq  # then trial-decrypt per candidate d
```

### L5 — RSA: comfact gcd sweep across many n (batch GCD)

```python
import math
ns = [int(x.strip()) for x in open('ns.txt')]
for i in range(len(ns)):
    for j in range(i+1, len(ns)):
        g = math.gcd(ns[i], ns[j])
        if g != 1:
            print(f'shared factor ns[{i}],ns[{j}]: {g}')
```

### L6 — Symmetric: CTR/GCM nonce reuse crib-drag (C1^C2 = P1^P2)

```python
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))
c1 = bytes.fromhex(open('c1.hex').read().strip())
c2 = bytes.fromhex(open('c2.hex').read().strip())
kstream = xor(c1, c2)  # equals p1 ^ p2
crib = b'flag{'
for off in range(len(kstream) - len(crib)):
    p2frag = xor(kstream[off:off+len(crib)], crib)
    print(off, p2frag)  # eyeball printable fragments, slide crib
```

### L7 — CBC bit-flip sketch (need one valid oracle response)

```python
# Condition: CBC, attacker controls a preceding block (e.g. user=...).
# Flip: target_byte = orig_byte ^ guess ^ desired.
# Theory: P2[i] = D(C1)[i] ^ IV/C_prev[i]; modify C_prev to steer P2.
# Then confirm with padbuster decrypt before forging admin token.
```

### L8 — Classical brute-everything (bounded order)

```python
import base64, binascii, codecs
def try_all(s: str):
    out = {}
    for i in range(26):
        t = codecs.encode(s, 'rot_13') if i == 13 else s  # placeholder Caesar sweep
        out[f'caesar{i}'] = t
    try: out['b64'] = base64.b64decode(s).hex()[:200]
    except Exception as e: out['b64'] = f'fail:{e}'
    try: out['hex'] = bytes.fromhex(s).decode('utf-8', 'replace')[:200]
    except Exception as e: out['hex'] = f'fail:{e}'
    # order: b64 -> hex -> URL -> Caesar(26) -> Atbash -> RailFence(2..6) -> Morse
    return out
```

### L9 — ECC nonce-reuse + Sage order check

```python
# Condition: two ECDSA sigs (r same, s1 != s2) share nonce k.
# k = (z1 - z2) * inv(s1 - s2) mod n; d = (s1*k - z1) * inv(r) mod n.
# Sage order check (run in sage):
#   sage: E = EllipticCurve(GF(p), [a, b]); print(E.order())
# Anomalous curve (|E| == p) and small-subgroup: note only, needs Sage.
```

### L10 — z3 skeleton for custom ciphers / CRC games

```python
from z3 import BitVec, Solver, sat
s = Solver()
x = BitVec('x', 32)
s.add((x ^ 0xDEADBEEF) == 0x12345678)  # replace with real relation
assert s.check() == sat
print(hex(s.model()[x].as_long()))
```

### L11 — pycryptodome / gmpy2 / sympy recipes

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, getPrime
import gmpy2, sympy
m = bytes_to_long(b'probe')
c = pow(m, 65537, 999999937)           # trial encrypt sanity check
root, exact = gmpy2.iroot(123456789, 3)  # integer e-th root
print(sympy.factorint(2**16 + 1))        # small composite sanity
print(inverse(65537, 999983 * 999979))   # modular inverse sanity
print(long_to_bytes(c))
```

## Decision tree

1. Blob has `-----BEGIN` or `n = ` / `e = `?
2. YES → RSA branch. Measure `bits(n)` and `e`, count ciphertexts/keys.
3. `bits(n) <= 512`? → `sage factor` / `yafu` / `factordb` → `--private`.
4. `|p - q|` small (isqrt gap tiny)? → `--attack fermat`.
5. Many `n` share a prime? → batch `gcd` → `--attack comfact_cn`.
6. `e = 3` and ≥3 `(n,c)` same plaintext? → `--attack hastads` / L2 script.
7. Same `n`, two `e`? → egcd L3 (`commonfactors`).
8. `e` huge / `d` tiny hint? → `--attack wiener` (then Boneh-Durfee note in Sage only).
9. Partial `p`/`d` bits given? → `partial_p` / `partial_d` / Coppersmith stereotyped.
10. `q` small / Mersenne / pastctf prime shape? → `smallq mersenne_primes pastctfprimes`.
11. `gcd(c, n) != 1`? → `p = gcd(c, n)` directly (comfact edge).
12. Blob is fixed-length hex with duplicate 16-B blocks? → ECB cut-paste.
13. Oracle distinguishes padding error? → `padbuster` decrypt, then forge.
14. Two CTs same key+nonce? → XOR crib-drag L6.
15. `H(secret||msg)` + append goal? → `hashpump` / `hash_extender`, sweep keylen 8–32.
16. Small curve / reused `r` in ECDSA? → nonce-recovery L9 + Sage order check.
17. Gibberish text / short blob? → CyberChef Magic → Caesar→Atbash→Vigenere(Kasiski)→Rail→Morse.
18. Fixed-length hex of 32/40/64/128 chars? → `hashid` → `hashcat -m` / `john`.
19. NOTHING fires → bounded brute-everything L8 + `featherduster --auto`, then blocked.

## AI automation notes

1. Auto-pipeline order (each step `timeout 120`, stop on first flag-pattern hit):
2. Step 0 (30s): `file`, length/alphabet log, `hashid`, ECB block test, PEM check.
3. Step 1 (60s): CyberChef Magic recipe on copy: `From_Base64, From_Hex, URL_Decode, ROT13, XOR_Brute, Magic(depth=3)`.
4. Step 2 (120s): if RSA envelope → `RsaCtfTool --publickey key.pub --private` (auto).
5. Step 3 (120s): if auto fails → targeted `--attack wiener fermat hastads factordb` subset.
6. Step 4 (120s): if symmetric oracle → one `padbuster` decrypt batch OR one crib-drag pass.
7. Step 5 (120s): if hash → `hashcat -m <mapped>` with `rockyou-top10000.txt` only.
8. Step 6 (120s): classical bounded sweep: Caesar×26, single-byte XOR×256, Rail 2–6, Morse.
9. CyberChef-MCP usage: `magic_decode(blob)` first, then explicit `xor_brute`, `vigenere_break`.
10. CTF-MCP crypto tools: `rsa_decrypt(n,e,c)`, `caesar_brute`, `xor_brute`, `hash_identify`.
11. dcode/cryptii equivalents when MCP offline: dcode Caesar/Vigenere analyzers, cryptii Base64↔Hex chain.
12. Log every MCP call: input hash, recipe, output length, English-score, seconds used.
13. Negative controls are mandatory before claiming any decode is the flag path.
14. Validator handoff must include the exact recipe string, not "used CyberChef".
15. Unverified at write time: featherduster exact subflags vary by version — run `featherduster --help` on-box.
16. Unverified at write time: Sage `BonehDurfee` has no stable one-liner — treat as Sage-notebook-only and cite version.

## Evidence contract reminder

1. Skill id: `crypto-ctf`; EXP/CP ids per attempt; unique artifact path per run.
2. Commands recorded verbatim with timeouts and exit codes.
3. Baseline diff: input hash before/after, output length shift noted.
4. Verdict HIGH/MEDIUM/LOW with the firing condition named.
5. Attempt count (cap 3 for gated step); flags local-only, handoff uses regex.

Reasoning Checkpoint: evidence = contract fields present + solve.py re-runnable + versions logged → confidence HIGH/MEDIUM/LOW → close task or loop back to Baseline on mismatch.

## Advanced / Hard-Challenge Playbook

> Hard challenges are still classifier problems, but the firing condition is a
> *partial-leak* or *relation* rather than a weak parameter. Measure the leak
> first, then pick the lattice/oracle/algebra tool. Lattices run long — hard-tier jobs.

### H1 — Coppersmith short-pad / known-high-bits (Sage stereotyped setup)

1. When to attempt: RSA with `e` small (often `e=3` or `e=65537`) AND part of the
   message or part of a prime is known: fixed header/footer, stereotyped prefix
   with generic `flag\{[^}]+\}` shape, high bits of `p` leaked, or short random
   pad (`m = pad || secret`).
2. Concept: Coppersmith finds small roots of `f(x) = 0 mod n` with LLL when the
   unknown part is `< ~n^(1/e)` (univariate) or meets the multivariate bound.
   Howgrave-Graham reformulation is what Sage implementations use.
3. Precondition check: estimate unknown-bit length `u`. Attempt only if
   `u <= floor(bits(n)/e) - 8` (safety margin). If `u` is larger, collect more
   leak or switch to Hastad/Franklin-Reiter/Boneh-Durfee.
4. Sage stereotyped setup skeleton (adapt variable names to the challenge):

```python
# SageMath stereotyped-message / known-high-bits skeleton (technique-only).
# Condition: c = (known_prefix * 2^k + x)^e mod n, |x| < X ~ n^(1/e).
n = int(open('n.txt').read().strip(), 0)
e = int(open('e.txt').read().strip(), 0)
c = int(open('c.txt').read().strip(), 0)
kbits = 200          # bit-length of unknown part (measured, not guessed)
X = 2**kbits
P = PolynomialRing(Zmod(n), 'x')
x = P.gen()
known = 12345        # placeholder for measured known prefix as integer
f = (known + x)**e - c
# small_roots needs Sage; bound X must satisfy Coppersmith bound:
roots = f.small_roots(X=X, beta=1.0, epsilon=0.05)
print(roots)
```

5. Known-factor variant (high bits of `p` leaked): build
   `f(x) = (p_high * 2^k + x)` and call `small_roots` mod `n` with `beta=0.5`.
   Needs roughly half the bits of `p`; fewer bits means no attempt.
6. Bounds: run with `timeout 600` or more; LLL dimension grows fast. Start with
   default `epsilon`, reduce only if no roots and bound check passed.
7. Validate: re-encrypt candidate root (`pow(m, e, n) == c`) before claiming.
   One failed `small_roots` run is a signal, not proof of wrong hypothesis —
   re-check `X` math first.
8. Fallback if Sage missing: do NOT hand-roll LLL; drop to Hastad/Wiener/gcd
   sweep or mark lattice-blocked (see Failure-Mode Catalog).

### H2 — Boneh-Durfee concept + when to attempt

1. Concept: extension of Wiener. When `d < n^0.292` (refined bound; `0.284` for
   the simpler lattice), the RSA equation `e*d - k*phi = 1` becomes a small-root
   bivariate problem solvable with LLL + resultants (Herrmann-May simplification).
2. When to attempt — ALL must hold:
   a. `e` is large (order of `n`, e.g. `e ~ n`), not `e=3`.
   b. Challenge hints small `d` (fast decrypt, small-d comment, Wiener near-miss).
   c. `bits(n) <= 2048` (lattices above this rarely finish in CTF time).
   d. RsaCtfTool `--attack wiener` already failed (Wiener covers `d < n^0.25/3`).
3. How to run: there is no stable one-liner; use a Sage Boneh-Durfee notebook
   script (`boneh_durfee.sage`-style, LLL + `m`,`t` parameters). Cite Sage version.
4. Parameter discipline: start small `m` (e.g. 3-4), increase only on explicit
   "try higher m/t" signal. Each increment multiplies runtime; cap at 2 attempts.
5. Detection of success: script returns `(x0, y0)` → recompute the RSA relation
   per script docs, then verify `pow(pow(2, e, n), d, n) == 2`. Never assume
   without this round-trip. Two failed `(m,t)` settings with `d` above `n^0.292`
   means declare lattice-blocked and pivot.

### H3 — Franklin-Reiter related-message attack

1. When to attempt: same `n`, same `e` (often `e=3`), two ciphertexts `c1, c2`
   whose plaintexts satisfy a KNOWN affine relation `m2 = a*m1 + b`
   (e.g. counter appended, fixed delta, same message with index suffix).
2. Concept: `gcd(f1(x), f2(x))` over `Z_n[x]` recovers `m1` without factoring,
   where `f1 = x^e - c1`, `f2 = (a*x + b)^e - c2`. Polynomial gcd, no lattice.
3. Precondition: `a, b` must be EXACT (read from challenge source). One wrong
   coefficient means garbage. Confirm by re-encrypting both candidates.
4. Skeleton (pure python + sympy, no Sage needed):

```python
import sympy
n = int(open('n.txt').read().strip(), 0)
e = 3
c1 = int(open('c1.txt').read().strip(), 0)
c2 = int(open('c2.txt').read().strip(), 0)
a, b = 1, 1  # placeholders: replace with measured relation m2 = a*m1 + b
x = sympy.Symbol('x')
P1 = sympy.Poly(x**e - c1, x, domain=f'ZZ[{n}]')
P2 = sympy.Poly((a*x + b)**e - c2, x, domain=f'ZZ[{n}]')
g = P1.gcd(P2)
print(g)
# linear factor gives m1; verify pow(m1, e, n) == c1 before claiming
```

5. Note: sympy quotient-domain gcd can be slow/fragile; Sage
   `gcd(f1, f2)` over `Zmod(n)` is the robust alternative when available.
6. Negative control: random `b'` must NOT yield a linear gcd — if it does, the
   model is wrong (likely different `n` or padded, not affine).

### H4 — Hastad broadcast with CRT across moduli (expanded)

1. When to attempt: same plaintext `m`, small `e` (classically `e=3`), `>= e`
   distinct moduli `n_i` with ciphertexts `c_i = m^e mod n_i`, moduli pairwise
   coprime (check `gcd(n_i, n_j) == 1` for all pairs first).
2. Concept: CRT combines `c_i` into `C = m^e` over the integers
   (`M = prod(n_i) > m^e`), then exact integer `e`-th root recovers `m`.
   No factoring, no lattice. L2 snippet is the reference implementation.
3. Checklist before running L2: count pairs (`len(pairs) >= e`), confirm same
   `m` (same length/shape, challenge says broadcast), confirm coprimality,
   confirm `M.bit_length() > e * m_bits_estimate`.
4. Failure mode: if `M < m^e` (too few ciphertexts), CRT value is still modular
   and `iroot` will not be exact — collect more samples; linear-padded variants
   route to H1/H3 instead, never force the root.

### H5 — ECDSA repeated / hidden nonce (lattice concept + howgrave pattern)

1. Repeated-nonce (no lattice): two sigs `(r, s1)`, `(r, s2)` on hashes `z1, z2`
   share `k`. Then `k = (z1 - z2) * inv(s1 - s2) mod q`,
   `d = (s1*k - z1) * inv(r) mod q`. Confirm `r` bytes identical, `s` differ.
   Pure-python modular arithmetic; always try this BEFORE any lattice.
2. Hidden-nonce / few-bits-leak (lattice): many sigs where top/bottom bits of
   each `k_i` are known or biased (e.g. short nonces, low-bit truncation). This is
   the Boneh-Venkatesan Hidden Number Problem (HNP): recover `d` from
   `k_i + A_i*d + B_i = 0 mod q` samples via a Howgrave-Graham-Smart lattice
   (CVP/SVP solved with LLL/BKZ + Babai nearest-plane).
3. Concept sketch (howgrave pattern): build lattice from `(A_i, q)` rows scaled
   by leak size, target vector from `(B_i + known_k_bits)`; the closest vector
   gives nonce offsets, hence `d`. Needs on the order of 50-100+ signatures for
   small leaks on 256-bit curves; 160-bit curves need fewer. Fewer samples means
   do not attempt the lattice.
4. Practical route: use an existing HNP lattice script (Sage/fplll) rather than
   hand-rolling LLL. Record curve order `q`, leak position (MSB/LSB), leak bits,
   sample count. Verify recovered `d` by checking `d*G == Pub` or one `verify()`.
5. Stop rule: tiny per-nonce leak on a 256-bit curve with few dozen sigs means
   negligible lattice success in CTF time — pivot to fault/reuse or escalate.

### H6 — Padding-oracle full automation loop (byte-at-a-time + retry math)

1. When to attempt: CBC service distinguishes valid vs invalid PKCS#7 padding
   (distinct error strings, status codes, or timing). Confirm in Phase 2 by
   flipping the last byte and observing a SPLIT (one error class changes).
2. Concept: decrypt last block byte-at-a-time from position 15 down to 0.
   For byte `i`, forge suffix `C_prev'[j] = intermediate[j] ^ pad_len` for known
   bytes, iterate `C_prev'[i]` over 0-255 until oracle says valid; then
   `intermediate[i] = guess ^ pad_len`, `plain[i] = intermediate[i] ^ orig_C[i]`.
3. Retry math: each byte costs on average ~128 queries (worst 256). One 16-byte
   block costs ~2048 queries average. Budget
   `queries = blocks * 2048 * margin(1.5)`.
   If the service rate-limits (see Failure Catalog), multiply wall-time by
   `delay_per_query` and re-tier before starting.
4. Automation skeleton (technique-only, adapt oracle function):

```python
import time, random
def oracle(ct: bytes) -> bool:
    # placeholder: return True iff server says padding VALID
    raise NotImplementedError
def decrypt_block(prev: bytes, cur: bytes, bs=16, delay=0.05):
    inter = bytearray(bs)
    plain = bytearray(bs)
    for pad in range(1, bs+1):
        i = bs - pad
        forged = bytearray(bs)
        for j in range(i+1, bs):
            forged[j] = inter[j] ^ pad
        found = None
        for g in range(256):
            forged[i] = g
            if delay:
                time.sleep(delay + random.uniform(0, delay))
            if oracle(bytes(forged) + cur):
                found = g
                break
        assert found is not None, 'byte %d: no valid padding' % i
        inter[i] = found ^ pad
        plain[i] = inter[i] ^ prev[i]
    return bytes(plain)
```

5. Guards: (a) `pad==1` ambiguity — a coincidental trailing valid pad can give a
   false valid; re-confirm by corrupting one more byte. (b) IV is `prev` for
   block 0 — same loop applies. (c) Log every query count; stop if error class
   collapses (service patched/rate-limited).
6. Tool-first rule: prefer the `padbuster` one-liner (tool table) before a
   hand-rolled loop; hand-roll only for custom non-HTTP transports.

### H7 — CBC bitflip target-block algebra

1. When to attempt: CBC with attacker-influenced plaintext block (username,
   role, cookie flag) and a readable/decrypting endpoint — no key needed.
2. Algebra: `P2[i] = D(C1)[i] ^ C1_prev[i]`. Attacker modifies transmitted
   `C1_prev[i]` to steer `P2[i]`:
   `C1_prev_new[i] = C1_prev[i] ^ want[i] ^ orig[i]`.
   Cost: the controlled preceding block decrypts to garbage (accepted trade).
3. Procedure: align target to block boundary (duplicate-block probe), compute
   XOR delta per byte, forge and submit ONCE, confirm via oracle response.
4. IV variant: for block 0, `P0 = D(C0) ^ IV`; forge `IV_new` the same way when
   the IV is transmitted alongside the ciphertext (common in CTF cookies).
5. Negative control: flip a bit in the LAST block and expect padding failure —
   confirms CBC (vs CTR/ECB) before forging.

### H8 — Custom-cipher z3 modeling skeleton

1. When to attempt: bespoke XOR/rotate/add cipher, CRC game, or LCG given as
   Python/source — NOT a standard primitive. If a binary implements it, escalate
   to `/rev` first (see Escalation Triggers); model only once semantics are read.
2. Skeleton (BitVec per word size, add constraints per round, check sat):

```python
from z3 import BitVec, Solver, sat, RotateLeft
s = Solver()
s.set("timeout", 120000)
# model word size EXACTLY (8/16/32/64); wrong width is the top failure
k = BitVec('k', 32)
x = BitVec('x', 32)
# placeholder round relation: replace with real cipher equations
s.add(RotateLeft(x ^ k, 3) == 0x12345678)
# add one constraint per known plaintext/ciphertext pair
assert s.check() == sat
print(hex(s.model()[k].as_long()))
# then re-encrypt in python to confirm before claiming
```

3. Discipline: one `Solver` per hypothesis; cap unrolled rounds; bound solver
   time. UNSAT means the relation is misread — re-read source.

### H9 — PRNG state recovery (Mersenne Twister untwist concept)

1. When to attempt: outputs look like Python `random` (`getrandbits`, `randint`,
   `random()` doubles) or MT19937 in another language; challenge leaks enough
   consecutive 32-bit outputs (on the order of 624) or reconstructible tempered
   values.
2. Concept: MT output is tempered state (shifts/masks/xors); untwisting inverts
   the temper step by step to recover state words, then clone the generator and
   predict all future outputs. No brute force.
3. Procedure: confirm generator from source (statistical guess is LOW confidence);
   map outputs to exact 32-bit tempered words; untemper, rebuild state, CONFIRM
   one predicted output before exploiting. Truncated/merged outputs need z3/H8.
4. Pitfalls: truncated/merged outputs need constraint solving (z3/H8) or more
   samples — do not assume raw words. Truncated LCG is a lattice problem.
5. Validate: prediction must match the next live output EXACTLY before use.

### H10 — Shamir split misuse

1. When to attempt: `n`-of-`m` share tuples `(x, y)` over a prime field, or
   challenges where the service leaks extra shares, reuses `x`, or evaluates
   at `x=0` (the secret).
2. Concept: secret is `f(0)`; with `>= threshold` shares, Lagrange interpolation
   recovers it. Misuse cases: threshold set to 1, duplicate `x` with different
   `y` (leaks inconsistency / allows forgery), unauthenticated shares (attacker
   submits own `x` and gets `f(x)` evaluations).
3. Skeleton (pure python, field prime `p` from challenge):

```python
def lagrange_zero(shares, p):
    # shares = [(x, y), ...]; returns f(0) mod p
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            num = (num * (-xj)) % p
            den = (den * (xi - xj)) % p
        s = (s + yi * num * pow(den, -1, p)) % p
    return s
```

4. Confirm field prime and share count `>= threshold` before interpolating;
   verify against a held-out share.

Reasoning Checkpoint: evidence = named hard-pattern precondition measured (leak bits / sample count / relation coefficients / oracle split) → confidence HIGH/MEDIUM/LOW → proceed to gated Exploit with the single matching lattice/oracle/algebra job or stop if bounds fail.

## Multi-Step Chains (abstract patterns)

Pattern A — e=3 broadcast across 3 keys (decrypt without factoring).
1. Baseline: three `(n_i, c_i)` blobs, `e=3` everywhere, same plaintext length/shape.
2. Confirm: pairwise `gcd(n_i, n_j) == 1`, count `>= 3`, combined modulus large enough.
3. Exploit (one step): CRT-combine (L2) → exact integer cube root → bytes decode.
4. Validate: `pow(m, 3, n_i) == c_i` for all `i`; fresh `solve.py` re-runs L2 only.
5. Stop if root is inexact → missing/duplicate ciphertext, not a solver bug.

Pattern B — ECB cut-paste to CBC bitflip escalation (forge role without key).
1. Baseline: ECB endpoint echoes attacker blocks (duplicate-block probe fires).
2. Confirm: cut a ciphertext block encrypting role-aligned bytes out of
   the ECB response (pad the prefix until duplicates shift to find alignment).
3. Exploit (one step): paste that block (or bitflip-forge per H7) into the CBC
   cookie at the role offset; submit once.
4. Validate: service response changes privilege class; wrong-offset paste must
   fail (negative control) before claiming the path.
5. Stop after one forge batch; do not loop forgeries into an oracle campaign
   without re-tiering (rate-limit risk).

Pattern C — oracle decrypt to forge (padding oracle to valid token).
1. Baseline: CBC cookie + padding-distinguishing endpoint (H6 split confirmed).
2. Confirm: single-block trial decrypt of the LAST block only (bounded queries).
3. Exploit step 1 (gated): full byte-at-a-time loop → recover intermediate bytes.
4. Exploit step 2 (separate gate): CBC-encrypt chosen bytes via
   `forged_prev = intermediate ^ want` (CBC-R technique) → submit forged token.
5. Validate: forged token accepted; random token rejected (negative control).
   Each step is separately gated with its own query budget.

Reasoning Checkpoint: evidence = each link confirmed in order with its own artifact (broadcast set / ECB blocks / oracle bytes) → confidence HIGH/MEDIUM/LOW → advance one link per gate or stop at first unverified link.

## Failure-Mode Catalog + Recovery

| # | Failure (detection) | Recovery (one corrected retry → one alternate) |
|---|---|---|
| F1 | factordb timeout/blocked (`curl` hangs, HTTP 429/403, empty JSON) | ONE retry with backoff; then LOCAL `yafu "factor(n)"` / `sage factor` / non-network RsaCtfTool subset |
| F2 | RsaCtfTool fork flag drift (unknown attack name, usage error) | run `RsaCtfTool --help` on-box; pin working flags + version; fall back to manual L2/L3 script |
| F3 | Sage missing (`sage: command not found`) | pure-python fallback: Wiener sketch (L4), egcd (L3), Hastad (L2), sympy gcd — NO lattice jobs; mark lattice-blocked |
| F4 | oracle rate-limit (429s, growing sleeps, resets mid-loop) | slow + jitter (delay + uniform jitter in H6 loop), shrink to 1 block, checkpoint intermediate bytes; resume, do not restart |
| F5 | wrong endianness in `long_to_bytes` (integer verifies but bytes garbled) | sweep big/little + leading-zero strip on a COPY; confirm with re-encrypt round-trip |
| F6 | padding-oracle false valid (`pad==1` ambiguity) | re-confirm by corrupting adjacent byte; require two consecutive valid signals |
| F7 | lattice job explodes (RAM/time blowup, no output in budget) | kill, record params, retry ONCE with smaller dimension; then mark blocked — never queue unbounded jobs |

Detailed notes:
1. F1 detection: `curl --max-time 20` to factordb returns nothing or HTTP error.
   Recovery order: factordb retry → `yafu` → `sage factor` (only if small `n`) →
   RsaCtfTool non-network attacks. If `n` is 1024b+, factordb failure means pivot
   to protocol attacks, not bigger factoring.
2. F2 detection: exit code 2 + unrecognized-arguments text. Fork names drift
   across versions. Recovery: on-box `--help` is authoritative; never trust
   memorized flag spellings.
3. F3 detection: `which sage` fails. Recovery: run L2/L3/L4 pure-python path and
   record "Sage absent" so the validator does not depend on it.
4. F4 detection: query counter stalls, sleeps grow, TCP resets. Recovery: set a
   0.5-2.0s delay + jitter, single-block scope, persist progress per byte.
   If budget exceeds tier, checkpoint and escalate rather than hammering.
5. F5 detection: recovered integer re-encrypts correctly but decoded bytes are
   garbage. Recovery: endianness/trim sweep; the integer is right, the BYTES
   rendering is wrong — do not re-attack the math.
6. F6/F7 are hard-tier guards: false-valid corrupts the whole suffix after it
   (restart block on detection); lattice blowup is a stop signal, not a retry loop.

Reasoning Checkpoint: evidence = failure signature matched to F1-F7 + recovery command logged → confidence HIGH/MEDIUM/LOW → one corrected retry, one alternate, then blocked.

## Version-Drift Guards

1. RsaCtfTool fork differences: attack names, `--private` semantics, and timeout
   flags vary by fork. On-box `RsaCtfTool --help` output is authoritative; paste
   the first 20 lines into the writeup with the fork version.
2. Sage version APIs: `small_roots` options, polynomial-ring construction, and
   LLL/BKZ defaults change across Sage releases. Log `sage --version`, keep the
   exact call, and note any tuning tried.
3. hashcat mode table re-check: `-m` numbers are stable for common modes but new
   modes appear regularly. Run `hashcat --help | grep -i <algo>` when a mapping
   misses; never assume a mode number from memory for exotic hashes.
4. Library drift (pycryptodome/gmpy2/sympy/z3): inverse helpers, integer-root
   exact-flag semantics, and z3 import paths shift. Pin versions in hard-tier
   writeups; re-run `solve.py` on the validator image before handoff.
5. CLI drift for oracle helpers: subflags vary by install — `--help` on-box
   before any gated run (already an Unverified note; blocking for hard tier).

Reasoning Checkpoint: evidence = on-box `--help`/version output captured for each tool used → confidence HIGH/MEDIUM/LOW → proceed or pin-and-retry on mismatch.

## Time-Budget Tiers

1. Easy (≤15 min): classifier + Magic + hashid/hashcat-top10k OR RsaCtfTool auto.
   Stop with no firing condition → blocked; do not start lattices.
2. Medium (≤45 min): easy + targeted RsaCtfTool subset + one oracle/crib batch
   (single block) + classical sweep. Stop: 3 gated attempts exhausted on the one
   firing hypothesis → blocked.
3. Hard (≤2 h, lattices run long): medium + ONE lattice job (Coppersmith with
   measured bound, or Boneh-Durfee with small `m`, or HNP with enough samples)
   with a long timeout in background while oracle/classical work continues.
   Stop: lattice exceeds budget with no short vectors → kill, record params,
   mark lattice-blocked; do not queue a second lattice without new evidence.
4. Insane (escalate): custom LLL dimensions, tiny HNP leaks with few samples, or
   multi-hour BKZ. Checkpoint artifacts + measured bounds, escalate with the exact
   missing input instead of burning time.
5. Per-tier stop: flag-regex hit (handoff) or `blocked` naming the missing
   precondition — never silent looping.

Reasoning Checkpoint: evidence = elapsed time + tier + attempt count vs budget → confidence HIGH/MEDIUM/LOW → continue, tier-up once with new evidence, or escalate.

## Escalation Triggers

1. Call `/rev` when: custom cipher is compiled/bytecode (not readable source),
   packed/VM logic, or z3 UNSAT twice (needs disassembly, not more constraints).
2. Call `/misc` when: pre-layer is encoding/compression/media (nested archives,
   QR/barcode, audio, image LSB) sitting IN FRONT of the crypto envelope —
   decode the carrier first, then return with clean bytes.
3. Call operator (hard gate) when: factordb-blocked network with no local factor
   path; oracle hard-rate-limits or bans; service restarts change artifacts
   mid-run; any unbounded-brute request. Packet: envelope type, measured params,
   commands + exit codes, exact missing input. Keep solving unblocked work.

Reasoning Checkpoint: evidence = trigger condition named (binary carrier / pre-layer / hard gate) + packet fields filled → confidence HIGH/MEDIUM/LOW → escalate and continue unblocked work.

## Worked End-to-End Example (abstract, generic RSA — technique only)

> No real flags. Generic envelope shapes only. Replace placeholders with measured values.

1. Challenge shape: directory with a public key file + one ciphertext bigint file.
   Goal: recover message bytes matching a generic `flag\{[^}]+\}` regex.
2. Baseline: `file` says PEM; `openssl -text -noout` shows a common `e`;
   `n` measures 1024 bits; single ciphertext; no duplicate blocks (not ECB).
3. Confirmation: key-dump echoes `n/e`; `gcd(c, n) == 1`; Wiener precondition
   fails (no small-`d` hint) → route to auto-attack, not Wiener.
4. Negative: alter one digit of `c` → decrypt must fail/garbage; base64-decode
   of the decimal blob must fail; Wiener flags must yield no key (expected).
5. Exploit (gated, ≤120s): `RsaCtfTool --publickey key.pub --private` with timeout
   writes recovered key material to a NEW file; render the integer with
   `long_to_bytes` (endianness check per F5).
6. Validation-handoff: `solve.py` reads key + ciphertext files, re-runs the
   same two commands, asserts the output matches the generic flag regex, logs
   tool versions + attempt count. Flag value stays local.

Reasoning Checkpoint: evidence = solve.py re-derives regex-matching bytes from artifacts alone on a fresh run → confidence HIGH → handoff; else re-baseline.

## Writeup-Distilled Patterns (W1..W60)

> Mined 2026-10-15 from 453 crypto CTF writeups
> (`knowledge/writeups_mined/crypto_manifest.md`) + R2 2026-10-16 from 459 NEW hard writeups
> (`knowledge/writeups_mined/crypto_manifest_r2.md`, 0% overlap). Each pattern below is NEW relative to
> H1-H10/L1-L11: a variant condition, a chained combo, or an operational discipline the base
> skill does not spell out. Format: name → mathematical condition → exact attack steps →
> Sage/python snippet → pitfalls → 2-3 source URLs. Technique-only, no flags.
> W1-W12 inline here; W13-W30 in `techniques/writeup-patterns-1.md`;
> W31-W40 in `techniques/writeup-patterns-r2-1.md`, W41-W50 in `techniques/writeup-patterns-r2-2.md`,
> W51-W60 in `techniques/writeup-patterns-r2-3.md`. Spill rule: if this
> file exceeds 1100 lines, move the highest-W block to `techniques/writeup-patterns-N.md`
> and leave the index row pointing at it.

| ID | Pattern | File |
|---|---|---|
| W1 | Bivariate Coppersmith: p+q MSB leak + small-d relation | SKILL.md |
| W2 | Multivariate Coppersmith: dinv MSB + p+q MSB hints | SKILL.md |
| W3 | Linear-padded broadcast unblinding (e=3, multiply-by-r) | SKILL.md |
| W4 | Small-message direct e-th root (m^e < n, no CRT) | SKILL.md |
| W5 | Stereotyped-message suffix-length sweep | SKILL.md |
| W6 | Short-pad difference chained into Franklin-Reiter | SKILL.md |
| W7 | Wiener near-miss ladder into Boneh-Durfee (+ multi-prime) | SKILL.md |
| W8 | Bleichenbacher single-interval fast path + trimmers | SKILL.md |
| W9 | Manger vs Bleichenbacher oracle triage | SKILL.md |
| W10 | LSB/parity RSA oracle binary-search decrypt | SKILL.md |
| W11 | Bellcore CRT-fault factor via gcd | SKILL.md |
| W12 | Smooth-group factoring triage (p-1 / p+1 / Fermat gap) | SKILL.md |
| W13 | HNP lattice with K-scaling + sample-count rule | techniques/writeup-patterns-1.md |
| W14 | ECDSA polynomial-nonce recurrence elimination | techniques/writeup-patterns-1.md |
| W15 | Crafted nonce-collision reuse | techniques/writeup-patterns-1.md |
| W16 | Anomalous-curve Smart attack | techniques/writeup-patterns-1.md |
| W17 | DSA/DH parameter-tampering checklist | techniques/writeup-patterns-1.md |
| W18 | ElGamal/DH small-subgroup confinement + Lim-Lee | techniques/writeup-patterns-1.md |
| W19 | CBC-R encrypt-via-decrypt-oracle | techniques/writeup-patterns-1.md |
| W20 | CBC-MAC concatenation forgery | techniques/writeup-patterns-1.md |
| W21 | GCM GHASH forgery under nonce reuse | techniques/writeup-patterns-1.md |
| W22 | Hash length-extension keylen differential | techniques/writeup-patterns-1.md |
| W23 | JWT triage ladder (none → HMAC → kid → jku/x5u) | techniques/writeup-patterns-1.md |
| W24 | CTR malleability forge without oracle | techniques/writeup-patterns-1.md |
| W25 | MT backward-twist previous-state recovery | techniques/writeup-patterns-1.md |
| W26 | Symbolic MT solver for truncated outputs | techniques/writeup-patterns-1.md |
| W27 | Seed-vs-clone decision | techniques/writeup-patterns-1.md |
| W28 | Truncated-LCG lattice recovery | techniques/writeup-patterns-1.md |
| W29 | Shamir misuse recipes | techniques/writeup-patterns-1.md |
| W30 | Generalized-GM/Paillier modified-BD decrypt | techniques/writeup-patterns-1.md |
| W31 | Coppersmith univariate refinement (epsilon/X re-tier) | techniques/writeup-patterns-r2-1.md |
| W32 | Bivariate Herrmann-May with dinv shift (background) | techniques/writeup-patterns-r2-1.md |
| W33 | HNP refinement (BKZ/Babai fallback, MSB/LSB flip) | techniques/writeup-patterns-r2-1.md |
| W34 | ECDSA GLV / invalid-curve small-order CRT | techniques/writeup-patterns-r2-1.md |
| W35 | Twist attack on single-coordinate ladder | techniques/writeup-patterns-r2-1.md |
| W36 | Singular-curve nodal/cuspidal reduction | techniques/writeup-patterns-r2-1.md |
| W37 | Bleichenbacher automation diary (trimmers+budget) | techniques/writeup-patterns-r2-1.md |
| W38 | Manger length-oracle refinement (~1100 queries) | techniques/writeup-patterns-r2-1.md |
| W39 | LSB/parity oracle binary search (calibrated) | techniques/writeup-patterns-r2-1.md |
| W40 | CBC padding-oracle diary + CBC-R forge | techniques/writeup-patterns-r2-1.md |
| W41 | GCM GHASH root recovery (reflection+3rd-sample) | techniques/writeup-patterns-r2-2.md |
| W42 | GCM keystream crib-drag diary (offset-aware) | techniques/writeup-patterns-r2-2.md |
| W43 | Hash combiner (chosen-prefix + SHA-0 weakness) | techniques/writeup-patterns-r2-2.md |
| W44 | PQ-adjacent LWE decoding (Kannan embedding) | techniques/writeup-patterns-r2-2.md |
| W45 | ChaCha reduced-round / stream-reuse slice | techniques/writeup-patterns-r2-2.md |
| W46 | RC4 stack-state reversal (reverse PRGA) | techniques/writeup-patterns-r2-2.md |
| W47 | xorshift128+ V8/Node (z3 + NaN-collapse) | techniques/writeup-patterns-r2-2.md |
| W48 | Truncated-LCG cascade (Hensel + geometric-sum) | techniques/writeup-patterns-r2-2.md |
| W49 | Go/Python random (seed-first + init inversion) | techniques/writeup-patterns-r2-2.md |
| W50 | Shamir misuse (x=0/dup-x/threshold-1/subgroup) | techniques/writeup-patterns-r2-2.md |
| W51 | Noisy Shamir Groebner + CRT reassembly | techniques/writeup-patterns-r2-3.md |
| W52 | Custom Feistel differential (structures + peel) | techniques/writeup-patterns-r2-3.md |
| W53 | Custom SPN differential + Groebner fallback | techniques/writeup-patterns-r2-3.md |
| W54 | RSA smooth-group triage (Fermat/p-1/p+1/ECM) | techniques/writeup-patterns-r2-3.md |
| W55 | Franklin-Reiter chained from short-pad (2-gate) | techniques/writeup-patterns-r2-3.md |
| W56 | CTR malleability + Poly1305 r/s reuse | techniques/writeup-patterns-r2-3.md |
| W57 | DSA/DH tampering + Lim-Lee static-key CRT | techniques/writeup-patterns-r2-3.md |
| W58 | Low-density knapsack LLL | techniques/writeup-patterns-r2-3.md |
| W59 | ECDSA polynomial-nonce (ECLCG lattice) | techniques/writeup-patterns-r2-3.md |
| W60 | Linear-padded broadcast unblinding (exact-r) | techniques/writeup-patterns-r2-3.md |

### W1 — Bivariate Coppersmith: p+q MSB leak + small-d relation
- Condition: RSA with `d <= N^0.35`-scale (above Wiener, near BD bound) AND top bits of
  `p+q` leaked as `hint = (p+q) >> b`. Stock `boneh_durfee.sage` fails (wrong equation).
- Steps: 1. Write `ed = 1 + k(N-p-q+1)`, reduce mod `e`:
  `f(x,y) = 1 + 2x((N+1)/2 - (hint*2^b + y)/2) = 0 (mod e)` with `x = k`, `y` = low bits
  of `p+q`. 2. Bounds `(N^0.35, 2^b)`; solve with `lbc small_roots` resultants `m = d = 6`
  + flatter. 3. `d = f(solx,soly)/e` over integers; verify `pow(pow(2,e,n),d,n) == 2`.
- Snippet: ```python
  P, (x, y) = PolynomialRing(ZZ, 2).objgens()
  f = 1 + 2*x*((N+1)//2 - (hint*2**b + y)//2)
  roots = small_roots(f.change_ring(Zmod(e)), (ZZ(N**0.35), 2**b), m=6, d=6,
                      algorithm='resultants', lattice_reduction=flatter)
  ```
- Pitfalls: integer division by 2 needs `N` odd handling (use exact `//` only on even
  terms or rational ring); `k`-bound from `e`-size assumption fails if `e` small —
  this pattern needs `e ~ N`; one `(m,d)` setting only, then re-derive bounds.
- Sources: https://zukane.github.io/connorsmith/ ,
  https://github.com/josephsurin/lattice-based-cryptanalysis , https://ctftime.org/writeup/37439

### W2 — Multivariate Coppersmith: dinv MSB + p+q MSB hints
- Condition: two hints — top bits of `dinv = d^-1 mod N` (`h`) and top bits of `p+q`
  (`hpq`), same shift `z`; `e` known. Two unknowns `x, y` plus multiplier `k`.
- Steps: 1. Build `f(k,x,y) = (1 + k(N+1-((hpq<<z)+y)))((h<<z)+x) - e = 0 (mod N)`.
  2. Bounds `(e, 2^z, 2^z)`; `coppersmith_multivariate_heuristic` (kiona). 3. Recover
  `d = inv((h<<z)+x0, n)`; decrypt and verify prefix structure.
- Snippet: ```python
  P, (k, x, y) = PolynomialRing(Zmod(n), 3).objgens()
  f = (1 + k*(n+1-((hpq << z)+y)))*((h << z)+x) - e
  roots = coppersmith_multivariate_heuristic(f, (e, 2**z, 2**z), 1.0)
  ```
- Pitfalls: `k`-bound `e` assumes `d ~= phi` scale — verify `bits(d recovered)` sane;
  trivariate lattices are the slowest tier — background it, keep solving other links;
  shift `z` off-by-one kills all roots — recompute from hint bit-lengths, never guess.
- Sources: https://zukane.github.io/that-one-rsa-challenge/ ,
  https://ctftime.org/writeup/22997 , https://ctftime.org/writeup/17265

### W3 — Linear-padded broadcast unblinding (e=3, multiply-by-r)
- Condition: `e = 3`, ciphertexts of the form `c = (m*r)^3` or `(m*256^t + pad)^3` where
  the blinding structure `r` (geometric sum, power of 256) is computable from the source.
- Steps: 1. Reconstruct `r` exactly (e.g. `r2 = sum(256^(18i))`, `k = prod` terms mod n).
  2. Unblind: `m^3 = c * r^-3 mod n`. 3. Integer cube root + bytes decode; each part
  verified by re-encrypt before concatenation.
- Snippet: ```python
  m3_cubed = c * pow(r, -3, n) % n
  m, exact = gmpy2.iroot(m3_cubed, 3)
  assert exact
  ```
- Pitfalls: `r` must be computed mod `n` with the challenge's exact summation bounds
  (off-by-one term = garbage root); `pow(r,-3,n)` needs `gcd(r,n) == 1` — check first.
- Sources: https://ctftime.org/writeup/39894 , https://ctftime.org/writeup/39890 ,
  https://ctftime.org/writeup/9601

### W4 — Small-message direct e-th root (m^e < n, no CRT needed)
- Condition: `e = 3`, single `(n, c)`, message short enough that `m^e < n`
  (no modular wrap); FIRST check before any broadcast machinery.
- Steps: 1. `m, exact = iroot(c, e)`; if exact, decode bytes. 2. Detect trap: decoded
  bytes may be little-endian (Broken Invitation needed `[::-1]`) — test both orders
  against re-encrypt. 3. Only if inexact, escalate to broadcast/Coppersmith.
- Snippet: ```python
  import gmpy2
  from Crypto.Util.number import long_to_bytes
  m, exact = gmpy2.iroot(c, 3)
  for b in (long_to_bytes(m), long_to_bytes(m)[::-1]):
      if pow(int.from_bytes(b[::-1] if b == long_to_bytes(m)[::-1] else b, 'big'), 3, n) == c:
          print(b); break
  ```
- Pitfalls: exact root but garbled bytes = endianness (F5), not failed math — sweep
  orders instead of re-attacking; short-message check costs one line — never skip it.
- Sources: https://ctftime.org/writeup/39890 , https://ctftime.org/writeup/23939 ,
  https://blog.kleinebu.de/rsa.html

### W5 — Stereotyped-message suffix-length sweep
- Condition: H1-shape (known prefix, e.g. flag format) but unknown total length:
  `m = prefix || x || suffix` with `|x|` unknown; single small-e ciphertext.
- Steps: 1. Loop candidate unknown-length `i` in `range(0, 100)`; build
  `f_i(x) = (prefix_int(i) + x)^e - c`. 2. `small_roots` per `i`; printable-decode
  every root. 3. Correct `i` yields structured bytes — verify by re-encrypt.
- Snippet: ```python
  for i in range(100):
      m = bytes_to_long(prfx + b'\x00'*i + b'}')
      P, x = PolynomialRing(Zmod(n), 'x').objgens()
      for r in ((m + x)**e - ct).small_roots(epsilon=1/30):
          print(i, long_to_bytes((m + int(r)) % n))
  ```
- Pitfalls: bound `X` must match the CURRENT `i` (stale `X` = missed roots);
  epsilon `1/30` is a starting value, not gospel — retry `1/15` once on near-miss.
- Sources: https://nightxade.github.io/ctf-writeups/writeups/2024/squ1rrel-CTF-2024/crypto/partial-rsa.html ,
  https://ctftime.org/writeup/26407 , https://ctftime.org/writeup/20858

### W6 — Short-pad difference chained into Franklin-Reiter
- Condition: two ciphertexts under same `(n, e)` whose plaintexts differ by a SHORT
  unknown pad (e.g. one MD5-derived 16-byte suffix); direct FR impossible (diff unknown).
- Steps: 1. Coppersmith short-pad attack with `X = 2^padbits` to recover `diff`.
  2. Feed `diff` as the affine constant into Franklin-Reiter poly-gcd (H3).
  3. Verify both residues; wrong `X` (pad length) is the usual failure — it is measurable.
- Snippet: ```python
  h = (x + known_pad_poly)**e - c1          # small_roots(X=2**128) -> diff
  g1 = x**e - c1; g2 = (x + diff)**e - c2   # Franklin-Reiter gcd -> m
  ```
- Pitfalls: two lattices/oracles in series = two gates with separate budgets; a failed
  FR after a good diff means the affine model is wrong (multiplicative pad, not additive).
- Sources: https://ctftime.org/writeup/21154 , https://ctftime.org/writeup/20024 ,
  https://ctftime.org/writeup/26281

### W7 — Wiener near-miss ladder into Boneh-Durfee (+ multi-prime)
- Condition: `e ~ n` (large), Wiener fails, but challenge hints small `d`
  (fast-decrypt comment, `d` size equations, or `d = next_prime(n^0.2919)`-style
  generation giving `d` just above Wiener range).
- Steps: 1. Run Wiener (RsaCtfTool + L4 sketch); on fail record convergents tried.
  2. Escalate to `boneh_durfee.sage` starting `delta = 0.27, m = 5`, then `0.23/7`,
  `0.28/12` (two attempts max). 3. Multi-prime RSA: same ladder with the extended
  script; verify via `pow(2, e*d?, ...)` round-trip per script docs.
- Snippet: ```bash
  timeout 600 sage boneh_durfee.sage   # edit N, e, delta, m in-script; log version
  ```
- Pitfalls: delta above 0.292 is never valid — larger delta wastes the run; `m`
  increments multiply LLL time — cap 2 attempts, then lattice-blocked; generated-`d`
  challenges (Insights) may need NO attack (recompute `d` from the generation line).
- Sources: https://ctftime.org/writeup/22738 , https://ctftime.org/writeup/31143 ,
  https://ctftime.org/writeup/37439

### W8 — Bleichenbacher single-interval fast path + trimmers
- Condition: PKCS#1 v1.5 validity oracle over small/medium key (384-bit lab keys skip
  step-2b entirely); standard interval attack otherwise.
- Steps: 1. Blind only if target `c` is not already conforming. 2. Skip to step-2c
  single-interval jump search (`r_i >= 2(b*s-2B)/n` formula) — never linear-scan 2b.
  3. Optional trimmers: multiply by fractional `(u/t)` approximants to shrink `M0`
  before the first search. 4. Narrow to one point; unblind with `s0^-1`.
- Snippet: ```python
  B = 2**(8*(k-2)); M = [(2*B, 3*B-1)]
  s = (n + 3*B - 1)//(3*B)   # first search start; then step-2c jumps only
  ```
- Pitfalls: oracle counts in the hundreds of thousands for 1024-bit keys — budget
  queries × delay before starting; error-string vs timing oracles need separate
  calibration runs; OAEP on the SAME key does not save v1.5 (attack still applies).
- Sources: https://id0-rsa.pub/problem/14/ ,
  https://alexdowad.github.io/understanding-bleichenbackers-crypto98-rsa-attack/ ,
  https://haind03.github.io/posts/crypto-6-5-rsa-padding-pkcs1-bleichenbacher-oaep/

### W9 — Manger vs Bleichenbacher oracle triage
- Condition: RSA oracle leaks something OTHER than strict padding-validity — e.g. the
  BYTE LENGTH of the decrypted message (Manger shape) rather than a yes/no pad check.
- Steps: 1. Classify the leak: valid/invalid bit → Bleichenbacher (W8); length/integer
  size → Manger attack (interval from `2^(8(L-1)) <= m*s mod n < 2^(8L)`).
  2. Run the matching script (Vozec tool supports both framings); ~1100 queries and
  minutes is normal for Manger on CTF keys. 3. Strip padding AFTER single-value
  convergence, not during.
- Snippet: ```python
  # Manger interval per query L: lo, hi = 2**(8*(L-1)), 2**(8*L)-1
  # same multiply-by-s^e lever as Bleichenbacher, different interval math
  ```
- Pitfalls: running Bleichenbacher code against a length oracle converges nowhere —
  triage FIRST with 3-5 probe queries; length oracles are noisier — majority-vote
  each measurement before narrowing.
- Sources: https://platypwnies.de/writeups/2021/htb-uni-quals/crypto/oracle-leaks/ ,
  https://github.com/Vozec/RSA-Padding-Oracle , https://www.dsi.unive.it/~focardi/RSA-padding-oracle/

### W10 — LSB/parity RSA oracle binary-search decrypt
- Condition: oracle leaks one BIT of `m*s mod n` per query (parity/LSB, or interval
  membership); works even on unpadded textbook RSA.
- Steps: 1. Start interval `[0, n)`. 2. Per bit: query `c*2^e` (halving step), narrow
  to lower/upper half by oracle answer. 3. After `n_bits` queries read `m` directly;
  verify by re-encrypt.
- Snippet: ```python
  lo, hi = 0, n
  for _ in range(n.bit_length()):
      c2 = c * pow(2, e, n) % n   # probe bit via parity oracle
      lo, hi = (lo, (lo+hi)//2) if oracle(c2) == 0 else ((lo+hi)//2, hi)
  ```
- Pitfalls: needs EXACTLY `n_bits` sequential queries — rate limits kill it (re-tier
  per F4); multiplier must be invertible mod `n` (`gcd(2,n) == 1` for odd `n` — fine);
  MSB-vs-LSB direction confusion inverts every bit — calibrate on a known plaintext.
- Sources: https://www.dsi.unive.it/~focardi/RSA-padding-oracle/ ,
  https://ctftime.org/writeup/36010 , https://ctftime.org/writeup/36011

### W11 — Bellcore CRT-fault factor via gcd
- Condition: RSA-CRT signing oracle (or fault-injection endpoint) returns a signature
  computed with ONE faulty CRT half (`sp` correct / `sq` faulty or vice versa).
- Steps: 1. Collect one correct `(s)` and one faulty `(s')` signature of the same
  message. 2. `p = gcd(s^e - m, n)` (or `gcd(s - s', n)`); factor found without any
  lattice. 3. Confirm `n % p == 0`, decrypt all ciphertexts.
- Snippet: ```python
  import math
  p = math.gcd(pow(s_faulty, e, n) - m, n)
  assert n % p == 0
  ```
- Pitfalls: needs same-message pair — mismatched messages give `gcd == 1` (collect
  again, don't re-attack); some oracles randomize padding per query (fault model void —
  confirm deterministic signing first); verify which factor before labeling `p`/`q`.
- Sources: https://ctftime.org/writeup/17137 , https://ctftime.org/writeup/23495 ,
  https://ctftime.org/writeup/20849

### W12 — Smooth-group factoring triage (p-1 / p+1 / Fermat gap)
- Condition: `n` with one prime having smooth `p-1` (or `p+1`), or `|p-q|` tiny
  (Fermat); `n` up to 1024+ bits still falls — factoring is NOT only for small `n`.
- Steps: 1. `isqrt` gap check (Fermat path, seconds). 2. Pollard `p-1` with smoothness
  bound `B` escalating `1e5 → 1e6` (yafu `factor(n)` or RsaCtfTool pollard attack).
  3. Williams `p+1` if `p-1` fails but structure hints smoothness. 4. Confirm factor by
  division, then standard decrypt.
- Snippet: ```bash
  timeout 120 yafu "factor(<n>)"                       # tries p-1/p+1/rho/ECM pipeline
  timeout 120 RsaCtfTool --publickey key.pub --attack fermat,pollard_p_1 --private
  ```
- Pitfalls: ECM phase dominates wall-time — bound it (this is a medium-tier job, not a
  background lattice); smooth challenges often pair with multi-prime (`too many
  primes`) — after first factor, trial-divide the cofactor before re-running ECM.
- Sources: https://ctftime.org/writeup/40685 , https://ctftime.org/writeup/32914 ,
  https://ctftime.org/writeup/40360

Reasoning Checkpoint: evidence = named W-pattern precondition measured (leak bits / sample count / relation coefficients / oracle split / smoothness bound) → confidence HIGH/MEDIUM/LOW → proceed to gated Exploit with the single matching W-pattern job or stop if bounds fail.

## EASY-FIRST ladder (2026 training refresh — run BEFORE any W-pattern, ≤20 min)
1. `file` + lengths: 32-hex=MD5, 40=SHA1, 64=SHA256; trailing `=`=base family → CyberChef Magic depth-3, loop until `flag{` (strip `b''` wrappers between rounds).
2. RSA: e∈{3,5,17} + small m → `gmpy2.iroot(c,e)` (never float `**(1/e)`); 2+ moduli → `math.gcd` pairwise; same n + two e → common-modulus EGCD (handle negative exponents via modular inverse); huge e → Wiener; else `RsaCtfTool` + FactorDB.
3. AES: duplicate 16B blocks → ECB (map equal blocks; PNG → recolor); decrypt-oracle → `pt[i] = Dec(ct[i]) ⊕ ct[i-1]`.
4. Hash prompt: crackable → `hashcat -m0/100/1400 rockyou` or crackstation; `MD5(secret||msg)` + extension param → `hash_extender`, never crack.
5. JWT cookie → `alg:none` + empty 3rd segment first; then weak secrets (`1234`,`secret`); then `kid` confusion.
6. `import random` + outputs → collect 624 full 32-bit ints → RandCrack; `srand(time)` → libc-time brute ±2s.

## R4 field patterns (browser-swarm 2026 — from 387 new writeups)
- Even-N RSA: `p=2` instantly — never launch factordb on an even modulus.
- `e^2 | (p-1)` → `nth_root`, not `iroot`; e=3 + 512-bit script output → cube analysis.
- Winternitz OTS reuse: walk the second hash chain to invert missing links (zero-checksum messages only).
- ECDSA psychic (`CVE-2022-21449`): scan for `r=0` before any lattice; simple identical-r → `k=(z1-z2)/(s1-s2)`.
- JWT kid-as-path: `../../dev/null` + null-byte HMAC; jku → host attacker JWK set on exploit server.
- JPEG Comment PEM: `exiftool -Comment | xxd -r -p` → `rsautl -decrypt` (StegoRSA class).

Deep-read bodies (13 complete articles): techniques/r5-deep-reads.md.
