# R5 deep reads — mobile (7 complete articles, browser-read 2026-10-17)


## Mobile 1. MHL Strings (deep-link bootstrap)
- READ: Activity2 decrypts `bqGrDKdQ8zo26HflRsGvVA==` (AES/CBC/PKCS5, key `your_secret_key_…`, IV `1234567890123456`) → `mhl_secret_1337`; Activity2 exits unless date gate passes.
- CHAIN: apktool + jadx find `KLOW()`+Activity2 → Frida call `KLOW()` to force gate → `adb shell am start -a VIEW -d "mhl://labs/<b64>"` → objection/`Memory.scan(libflag.so,"4D 48 4C 7B")`.
- GOTCHA: Activity exits without bootstrap; force `KLOW()` via Frida BEFORE firing intent.
- REUSE: Exported activity + deep-link + hidden bootstrap = Frida-drive state, fire intent, scan memory.

## Mobile 2. MHL ConfigEditor (SnakeYAML RCE)
- READ: `loadYaml()` = SnakeYAML `yaml.load(inputStream)` + in-app gadget `LegacyCommandUtil{ Runtime.exec(command) }` (CVE-2022-1471 shape).
- CHAIN: Host `exploit: !!com.mobilehackinglab.configeditor.LegacyCommandUtil ["touch /sdcard/…"]` → deep-link VIEW to attack URL → verify exec.
- GOTCHA: Public `ScriptEngineManager` PoC absent on Android; use in-app gadget class.
- REUSE: `yaml.load()` on untrusted URI + exported VIEW = `!!<app-class> [cmd]` deserialization RCE.

## Mobile 3. MHL SecureNotes (provider brute force)
- READ: Exported `SecretDataProvider` (`content://…secretprovider`) expects `pin=NNNN`; PIN `2580` returns flag.
- CHAIN: jadx confirm `query(selection="pin=")`→`decryptSecret()` → adb loop `{0000..9999}` or in-app ThreadPool/coroutine brute checking `Secret` column.
- GOTCHA: Single-thread adb brute takes hours + API30+ needs `<queries>` manifest entry; 60-thread/coroutine + manifest fix.
- REUSE: Exported provider with `selection` key + no rate-limit = enumerate via adb, automate in-app.

## Mobile 4. Frida-Labs (ladder)
- READ: DERE-ad2001 repo (1.3k stars): 0x1 method-hook through 0xB patching via X86Writer/ARM64Writer, APK+solution per folder.
- CHAIN: `frida-ps -U; adb push frida-server; frida -U -f <pkg> -l solve.js` with `Java.use().implementation`, `Java.choose()`, `$new()`, `Interceptor.attach(…ExportByName…)` + `retval.replace()`.
- GOTCHA: Native overloads/ctors `$init` fail on wrong signature; enumerate `overloads`, hook `.overload('java.lang.String')`.
- REUSE: Frida ladder: hook → call static → set field → new instance → hook ctor → hook native → call native → patch writer.

## Mobile 5. MSTG Crackmes (standard loop)
- READ: OWASP mastg `Crackmes/` points at mas.owasp.org UnCrackable apps used as MASTG examples (binaries + docs, no writeups in repo).
- CHAIN: clone → jadx → adb install → frida/objection anti-tamper bypass (`android root disable`, hook `a()`/`verify()`) → extract → patch-and-resign loop.
- GOTCHA: Repo holds no solutions; combine MASTG theory chapters + community writeups per level.
- REUSE: Standard crackmes: manifest → jadx string hunt → Frida anti-tamper bypass → patch-and-resign.

## Mobile 6. HTB APKey (patch, don't crack)
- READ: `MainActivity$onClick` checks user `admin` + MD5(password)==hash, then `Toast(decrypt())` shows flag.
- CHAIN: jadx `Wrong Credentials!` → apktool → replace hash with MD5(admin) or flip `if-eqz→if-nez` → `apktool b; zipalign -p 4; apksigner; adb install` → login; OR Frida override `onClick` to call decryptors directly.
- GOTCHA: Hash uncrackable + `Failure -124 resources.arsc` alignment error; patch + `zipalign` BEFORE `apksigner`.
- REUSE: Hardcoded user + unsalted hash = patch comparison or directly invoke post-auth decryptors via Frida.

## Mobile 7. HTB cryptohorrific (iOS plist + CCCrypt)
- READ: `challenge.plist` base64 blob; Ghidra shows `CCCrypt` + cfstrings key `!A%D*G-KaPdSgVkY` / IV `QfTjWnZq4t7w!z%C`.
- CHAIN: `unzip; strings challenge.plist` → Ghidra `key/IV/CCCrypt` xref → offline AES decrypt (devglan tool) with key+IV+CBC/PKCS7 on base64.
- GOTCHA: One popular article is generic fluff, not the iOS solution; use the `CCCrypt`+plist path.
- REUSE: plist `strings` + `CCCrypt` xref = pull embedded key/IV, offline decrypt, no web-attack.

- READ: Vault holds 1M DVT; `flashLoan` reverts `InvalidBalance` if `convertToShares(totalSupply)!=balanceBefore`.
- CHAIN: `token.transfer(vault,123)` from small balance → balance skew → all future flashloans DOS.
- GOTCHA: Equality (not shares) accounting; any direct donation breaks invariant; fix = internal shares/virtual offset.
- REUSE: Strict `balance==totalSupply` + permissionless `transfer()` = donate-to-DOS.

- READ: Pool 1000 ETH checks balance-not-decreased but `deposit()` credits `balances[msg.sender]` for same ETH.
- CHAIN: Attacker contract `flashLoan(1000)` → `execute(){pool.deposit{value}()}` → `withdraw()` → send to recovery; needs `receive() payable`.
- GOTCHA: EOA can't borrow (needs `IFlashLoanEtherReceiver.execute`); attacker contract required.
- REUSE: Balance-check repayment + deposit-counts-as-repay = borrow-deposit-withdraw drain.

- READ: SunWeb3Sec 1415-line writeup: naive-receiver needs `multicall+BasicForwarder`; truster `target.functionCall(data)`; selfie `delegate+queue+execute`.
- CHAIN: Unstoppable transfer-1; Naive 10× loans batched via `multicall` + meta-tx spoofing `_msgSender`; Truster approve+transferFrom; SideEntrance one-tx triple.
- GOTCHA: Naive requires `nonce<=2`, so 10 loans must batch; single `multicall` + meta-tx.
- REUSE: Bundle privileged calls into `multicall`/forwarder to satisfy nonce/single-tx gates.

- READ: Drain-to-1%-TVL flag via `MintVars memory v` aliasing `amounts[]` after `malloc` overflow of `0x40`.
- CHAIN: Swap pool to DAI-only → buy amounts encoding huge len → overflow free-ptr → `mint(amounts)` writes supply/norm slots → huge `amountToMint` → `burn` below 1% TVL.
- GOTCHA: Loop clobbers payload + recomputes mint; choose balances surviving 4 iterations, target first three slots.
- REUSE: `struct mem + dynamic array arg` = test ABI offset/length overflow for memory aliasing.

- READ: Peking Duk backstage pass; sKRW 1000× paper profit; Harvest 33M; defenses TWAP/speed-bump/M-of-N.
- CHAIN: Flashloan-buy to push price 400→1733 → borrow max vs inflated collateral → reverse trade → keep undercollateralized profit.
- GOTCHA: In-tx spot is atomically manipulable; require TWAP, 1-block enter/exit delay, or actual swap (not quote).
- REUSE: Same-tx `price=reserve-ratio/balanceOf` = attacker-controlled; require time-average or settlement.

- READ: Hashmasks `_safeMint` loop reenters to mint 39 vs max 20; ENS `_doSafeTransferAcceptanceCheck` lets attacker unwrap before ownership check.
- CHAIN: `onERC721Received/onERC1155Received(){ mint again / unwrap+setResolver }` then return to complete outer call owning underlying.
- GOTCHA: `safe*` = receiver-safe, NOT reentrancy-safe; fix checks-effects-interactions + nonReentrant.
- REUSE: Every `safeMint/safeTransfer` callback = untrusted reentry; own-then-verify order is exploitable.

- READ: Nov 2025 >$100M over 9 chains from Stable-Math rounding-direction error (flagged 2021, TOB-BALANCER-004).
- CHAIN: `echidna/roundme` find 1-wei user-favoring loss → low-liquidity Composable Stable Pool → repeat small-profit swaps to drain.
- GOTCHA: "Rounding favors protocol" misses multi-op flows; per-op invariant + unit + mutation + fuzz + formal verification.
- REUSE: After any arithmetic hack, add rounding-direction invariants to fuzzer; re-run on every dependency upgrade.

- READ: Feb 2025 $1.5B multisig cold-wallet theft (TraderTraitor) after WazirX/Radiant; compromised signer devices showing fake Safe UI.
- CHAIN: Spear-phish treasury/devs → backdoor persist → spoof Safe UI → collect threshold sigs → sweep.
- GOTCHA: Multisig/hardware fails when all signers see the same lie; air-gapped signing + independent verifier + war-games.
- REUSE: High-value ops assume endpoint compromise; out-of-band verification + segmentation over more signatures.
