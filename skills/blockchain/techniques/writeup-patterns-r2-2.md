
# Writeup Patterns R2-2 — Vyper / Cairo / Solana / Move / FV-Escape (W47–W62)

Companion to `../SKILL.md` section `## Writeup-Distilled Patterns`.
Technique-only: local Anvil/fork shapes, no real addresses, no flags/keys.
Source URLs below are all indexed in `knowledge/writeups_mined/blockchain_manifest_r2.md`.
Each entry: signals → steps → snippet → pitfalls → sources.

## W47. Vyper `@nonreentrant` slot-alias failure

- Signals: Vyper 0.2.15/0.2.16/0.3.0; `@nonreentrant('lock')` on add/remove-liquidity pair; ETH-transfer callback path (`raw_call` with value).
- Steps: 1. pin compiler version; 2. flash-borrow base; 3. `remove_liquidity` to trigger fallback; 4. reenter `add_liquidity` inside fallback; 5. repay flash, keep spread.
- Snippet: `def __default__(): log Add; self.internal_add() # reentry: lock slot aliased, no revert`
- Pitfall: fixed in 0.3.1+; `grep` the compiled IR for the lock slot — same-key cross-function locks alias, different-key locks may hold.
- Sources: [Vyper/incident-analysis](https://www.certik.com/blog/vyper-incident-anaylsis), [Vyper/reentrancy-0day](https://highlandsecurity.substack.com/p/post-mortem-vyper-reentrancy-0-day), [Vyper/59m-losses](https://www.chaincatcher.com/en/article/2098263)

## W48. Vyper `concat` zero-overwrite (compiler bug as CTF primitive)

- Signals: Vyper contract calling `concat()` in one function while a sibling reads freshly-declared locals; health/battle math on signed values.
- Steps: 1. trigger `concat` path first; 2. reenter the reader so leading bytes of its first local are zeroed; 3. negative health becomes huge positive; 4. win battles/claim.
- Snippet: `concat(a, b) # side effect: zeroes leading bytes of next-frame first local (CVE-2024-22419)`
- Pitfall: layout-dependent; any compiler bump moves the victim local — verify with `vyper -f asm` before sizing the exploit.
- Sources: [HITCON2024/lustrous](https://github.com/DeFiHackLabs/hitcon-ctf-2024-writeup/blob/main/writeup/lustrous.md), [Vyper/0day-economics](https://medium.com/@afterdark_labs/how-a-vyper-0-day-led-to-tens-of-millions-of-dollars-in-hacked-funds-d220fa8f41fe), [Vyper/offensive-vyper](https://medium.com/@jtriley15/offensive-vyper-an-evm-ctf-aa172ae34452)

## W49. Vyper return-ABI negative-offset read

- Signals: external call with dynamic-array return; decoder trusts returned offset; attacker controls callee.
- Steps: 1. deploy malicious callee returning crafted offset (negative position); 2. victim copies opponent actions/state from attacker-chosen slot; 3. force draw/win loop; 4. assert state equals attacker buffer.
- Snippet: `return (offset=-32, data=attackerBytes) # decoder copies from attacker-chosen position`
- Pitfall: fixed decoders bound-check offsets; fingerprint the compiler version — only pre-fix builds follow negative offsets.
- Sources: [HITCON2024/lustrous](https://github.com/DeFiHackLabs/hitcon-ctf-2024-writeup/blob/main/writeup/lustrous.md), [Vyper/CVE-2023-42441](https://app.opencve.io/cve/CVE-2023-42441)

## W50. Cairo proxy ABI-merge mint

- Signals: Cairo proxy forwarding to ERC20 impl; separate utils contract with `write(address,value)` keyed by `starknet_keccak(name)`; mint gated on owner.
- Steps: 1. merge ERC20 ABI + utils ABI against the proxy address; 2. `write(owner_slot, attacker)` via utils selector; 3. `mint(attacker, 50000e18)` via ERC20 selector; 4. assert balance on implementation view.
- Snippet: `proxy.write(owner_var, me); proxy.mint(me, 50000e18) # same address, merged ABI`
- Pitfall: felt short-strings truncate at 31 bytes; storage-var naming must hash exactly (`starknet_keccak` of full name).
- Sources: [Cairo/paradigm-solutions](https://amanusk.medium.com/paradigm-ctf-cairo-solutions-3a4b31210918), [ParadigmCTF2022/CairoProxy](https://github.com/minaminao/ctf-blockchain/tree/main/src/ParadigmCTF2022/CairoProxy), [ParadigmCTF2022/CairoAuction](https://github.com/minaminao/ctf-blockchain/tree/main/src/ParadigmCTF2022/CairoAuction)

## W51. Cairo felt-string + account-derivation gaps

- Signals: `solution()->felt` compared to short-string; hidden player account derived from salt+class-hash; starknet.py client usable.
- Steps: 1. reimplement `calculate_contract_address_from_hash(salt=20,...)` from infra repo; 2. recover player address; 3. submit felt-encoded answer (`b"man"` as felt); 4. assert checker passes.
- Snippet: `to_bytes(solution).lstrip(b"\x00") == b"man" # felt short-string compare`
- Pitfall: devnet vs private-node class hashes differ; copy derivation code verbatim from the challenge infra, never mainnet values.
- Sources: [Cairo/paradigm-solutions](https://amanusk.medium.com/paradigm-ctf-cairo-solutions-3a4b31210918), [Cairo/balsn-gist](https://gist.github.com/YSc21/b1cf72f4cc124c84f13028c1dc6f1ecd)

## W52. Solana missing-signer drain

- Signals: Anchor instruction taking `authority: AccountInfo` without `Signer` constraint; vault transfer gated only on account match.
- Steps: 1. list instructions missing `Signer<'info>`; 2. call withdraw with attacker's signature but victim's authority account; 3. vault releases funds; 4. assert lamport delta.
- Snippet: `#[account(mut)] authority: AccountInfo<'info> // missing Signer => anyone calls; fix: Signer<'info>`
- Pitfall: Anchor `has_one`/`constraint` do NOT imply signature; only `Signer` checks `is_signer`.
- Sources: [Solana/missing-signer-check](https://github.com/BlockChomper/solana-ctf/tree/master/missing-signer-check), [Solana/updraft-signer-check](https://updraft.cyfrin.io/courses/solana/common-bugs/missing-signer-check), [Solana/security-pitfalls](https://github.com/hifey62/solana-security-pitfalls)

## W53. Solana PDA seed-confusion hijack

- Signals: PDA derived without user-pubkey seed; first-claimer or shared-seed pattern; `init_if_needed` on shared PDA.
- Steps: 1. pre-claim the shared PDA yourself; 2. victim deposits route to your PDA; 3. withdraw via your signer; 4. assert lamport delta.
- Snippet: `seeds=[b"vault"] // missing user key => first-claimer owns it; fix: seeds=[b"vault", user.key()]`
- Pitfall: `init_if_needed` re-inits silently; check whether the challenge uses `init` (safe) or `init_if_needed` (claimable).
- Sources: [Solana/anchor-security-5](https://github.com/TobiAdeniji94/solana-anchor-security), [Solana/security-pitfalls](https://github.com/hifey62/solana-security-pitfalls), [Solana/moar-horse-5](https://github.com/otter-sec/sol-ctf-framework/tree/main/examples/moar-horse-5)

## W54. Anchor program-id confusion (arbitrary CPI)

- Signals: `Program<'info, System>`-typed account without explicit key check; CPI into passed-in program; Anchor 1.0.0-1.0.1 semantics.
- Steps: 1. pass malicious executable where System expected; 2. program CPIs into it assuming system semantics; 3. malicious program re-routes lamports; 4. assert ledger delta.
- Snippet: `require_keys_eq!(*prog.key, system_program::ID) // insert explicitly; framework default allowed any`
- Pitfall: version-gated (fixed in 1.0.2); confirm framework version in `Cargo.lock` before assuming the bypass.
- Sources: [Solana/anchor-CVE-2026-45137](https://vuldb.com/cve/CVE-2026-45137), [Zellic/the-vulnerabilities-youll-write-with-anchor](https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor), [Solana/solana-ctf-14](https://github.com/preeeetham/solana_ctf)

## W55. Move entry-visibility confusion

- Signals: `public(package) entry fun` on vault withdraw; assumption that package-visibility equals access control.
- Steps: 1. call the entry fun directly in a PTB/tx (no package membership needed); 2. receive full balance; 3. assert vault emptied; 4. fix is capability-token or sender check, not visibility.
- Snippet: `sui client call --function vault::emergency_withdraw # entry => directly callable by anyone`
- Pitfall: `public`, `public(package)`, `public(friend)`, `entry` compose independently; audit the `entry` modifier, not the visibility word.
- Sources: [Move/sui-workshop](https://medium.com/@monethic/sui-move-security-workshop-writeup-material-480c5e7d1da3), [Move/MOVEment-amber](https://medium.com/amber-group/movement-ctf-2022-writeup-4904ff8a82e), [Move/MOVEment-aptos-2022](https://leoq7.com/2022/12/CTF-Movement-Aptos)

## W56. Sui object/PTB lottery bypass

- Signals: 1-in-100k lootbox with per-tx gas cost; clock/ randomness from shared object; exploit dir expected (deploy own module).
- Steps: 1. read window/odds logic in `*.move`; 2. deploy helper module calling the draw in a loop within one PTB; 3. amortize gas across N draws; 4. claim on win.
- Snippet: `for (i=0;i<N;i++) { lootbox::draw(ticket); } // one PTB, N draws, ~1/N of naive gas`
- Pitfall: testnet faucet limits mass retries; compute expected draws off-chain and batch tightly.
- Sources: [Move/suictf](https://github.com/chennethelius/suictf), [Move/move-over-ctf](https://yashwanth1208.github.io/blog/move-over-ctf-writeup), [Move/sui-ctf-framework](https://deepwiki.com/otter-sec/sui-ctf-framework/4-move-contract-reference)

## W57. CosmWasm funds/account confusion ladder

- Signals: Oak-style leveled set (Mjolnir→…); each level one missing check (auth, funds, owner); `cargo test` harness.
- Steps: 1. solve in order, one invariant per level; 2. each exploit is a single-message client call with spoofed funds field; 3. assert contract balance delta; 4. carry the check-pattern to the next level.
- Snippet: `grep -rHn 'info.sender\|deps.querier\|BankMsg\|CW20' contracts/ | head -n 30`
- Pitfall: levels share scaffolding; a fix that solves level N often breaks your level N+1 shortcut — re-read per level.
- Sources: [OakCosmWasm/Mjolnir](https://github.com/minaminao/ctf-blockchain/tree/main/src/OakSecurityCosmWasmCTF/01-Mjolnir), [OakCosmWasm/Gungnir](https://github.com/minaminao/ctf-blockchain/tree/main/src/OakSecurityCosmWasmCTF/02-Gungnir), [OakCosmWasm/Laevateinn](https://github.com/minaminao/ctf-blockchain/tree/main/src/OakSecurityCosmWasmCTF/03-Laevateinn)

## W58. Fuzzer showdown harness (Foundry vs Echidna vs Medusa)

- Signals: invariant set with easy + hard properties; `echidna.yaml` present; Medusa parallel mode available.
- Steps: 1. run all three in basic config, 120s each; 2. promote only unbroken invariants to guided mode; 3. take the shortest transaction trace as the PoC; 4. assert trace replays under `forge test`.
- Snippet: `medusa fuzz --timeout 120; echidna-test . --config echidna.yaml; forge test --match-test invariant -vvv`
- Pitfall: basic-mode ties mislead — hard invariants need guided config; cap at 3 seeds x 120s, then escalate, never brute-force longer.
- Sources: [FV/fuzzing-comparison](https://github.com/devdacian/solidity-fuzzing-comparison), [FV/echidna-intro](https://github.com/klauswaiss/trail-of-bits-building-secure-contracts/blob/master/program-analysis/echidna/introduction/fuzzing-introduction.md), [TrailOfBits/unleashing-medusa-fast-and-scalable-smart-contract-fuzzing](https://blog.trailofbits.com/2025/02/14/unleashing-medusa-fast-and-scalable-smart-contract-fuzzing)

## W59. FV-escape via over-summarized spec (eBTC shape)

- Signals: Certora spec with `summary` on linked-list mutators; Echidna ran 100k+ calls with no break; property involves aggregated state.
- Steps: 1. read which functions the spec summarizes away; 2. attack THROUGH a summarized function (list insert/delete); 3. show concrete trace violating the proven property; 4. property holds only under the false summary.
- Snippet: `certoraRun certora/confs/AP04.conf # passes; concrete list-op trace breaks the same invariant`
- Pitfall: escaping the prover needs the exact summarized entrypoint; fuzz the summary boundary, not random state.
- Sources: [FV/certora-vs-echidna-eBTC](https://allthingsfuzzy.substack.com/p/certora-vs-echidna-a-case-study-on), [FV/eBTC-invariants](https://github.com/nican0r/eBTC-certora-vs-echidna/blob/main/Invariants.MD), [FV/fuzz-vs-fv-showdown](https://github.com/Certora/fuzz-vs-fv-showdown)

## W60. Contest-finding reuse (Code4rena 2024-26 as PoC library)

- Signals: live target forks a 2024-26 contest codebase (Ethena/PoolTogether/Uniswap-Foundation style); same file layout; fix commit absent.
- Steps: 1. fingerprint version (`git log`/bytecode); 2. pull the contest report findings; 3. replay the PoC test against the fork; 4. unpatched fork falls to the published trace.
- Snippet: `diff -rq lib/contest-src src/ | head; forge test --match-test PoC_ --fork-url $RPC -vvv`
- Pitfall: forks drift; a renamed function kills the replay — adapt selectors, keep the state-transition shape.
- Sources: [Code4rena/2024-11-ethena-labs](https://code4rena.com/reports/2024-11-ethena-labs), [Code4rena/2024-03-pooltogether](https://code4rena.com/reports/2024-03-pooltogether), [Code4rena/2024-02-uniswap-foundation](https://code4rena.com/reports/2024-02-uniswap-foundation)

## W61. Incident-DB to CTF adaptation loop

- Signals: new CTF resembles a 2024-26 incident (same protocol fork, same vuln class); incident DB has root-cause + PoC.
- Steps: 1. search DB by vuln class (flash-loan/oracle/reentrancy); 2. map incident contracts to challenge contracts; 3. port the PoC file; 4. adjust for CTF simplifications (faucets, no timelock).
- Snippet: `grep -ril 'read-only\|donation\|twap' 2025/ | head # pick template incident, then port`
- Pitfall: CTFs patch the exact incident vector but keep the sibling (e.g. fixes spot, keeps TWAP-warpable); test variants, not just the original.
- Sources: [DB/defi-security-incident](https://github.com/kismp123/DeFi-Security-Incident), [DB/defi-incident-db](https://github.com/securitymath/defi-incident-db), [DB/defi-hacks-2024](https://www.smartcontractaudit.com/guides/defi-hacks-2024-roundup)

## W62. Read-only reentrancy v2 (rate-view window)

- Signals: oracle reads Balancer-style `getRate()`/Curve `get_virtual_price`; `exitPool`/withdraw sends value before balance update; 2025 fork of 2023 code.
- Steps: 1. join pool, deposit LP as collateral; 2. `exitPool` and act inside `receive()` on the inflated view; 3. borrow/self-liquidate; 4. repeat while `rate_view/rate_settled > fee`.
- Snippet: `receive() external payable { if (n++==0) pool.setUseAsCollateral(coll, false); } // inflated getRate`
- Pitfall: Vault-level reentrancy was patched in 2023 forks; only the `view`-reading oracle path survives — log view inside vs outside the callback.
- Sources: [TrailOfBits/balancer-hack-analysis-and-guidance-for-the-defi-ecosystem](https://blog.trailofbits.com/2025/11/07/balancer-hack-analysis-and-guidance-for-the-defi-ecosystem), [ChainSecurity/heartbreaks-curve-lp-oracles](https://www.chainsecurity.com/blog/heartbreaks-curve-lp-oracles/), [ChainSecurity/curve-lp-oracle-manipulation-post-mortem](https://www.chainsecurity.com/blog/curve-lp-oracle-manipulation-post-mortem/)
