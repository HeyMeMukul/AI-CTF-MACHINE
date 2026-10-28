
# Writeup Patterns R2-1 — L2 / AA / MEV / Restaking / Bridges (W31–W46)

Companion to `../SKILL.md` section `## Writeup-Distilled Patterns`.
Technique-only: local Anvil/fork shapes, no real addresses, no flags/keys.
Source URLs below are all indexed in `knowledge/writeups_mined/blockchain_manifest_r2.md`.
Each entry: signals → steps → snippet → pitfalls → sources.

## W31. L2 dispute-window censorship (BOLD force-inclusion delay)

- Signals: L3-on-L2 with turn-based dispute game; `forceInclusion` path exists with multi-hour delay; chess-clock per participant.
- Steps: 1. read `delayBlocks`, clock limits, turn count; 2. model censor-every-move delay x turns vs honest clock; 3. attacker submits invalid assertion, honest moves all forced via L1; 4. clock exhausts, assertion confirms.
- Snippet: `cast call $SEQ "delayBlocks()(uint256)"; # turns * delay > honestClock => dispute unwinnable`
- Pitfall: per-move delay compounds over ~40-50 bisection turns; single-move analysis understates the censor.
- Sources: [Arbitrum-BOLD-sequencer](https://github.com/code-423n4/2024-05-arbitrum-foundation-findings/issues/26), [sequencing-walkthrough](https://docs.l2beat.com/code_walkthroughs/arbitrum/sequencing.html)

## W32. Uninitialized L2 inbox (DelayedInbox storage wipe)

- Signals: TransparentUpgradeableProxy inbox with public `initialize()`; bridge/sequencerInbox slots readable; initializer booleans in slots 0/1.
- Steps: 1. `cast storage` slots 0/1 on proxy; 2. if both empty while bridge set, contract is live-but-uninit; 3. call `initialize(attacker...)` to seize inbox; 4. redirect deposits.
- Snippet: `cast storage $INBOX 0 --rpc-url $RPC; cast storage $INBOX 1 --rpc-url $RPC # both 0x0 = live`
- Pitfall: gas-optimized init may pack booleans unexpectedly; read the exact layout, never assume slot meaning.
- Sources: [Arbitrum-inbox-init](https://medium.com/@0xriptide/hackers-in-arbitrums-inbox-ca23272641a2), [Arbitrum-audit-writeup](https://github.com/EduardoFernandess/audit-writeup-arbitrum), [Arbitrum-bridge-surface](https://dev.to/dannydoes_2abdf9c/smart-contract-vulnerability-surface-analysis-arbitrum-bridge-gl3)

## W33. OptimismPortal value mismatch (`msg.value` vs `_value`)

- Signals: `depositTransaction(..., _value, ...)` where L1 contract forwards user funds; no `require(_value == msg.value)`; L2 alias holds balance.
- Steps: 1. deposit with `msg.value` small, `_value` large; 2. sequencer mints `_value` from L1-alias on L2; 3. alias drained in favor of depositor; 4. assert L2-alias delta equals `_value - msg.value`.
- Snippet: `portal.depositTransaction{value: 0.01 ether}(to, 0.1 ether, 100000, false, hex"") // alias pays 0.1`
- Pitfall: forks (Base/Blast/OP-Stack copies) inherit the shape; check each fork, the portal never enforces equality itself.
- Sources: [Optimism-portal-value](https://paragraph.com/@shanmuga-bharathi/security-research-disclosure-optimism-bridge-portal), [bridging-finality](https://jumpcrypto.com/resources/bridging-and-finality-optimism-and-arbitrum)

## W34. Paymaster allowlist bypass (sponsored-UserOp drain)

- Signals: `BasePaymaster` subclass with owner-managed allowlist; `validatePaymasterUserOp` reads caller-supplied allowlist key; deposit funded.
- Steps: 1. fund nothing; craft UserOp with victim-allowlisted sender field; 2. bundler `handleOps` sponsors gas; 3. loop sponsored ops until deposit drains; 4. assert deposit delta.
- Snippet: `vm.prank(bundler); entrypoint.handleOps(ops, bundler); // paymaster deposit decreases, attacker pays 0`
- Pitfall: EntryPoint v0.7+ separates validation scope (ERC-7562); storage-touching validation reverts — test against the pinned EntryPoint version.
- Sources: [gasless-smart-account](https://github.com/chainwright/gasless-smart-account), [OZ-4337-audit](https://www.openzeppelin.com/news/erc-4337-account-abstraction-incremental-audit), [4337-reading-material](https://docs.erc4337.io/resources/reading-material.html)

## W35. Cross-chain UserOp replay (missing chainid/EntryPoint binding)

- Signals: `validateUserOp` verifies signature over `userOpHash` but account rebuilds hash without `block.chainid` or EntryPoint address.
- Steps: 1. capture valid UserOp on cheap chain; 2. resubmit same `(sender, nonce, signature)` on target chain via its EntryPoint; 3. account executes with attacker's calldata; 4. fresh nonce per chain or sequential nonces.
- Snippet: `grep -rHn 'getUserOpHash\|block.chainid\|msg.sender == entryPoint' src/ // absent chainid+binding = live`
- Pitfall: v0.8+ `userOpHash` construction changed (PackedUserOperation); rebuild the hash exactly per version or the PoC fails spuriously.
- Sources: [ERC4337-magicians-replay](https://ethereum-magicians.org/t/erc-4337-account-abstraction-via-entry-point-contract-specification/7160/22), [eth-infinitism-contracts](https://github.com/eth-infinitism/account-abstraction), [verifying-paymaster](https://github.com/dngr2/paymaster)

## W36. Optimal sandwich sizing (quadratic front-run)

- Signals: constant-product AMM victim swap with known slippage tolerance; attacker sees mempool tx; local Foundry AMM available.
- Steps: 1. read victim amount + min-out; 2. solve quadratic for max front-run respecting `minOut`; 3. front-run, let victim execute, back-run full balance; 4. require profit > gas + bribes.
- Snippet: `uint amt = computeFrontRunAmount(victimAmt, minOut, x, y); // scaled /1e9 to avoid uint256 overflow`
- Pitfall: unscaled discriminant overflows for 1000+ ether amounts; scale intermediates, and re-check victim min-out after your front-run.
- Sources: [sandwich-simulator](https://github.com/KushagraKanaujia/mev-sandwich-bot), [subway-reference](https://github.com/korchix/mevBot), [Zellic/your-sandwich-is-my-lunch-how-to-drain-mev-contracts-v2](https://www.zellic.io/blog/your-sandwich-is-my-lunch-how-to-drain-mev-contracts-v2)

## W37. Private-mempool sandwich infeasibility (negative pattern)

- Signals: rollup with private mempool, no builder market; back-run puzzle expects deterministic co-inclusion.
- Steps: 1. check sequencer ordering policy (priority-fee? FIFO?); 2. attempt redundant-submission sandwich on local fork; 3. measure inclusion correlation; 4. if probabilistic, pivot to single-tx atomic (flash) path.
- Snippet: `cast rpc eth_sendBundle $BUNDLE # unsupported on private-mempool sequencer => probabilistic only`
- Pitfall: naive heuristics flag false-positive sandwiches; verify with execution-feasibility (co-inclusion), not pattern matching.
- Sources: [private-L2-mempools](https://ui.adsabs.harvard.edu/abs/2026arXiv260119570G/abstract), [ParadigmCTF2023/dodont](https://github.com/paradigmxyz/paradigm-ctf-2023/tree/main/dodont)

## W38. Restaking rewards-accounting drift (EigenLayer shape)

- Signals: rewards coordinator with retroactive roots; operator-set accounting separate from stake escrow; withdrawal delay queue.
- Steps: 1. map rewards-submission vs stake-escrow state; 2. deposit/withdraw across a rewards-root boundary; 3. claim with stale root + fresh escrow; 4. assert double-counted rewards.
- Snippet: `grep -rHn 'submitRewards\|rewardsRoot\|withdrawalDelay\|slashEscrow' src/ | head -n 20`
- Pitfall: 7-14 day escrow means single-tx PoCs die; use `vm.warp` past the delay and test root-finality timing first.
- Sources: [eigenlayer-rewards](https://skynet.certik.com/third-party-audit-reports/jqfm0se0f03r/1IWPRNMPOEjdn2vD3anq9U/41187b3a5f979369411209a5190c9bf2/Sigma_Prime_Eigen_Labs_EigenLayer_Rewards_Coordinator_Security_Assessment_Report_v1.1.pdf), [eigenlayer-review-3](https://skynet.certik.com/third-party-audit-reports/jqfm0se0f03r/bBK8Pg07hcEHIQvvpHsY7/580b78addc14d0d1f971b567de2857e2/eigenlayer-3.pdf), [ChainSecurity/eigenlayer-secure-integration](https://www.chainsecurity.com/blog/eigenlayer-secure-integration/)

## W39. Native-restaking credential redirect

- Signals: withdrawal credentials pointable at protocol contracts; pre/post-Deneb tree-height constants; operator opt-in per AVS.
- Steps: 1. read credential-setting flow + tree-height logic; 2. point credentials at attacker-influenced strategy; 3. trigger withdrawal across fork-boundary logic; 4. assert escrow release to wrong strategy.
- Snippet: `cast call $EL "getWithdrawalCredentials(address)(bytes)" $OP --rpc-url $RPC`
- Pitfall: pre/post-Deneb branches differ; test both heights or the PoC passes on one fork and reverts on the pinned one (F1).
- Sources: [eigenlayer-review-3](https://skynet.certik.com/third-party-audit-reports/jqfm0se0f03r/bBK8Pg07hcEHIQvvpHsY7/580b78addc14d0d1f971b567de2857e2/eigenlayer-3.pdf), [Zellic-Reports/ether.fi-266-267](https://reports.zellic.io/publications/etherfi-266-267)

## W40. Solver/matchmaker back-run bundles (MEV-Share shape)

- Signals: matchmaker contract accepting bundles; per-level profit multipliers (10x/20x/30x/40x); back-run-only win condition.
- Steps: 1. read pending victim swap from matchmaker feed; 2. build back-run-only bundle (no front-run needed); 3. submit via matchmaker path; 4. assert multiplier payout.
- Snippet: `grep -rHn 'sendBundle\|backrun\|matchmaker\|multiplier' src/ challenge/ | head -n 20`
- Pitfall: levels differ only in multiplier/threshold; copy the base solution then scale amounts per level.
- Sources: [MEVShareCTF/10x](https://github.com/minaminao/ctf-blockchain/tree/main/src/MEVShareCTF/10x), [MEVShareCTF/30x](https://github.com/minaminao/ctf-blockchain/tree/main/src/MEVShareCTF/30x), [MEVShareCTF/base](https://github.com/minaminao/ctf-blockchain/tree/main/src/MEVShareCTF/base)

## W41. Golden-bridge message validation flaw

- Signals: L1 executes decoded L2 messages without origin allowlist; `sendRemoteMessage(chainId, target, data)` open; relayer permissionless.
- Steps: 1. encode `transfer(attacker, fullBal)` as message data; 2. send from L2 side to L1 token; 3. relayer executes; 4. verify L1 `balanceOf` post-state on the correct RPC.
- Snippet: `bridge.sendRemoteMessage(L1, token, abi.encodeWithSignature("transfer(address,uint256)", me, bal))`
- Pitfall: L1/L2 RPC mixups succeed-but-do-nothing; assert post-state on the execution chain, and bind `chainId` in tests.
- Sources: [DiceCTF2025/GoldenBridge](https://github.com/minaminao/ctf-blockchain/tree/main/src/DiceCTF2025/GoldenBridge), [SCAN2024/Bridge](https://github.com/minaminao/ctf-blockchain/tree/main/src/Scan2024CTF/Bridge), [ParadigmCTF2023/enterprise-blockchain](https://github.com/paradigmxyz/paradigm-ctf-2023/tree/main/enterprise-blockchain)

## W42. Dual-ledger withdrawal race (migration hook)

- Signals: ETH leg + ERC20 leg tracked separately; recipient-migration hook; over-approvable migration path.
- Steps: 1. over-approve migration; 2. trigger recipient migration mid-flow; 3. withdraw both legs against one credit; 4. dry-run per-leg balances to fix ordering.
- Snippet: `grep -rHn 'migrate\|recipient\|approve\|transferFrom' src/ | head -n 30`
- Pitfall: withdrawing the synced leg first reverts the second; order is exact — log pre/post per leg.
- Sources: [DVDv4/Withdrawal-ilainy](https://github.com/ilainy/damn-vulnerable-defi-v4-solutions/blob/main/Withdrawal%20/README.md), [DVDv4/full-v4.1-walkthrough-chujimafa](https://github.com/Chujimafa/damn-vulnerable-defi-v4.1.0-solutions/blob/master/WalkThrough/damn-vulnerable-defi-v4-full-solutions-walkthrough.md)

## W43. Two-block TWAP warp skew

- Signals: 10-min TWAP oracle; `vm.warp`-able test env; router `exactInputSingle` with deep liquidity on your side.
- Steps: 1. large skew swap leg 1; 2. `vm.warp(+period); vm.roll(+1)`; 3. skew leg 2 to move TWAP; 4. borrow at lagging quote, unwind, repay.
- Snippet: `pool.swap(attacker, true, L); vm.warp(block.timestamp + 600); pool.swap(attacker, true, L); victim.borrow(max);`
- Pitfall: single-tx skew leaves TWAP unmoved (`p1==p0`); assert TWAP moved before borrowing or(size down 25%).
- Sources: [DVDv4/PuppetV3-astierfe](https://github.com/astierfe/damn-vulnerable-defi-writeups/blob/main/reports/puppet-v3/Puppetv3_exploit.md), [DVDv4/PuppetV3-ilainy](https://github.com/ilainy/damn-vulnerable-defi-v4-solutions/blob/main/Puppet%20V3/README.md), [Damn Vulnerable DeFi v4](https://medium.com/@maggie.chujifan/damn-vulnerable-defi-v4-walkthrough-challenges-1-18-breakdown-6316d34a8492)

## W44. Flash-governance queue-then-warp (Selfie v2)

- Signals: `delegate()` snapshot token; pool flash loan; timelock queue + delay; `emergencyExit`/`executeAction` sink.
- Steps: 1. flash-borrow majority; 2. in callback `delegate(self)` BEFORE queue; 3. repay; 4. `vm.warp(+delay); executeAction(id)` to recovery.
- Snippet: `token.delegate(address(this)); gov.queueAction(pool, 0, abi.encodeWithSignature("emergencyExit(address)", rec));`
- Pitfall: queue-before-delegate fails quorum; delegation must precede the snapshot in the same callback.
- Sources: [DVDv4/Selfie-astierfe](https://github.com/astierfe/damn-vulnerable-defi-writeups/blob/main/reports/selfie/selfie_exploit.md), [DVDv4/Selfie-ilainy](https://github.com/ilainy/damn-vulnerable-defi-v4-solutions/blob/main/Selfie/README.md), [DVD/AttackSelfie-MikeSpa](https://github.com/MikeSpa/DamnVulnerableDeFi/blob/main/contracts/attacker-contracts/AttackSelfie.sol)

## W45. EIP-7702 delegated-account takeover

- Signals: EOA delegation designator (`0xef0100`); `Simple7702Account`-style init callable once; `entryPoint.senderCreator` gate missing on init.
- Steps: 1. EOA signs 7702 authorization to attacker implementation; 2. call init directly (not via EntryPoint); 3. seize account, drain via execute batch; 4. assert bundler path still works post-takeover.
- Snippet: `cast send $EOA --auth $AUTH "initialize(address)" $ME --private-key $K --rpc-url $RPC`
- Pitfall: init gated on `senderCreator` in fixed versions; verify the gate on the deployed EntryPoint version first (v0.7 vs v0.8 differ).
- Sources: [ITSEC Summit CTF 2025](https://medium.com/@firdausfarul/itsec-summit-ctf-2025-blockchain-writeup-a3881ded185e), [ChainSecurity/the-real-minimal-proxy---powered-by-eip-7702](https://www.chainsecurity.com/blog/the-real-minimal-proxy---powered-by-eip-7702/), [eth-infinitism-contracts](https://github.com/eth-infinitism/account-abstraction)

## W46. Rebasing/fee-token integration drift

- Signals: rebasing or fee-on-transfer token listed as collateral; lender uses raw `balanceOf` deltas; harvest loops per-transfer fees.
- Steps: 1. force rebase/dust to shift `balanceOf` without touching lender state; 2. trigger lender sync/quote; 3. borrow against inflated view; 4. unwind before next rebase.
- Snippet: `token.rebase(epoch); lender.sync(); lender.borrow(maxAtInflatedQuote); // same block`
- Pitfall: positive and negative rebases are asymmetric; model both directions and never hold the position across an epoch boundary.
- Sources: [ChainSecurity/the-hitchhikers-guide-to-rebasing-tokens](https://www.chainsecurity.com/blog/the-hitchhikers-guide-to-rebasing-tokens/), [ChainSecurity/f-x-protocol-circumventing-access-control-with-a-double-flash-loan-attack](https://www.chainsecurity.com/blog/f-x-protocol-circumventing-access-control-with-a-double-flash-loan-attack/), [TrailOfBits/accidentally-stepping-on-a-defi-lego](https://blog.trailofbits.com/2020/08/05/accidentally-stepping-on-a-defi-lego)
