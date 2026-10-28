# blockchain SUMMARY (quickref)

Setup: `forge build`, `forge test -vvv`, `anvil [--fork-url $RPC]`,
`slither src/ --solc solc`. Never mainnet; local Anvil only.

Baseline: list `src/|test/|script/`, pragma (`<0.8` overflow?), sinks:
`call{|delegatecall|mint|withdraw|swap`, auth: `onlyOwner|tx.origin`.
Win condition from README/`isSolved`.

Confirm (read-only): `cast call $V "balance()"`,
`cast call $T "balanceOf(address)(uint256)" $V`,
`cast storage $C 0`, `cast implementation/admin $PROXY`.

EIP-1967 slots: impl `0x3608…bbc`, admin `0xb531…b7`, beacon `0xa3f0…e32` —
verify via `cast implementation|admin`, don't trust memory.

Exploit loop: write `test/Exploit.t.sol` attacker + `vm.prank/deal/warp/store`,
`forge test --match-test test_Exploit -vvv`, read trace, fix/pivot.
Local send: `cast send $V "f(...)" args --private-key $KEY`.

Top vulns: missing `onlyOwner` → reentrancy (call-before-update) →
`tx.origin` phish → `delegatecall` inject / storage collision → unchecked
return → overflow (`<0.8|unchecked`) → spot-oracle + flash-loan pump →
`block.timestamp` randomness.

Kill first: state-before-call (no reentrancy), `>=0.8` no-unchecked
(no overflow), TWAP/VRF (no pump/predict), timelocked proxy admin.

Gates: 1 sinks → 2 read-only confirm → 3 negatives → 4 ONE PoC ≤120s →
5 re-run twice + `isSolved` + `results/bc_<id>/Exploit.t.sol`.

Hard playbook: cross-function (unguarded sibling) / cross-contract (hook
`tokensReceived|onERC721Received|uniswapV2Call`) / read-only (`view`
stale price) → log view before vs inside callback.
AMM math: `out=(in*997/1000*y)/(x+in*997/1000)`; flash `L≈x0/2`,
skew `p0→p1`, `borrow/mint`, swap back, repay; TWAP → 2-block warp path.
Permit: twin `(v^1,r,n-s)` bypasses sig-hash keys; check
nonce++/deadline/domain/low-s in `permit()` body.
Proxy: `cast implementation/admin` (never hardcode slots); try
`initialize(attacker)` on proxy then impl; open UUPS `upgradeTo`,
beacon swap, slot-0 collision via `vm.store` round-trip.
Merkle: single-leaf (`proof=[]`, `leaf==root`) + open `bondRoot`;
copy `verify` verbatim. Dust: loop 50–200, assert gain.
Timelock-zero: `setChallengePeriod(0)` skips loops; CREATE2: ancestry
check, `vm.etch`, never addr⇒code.

Chains (one `Exploit.t.sol` each): flash→skew→drain;
proxy→impl→init→upgrade; gov-zero→forge-root→withdraw.

Failures: F1 fork drift→pin `--fork-block-number`; F2 prank≠deal→use
both; F3 gas grief→explicit `{gas:…}`; F4 TWAP→`warp+roll` 2-block skew;
F5 permit replay→fresh nonce/`vm.sign`; F6 slot→re-derive via cast;
F7 hook skipped→register ERC1820 implementer.

Drift: pin `forge/cast/solc --version` + pragma; probe one `cast call`
after bump. Tiers: easy ≤20m / medium ≤1h / hard ≤3h / insane→escalate
at 90m no-hypothesis; fuzz ≤3×120s.
Escalate: /rev (off-chain bot signs), chaining-flagpath (≥2-contract
hops), operator (fork RPC 401/429) via `tools/operator_ping.sh`.

Solana brief: `programs/|Anchor.toml`, missing signer/owner checks,
`anchor test`, one client PoC per gate. Never paste keys/flags hosted.

Writeup patterns W1-W30 (in SKILL.md): 4626-donation→777 send-before-burn→
fee-dust loops→double-entrypoint→puzzle-multicall double-deposit→uninit UUPS
impl→Safe CREATE2 backdoor→ABI-smuggle decoy-selector→forwarder tail-spoof→
approve-via-loan→deposit-as-repay→same-round rewarder replay→flash-govern
queue+warp→median-key flip→V2-spot borrow→buyMany bounty reentry→timelock
execute-before-check→wallet replay+impl→shard ordering→Curve-LP skew→
dual-leg withdrawal→DVM re-init→selector clash→cache-key collision→
donate-to-reserves→harvest delta→exit-window price→sig replay→Huff
ecrecover steer→forged xchain message. Extended PoCs:
`techniques/writeup-patterns-1.md`. Mined index (422):
`knowledge/writeups_mined/blockchain_manifest.md`.
R2 (488 new, 0% R1 overlap): dispute-delay→inbox-init→portal-value→paymaster→
UserOp-replay→sandwich→solver-bundles→restaking-drift→7702→Vyper-codegen→
Cairo-merge→Anchor signer/PDA→Move-entry→Sui-PTB→FV-escape→contest-reuse.
W31-W62 in `techniques/writeup-patterns-r2-1.md`, `-r2-2.md`;
index `knowledge/writeups_mined/blockchain_manifest_r2.md`.
