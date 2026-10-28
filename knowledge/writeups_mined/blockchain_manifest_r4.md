# blockchain Writeups Mined — Manifest r4, browser-swarm batch ( technique-only, no flags )

Mined 2026-10-17 by 8 reader subagents via real browsers (Playwright snapshots; Medium member-only pieces via medium-unlocker.inulute.com -> Freedium mirror; GitHub/team-blog/pro-research sources). Rows filtered (video/bare-profile/placeholder links dropped) and deduped by URL within the batch and against the full corpus. Difficulty as labeled by readers. Format: `- [source/challenge](URL) | difficulty | technique-chain`. No flag values anywhere.

## batch 2026-10-17-browser-swarm (28 rows, 2 easy)

- [Paradigm/Swap-2021](https://www.paradigm.xyz/writing/paradigm-ctf-2021-swap) | hard | LP invariant confusion, mint-burn accounting, nonReentrant bypass reasoning
- [Paradigm/Hiding-Plain-Sight](https://www.paradigm.xyz/writing/hiding-in-plain-sight) | hard | Solidity 0day backdoor, obscure compiler bug, hidden storage exploit
- [Samczsun/Price-Oracle](https://samczsun.com/so-you-want-to-use-a-price-oracle) | hard | spot price manipulation, flashloan sandwich, TWAP delay mitigation
- [Samczsun/Dangers-Surprising-Code](https://samczsun.com/the-dangers-of-surprising-code) | medium | safeTransfer callback, ERC1155 reentrancy, wrapper verification bypass
- [Samczsun/Escaping-Dark-Forest](https://www.paradigm.xyz/writing/escaping-the-dark-forest) | hard | mempool frontrun rescue, private relay, nonce gas auction
- [Samczsun/Taking-Undercollateralized-Loans](https://samczsun.com/taking-undercollateralized-loans-for-fun-and-for-profit/) | hard | lending collateral oracle, Uniswap reserve skew, borrow drain
- [Paradigm/Two-Rights-Wrong](https://www.paradigm.xyz/writing/two-rights-might-make-a-wrong) | hard | frontrun double-spend logic, MEV ordering, invariant break
- [Paradigm/Uniswap-v3-Universal-AMM](https://www.paradigm.xyz/writing/uniswap-v3-the-universal-amm) | medium | concentrated liquidity math, tick manipulation, fee accounting edge
- [Paradigm/Blend-NFT-Lending](https://www.paradigm.xyz/writing/blend) | medium | perpetual NFT collateral, Dutch auction liquidation, oracle expiry abuse
- [Paradigm/Art-Gobblers](https://www.paradigm.xyz/writing/artgobblers) | medium | GOO emission math, VRGDA pricing, mint exploit modeling
- [TrailOfBits/Bybit-1.5B-OpSec](https://blog.trailofbits.com/2025/02/21/the-1.5b-bybit-hack-the-era-of-operational-security-failures-has-arrived) | hard | multisig UI spoof, signer device compromise, cold storage bypass
- [TrailOfBits/Uniswap-v4-Hooks](https://blog.trailofbits.com/) | hard | hook caller check missing, PoolManager accounting, settlement invariant bypass
- [DamnVulnDeFi/Side-Entrance](https://medium.com/coinmonks/damn-vulnerable-defi-challenges-4-side-entrance-f473bafcdd87) | easy | flashloan deposit trick, balance mapping, withdraw drain
- [DamnVulnDeFi-Foundry/Full-Set](https://github.com/nicolasgarcia214/damn-vulnerable-defi-foundry) | medium | Foundry cheatcodes, prank exploit harness, flashloan oracle suite
- [DamnVulnDeFi-Foundry-Achraf](https://github.com/Achraf012/damn-vulnerable-defi) | medium | reentrancy access control, Foundry rewrite, contest practice harness
- [Ethereum/DamnVulnDeFi-Info](https://ethereum.org/developers/tools/damn-vulnerable-defi) | easy | training playground intro, Solidity DeFi puzzles, educator benchmark suite
- [Paradigm/RICKS](https://www.paradigm.xyz/writing/ricks) | hard | NFT fractionalization, recursive staking, auction settlement exploit
- [Paradigm/Floor-Perps](https://www.paradigm.xyz/writing/floor-perps) | medium | NFT floor oracle, funding rate, short squeeze manipulation
- [Paradigm/TWAMM](https://www.paradigm.xyz/writing/twamm) | medium | time-weighted AMM, long-term order, grinding attack mitigation
- [Paradigm/GOO-Emission](https://www.paradigm.xyz/writing/goo) | hard | gradual ownership, emission curve, equilibrium mint abuse
- [Paradigm/GDA-Dutch-Auction](https://www.paradigm.xyz/writing/gda) | medium | gradual Dutch auction, price decay, bid timing exploit
- [Paradigm/Intent-Risks](https://www.paradigm.xyz/writing/intents) | medium | intent solver trust, signature replay, mempool leakage abuse
- [Paradigm/Casino-On-Mars](https://www.paradigm.xyz/writing/casino-on-mars) | medium | onchain game randomness, commit-reveal, VRF bypass
- [Samczsun/Rari-Reentrancy](https://samczsun.com/) | hard | cEther call.value reentrancy, Fuse pool borrow, cross-pool drain
- [Paradigm/Leaderless-Auctions](https://www.paradigm.xyz/writing/leaderless-auctions) | medium | MEV auction ordering, leaderless design, timing advantage abuse
- [Paradigm/Timing-Onchain-Auctions](https://www.paradigm.xyz/writing/timing-advantages-in-onchain-auctions) | hard | slot timing oracle, proposer bias, bid frontrunning
- [Paradigm/Priority-Is-All-You-Need](https://www.paradigm.xyz/writing/priority-is-all-you-need) | medium | mempool priority fee, ordering manipulation, backrun modeling
- [TrailOfBits/Cold-Storage-Eth](https://blog.trailofbits.com/categories/blockchain) | medium | smart contract custody, multisig compromise resilience, programmable withdrawal

## batch 2026-10-17-browser-swarm (28 rows, 2 easy)


## batch 2026-10-17-browser-swarm (30 rows, 2 easy)

- [CryptoCabana-vault-shards](https://dhanushnehru.medium.com/hacker-holidays-2026-day-9-walkthrough-cryptocabana-a6a1caa9438a#keyvault-shards) | medium | Azure vault sharded secret version history not-your-keys coins assemble
- [EVM-guess-zichmp2026](https://medium.com/@amrkhaledv2171516/zichmp-ctf-2026-cyber-champions-2026-abbfe3f13fc6#evm) | medium | On-chain guessing game storage slot read key XOR flag recover

## batch 2026-10-17-browser-swarm (10 rows, 4 easy)

- [NaiveReceiver-JohnnyTime](https://medium.com/@JohnnyTime/damn-vulnerable-defi-v4-foundry-challenge-2-solution-naive-receiver-e438bc7acf4c) | medium | drain fees via multicall then forwarder spoofed withdraw
- [NaiveReceiver-iphelix](https://iphelix.medium.com/damn-vulnerable-defi-challenge-2-walkthrough-c2a7eac3374d) | easy | loop flashLoan ten times fee drains receiver single-tx attacker
- [SideEntrance-Juan](https://medium.com/@juanxaviervalverde/damn-vulnerable-defi-side-entrance-level-4-solution-8d76d4d629e1) | easy | flashloan callback deposit fakes balance then withdraw all
- [SideEntrance-lazy](https://medium.com/@opensiddhu993/challenge-4-side-entrance-damn-vulnerable-defi-v4-lazy-solutions-series-b19a01aab66e) | easy | exploit balance check deposit during execute withdraw recovery
- [Truster-Juancito](https://github.com/juancito-dev/damn-vulnerable-defi-solutions) | easy | flashloan arbitrary call approve attacker steal tokens
- [Compromised-Solutions](https://github.com/alexbabits/damn-vulnerable-defi-ctfs) | medium | leaked oracle keys manipulate NFT price buy cheap
- [Puppet-Solutions](https://github.com/typicalHuman/damn-vulnerable-defi-foundry-solutions/tree/master/unstoppable) | medium | Uniswap TWAP manipulate with flashloan borrow undercollateralized
- [DVD-Repo](https://github.com/theredguild/damn-vulnerable-defi) | medium | Foundry src test per challenge flashloan oracle governance patterns
- [Paradigm-Repo](https://github.com/paradigmxyz/paradigm-ctf-2023) | hard | kCTF anvil fork grains hopping black-sheep dropper enterprise sources
- [Paradigm-Dropper](https://hackmd.io/@0xgalois/HJJkjK-n0) | hard | gas golf huff airdrop basefee gasprice selfdestruct optimization
