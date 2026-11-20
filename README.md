# Sentinel — Token Risk Guard

**A wallet-security agent that reads live on-chain state and tells you what a token's owner can actually do to you — before you buy.**

**Live demo:** https://sentinel-guard-brown.vercel.app
**Scan endpoint:** `GET https://sentinel-guard-brown.vercel.app/api/scan?chain=bsc|ethereum&token=0x…`

Try it: [LUNOR on Ethereum](https://sentinel-guard-brown.vercel.app/api/scan?chain=ethereum&token=0x664A01238C9ad0Bee5EB5C4cC899e91A4b96e925) · [WBNB on BSC](https://sentinel-guard-brown.vercel.app/api/scan?chain=bsc&token=0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c)

---

## The problem

Every week, retail buyers on BNB Smart Chain and Ethereum lose money to token contracts whose owners quietly hold powers the buyers never saw: the owner mints new supply and dumps it, blacklists a seller's wallet, raises the sell fee to 99%, pauses all transfers, or upgrades the contract logic overnight into something else entirely. None of this is hidden on-chain — it is all sitting in the deployed bytecode and contract state — but block explorers bury it across a dozen tabs, in hex, with no verdict. By the time a buyer figures it out, the exit is gone.

Sentinel exists so that checking takes ten seconds instead of an audit.

## Who it helps

- **Retail token buyers** who can paste an address but cannot read bytecode.
- **Wallet and community moderators** who need a fast, explainable first screen before listing or pinning a token.
- **Other agents** — the report is plain JSON with published weights, so any automated buyer can consume it as one signal among several.

## What it does

Give Sentinel an EVM token contract address on BSC or Ethereum. It pins the latest block, then runs eight checks against live on-chain state at that exact block:

1. **Contract check** — `eth_getCode`: no bytecode → verdict `NOT_A_CONTRACT`.
2. **ERC-20 metadata** — `name()`, `symbol()`, `decimals()`, `totalSupply()` via `eth_call`. If they don't all answer, the token is flagged as not a standard ERC-20.
3. **Ownership** — `owner()`: a live owner address, a renounced owner (zero address), or no `owner()` function at all.
4. **Pausable state** — `paused()`: whether the contract can halt transfers, and whether it is paused *right now*.
5. **Upgradeability** — the EIP-1967 implementation storage slot (`0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`). A non-zero implementation means the contract's logic can be swapped after you buy.
6. **Dangerous-selector scan** — the runtime bytecode is searched for the 4-byte selectors of 23 known owner-power functions, computed at runtime with Keccak-256: mint variants, `pause()`/`unpause()`, blacklist functions, fee-setting functions (`setTaxFeePercent`, `setBuyFee`, `setSellFee`, `setMaxTxAmount`, `excludeFromFee`, …), `upgradeTo`/`upgradeToAndCall`, owner-transfer functions, and withdraw functions. Findings are grouped as **MINT, PAUSE, BLACKLIST, FEE_CONTROL, UPGRADE, OWNER_CONTROL, WITHDRAW** and worded honestly: *"selector present in deployed bytecode — capability likely available to the owner."*
7. **Liquidity** — the main V2 factory (PancakeSwap V2 on BSC, Uniswap V2 on Ethereum) is asked for a pair against WBNB/WETH. If one exists, Sentinel reports the pair address, its reserves, and the pair's token balance as a percentage of total supply.
8. **Concentration** — `balanceOf(owner)` as a percentage of total supply, when a live owner exists.

## How the score works

The score starts at **100** and deductions are subtracted (floor 0). Every deduction is listed in the report with its reason and evidence, so the score is fully explainable — never a black box.

| Rule | Points |
|---|---|
| Ownership not renounced (a live `owner()` exists) | −15 |
| Mint capability present in bytecode | −20 |
| Blacklist capability present in bytecode | −15 |
| Upgradeable proxy (EIP-1967) or upgrade functions present | −15 |
| No liquidity pair on the main V2 factory | −15 |
| Pause capability present in bytecode | −10 |
| Fee-control capability present in bytecode | −10 |
| Owner holds more than 10% of total supply | −10 |

| Score | Band |
|---|---|
| 80–100 | LOWER RISK |
| 60–79 | MODERATE |
| 40–59 | HIGH |
| 0–39 | EXTREME |

This is a **heuristic screen, not a guarantee**. A clean score does not make a token safe; a bad score tells you exactly which powers to investigate before trusting it.

## How to verify a report

Every report is pinned to a `blockNumber` and includes the raw evidence values (total supply, owner address, reserves, balances, bytecode size, the RPC endpoint used). To reproduce a verdict, re-run the same calls at that block against any node:

- `eth_getCode(token, block)` — bytecode for the selector scan
- `eth_call` for `name()` `0x06fdde03`, `symbol()` `0x95d89b41`, `decimals()` `0x313ce567`, `totalSupply()` `0x18160ddd`, `owner()` `0x8da5cb5b`, `paused()` `0x5c975abb`, `balanceOf(address)` `0x70a08231`, `getPair(address,address)` `0xe6a43905` on the factory, `getReserves()` `0x0902f1ac` on the pair
- `eth_getStorageAt(token, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, block)` — EIP-1967 implementation

Same block, same calls, same evidence, same score. No trust in Sentinel required.

## Architecture

- **Zero-framework Vercel project** — one Node serverless function (`api/scan.mjs`) plus a static demo page (`public/index.html`). Core logic lives in `lib/scan.mjs` and is shared by the endpoint and the local test harness.
- **One dependency: ethers v6**, used only for Keccak-256 function selectors and ABI encoding/decoding. All chain access is raw `fetch` JSON-RPC, which makes multi-endpoint fallback trivial.
- **Public RPC with fallbacks** — BSC: Binance dataseeds and PublicNode; Ethereum: LlamaRPC, PublicNode, Ankr. Each endpoint gets a ~6 s timeout; transport failures fall through to the next endpoint, while an execution revert is treated as a definitive on-chain answer.
- **Read-only, no keys, no custody.** Sentinel holds no private keys, signs nothing, moves nothing, and needs no API keys. It cannot be drained because there is nothing to drain.

## Limitations

- **Selector presence is a bytecode heuristic.** A 4-byte selector found in deployed bytecode strongly suggests the function exists, but selectors can theoretically appear inside unrelated data, and a capability can hide behind a proxy or a differently-named function. Absence of a selector is not proof of absence of the power.
- **No holder-list indexing.** Concentration is checked for the owner and the liquidity pair only — not the full holder distribution.
- **Liquidity is checked on the main V2 factory only** (PancakeSwap V2 / Uniswap V2). A token liquid only on V3, another DEX, or another quote asset will show "no V2 pair".
- **State is a snapshot.** Ownership, fees, and pause state can change in the next block; the pinned block number tells you exactly which moment the report describes.
- **Not financial advice.** Sentinel is a screening aid. It does not evaluate the team, the tokenomics, the audit quality, or whether you should buy anything.

## Built for Agent Games — Wildcard track

Sentinel was built as a Wildcard entry for **Agent Games by zkVerify**: an open-build track for Web3 agents, where it competes as a wallet-security agent. The same operator runs a **Proof Gatekeeper** agent in the main tournament — an agent that judges proof-backed payment claims and writes a Groth16 zero-knowledge proof of every decision, verified on-chain via zkVerify/Kurier. Sentinel applies the same philosophy to token safety: *don't trust the agent's verdict — check the evidence yourself.* Where the Gatekeeper proves its decisions with ZK proofs, Sentinel pins its evidence to a block so anyone can re-run the calls and reach the same conclusion.

## Local development

```bash
npm install
node test_local.mjs   # runs the scanner against LUNOR (Ethereum) and WBNB (BSC), writes test_*.json
```

## License

MIT
