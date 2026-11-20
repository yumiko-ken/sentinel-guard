// Sentinel — Token Risk Guard: core scanner.
//
// Read-only, keyless, custody-free. Every check is a plain JSON-RPC call
// (eth_blockNumber / eth_getCode / eth_call / eth_getStorageAt) pinned to a
// single block, so anyone can re-run the exact same calls at that block and
// reproduce the verdict.

import { AbiCoder, getAddress, id as ethersId } from "ethers";

const coder = AbiCoder.defaultAbiCoder();
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

export const CHAINS = {
  bsc: {
    label: "BNB Smart Chain",
    rpcs: [
      "https://bsc-dataseed.binance.org",
      "https://bsc-dataseed1.defibit.io",
      "https://bsc.publicnode.com",
    ],
    factory: "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73", // PancakeSwap V2
    factoryName: "PancakeSwap V2",
    quote: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", // WBNB
    quoteSymbol: "WBNB",
  },
  ethereum: {
    label: "Ethereum",
    rpcs: [
      "https://eth.llamarpc.com",
      "https://ethereum.publicnode.com",
      "https://rpc.ankr.com/eth",
    ],
    factory: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", // Uniswap V2
    factoryName: "Uniswap V2",
    quote: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    quoteSymbol: "WETH",
  },
};

// Dangerous owner capabilities, by group. Presence of a 4-byte selector in
// the deployed runtime bytecode means the capability is *likely* available
// (bytecode heuristic — see README limitations).
export const CAPABILITY_GROUPS = {
  MINT: ["mint(address,uint256)", "mint(uint256)", "mint(address)"],
  PAUSE: ["pause()", "unpause()"],
  BLACKLIST: [
    "addToBlacklist(address)",
    "blacklist(address)",
    "setBlacklist(address,bool)",
  ],
  FEE_CONTROL: [
    "setFees(uint256,uint256)",
    "setFee(uint256)",
    "setTaxFeePercent(uint256)",
    "setLiquidityFeePercent(uint256)",
    "setBuyFee(uint256)",
    "setSellFee(uint256)",
    "setMaxTxAmount(uint256)",
    "excludeFromFee(address)",
    "setSwapAndLiquifyEnabled(bool)",
  ],
  UPGRADE: ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
  OWNER_CONTROL: ["setOwner(address)", "changeOwner(address)"],
  WITHDRAW: ["withdraw()", "withdraw(uint256)"],
};

// Published scoring weights (start at 100, floor 0).
export const WEIGHTS = [
  { rule: "Ownership not renounced (a live owner() exists)", points: -15 },
  { rule: "Mint capability present in bytecode", points: -20 },
  { rule: "Pause capability present in bytecode", points: -10 },
  { rule: "Blacklist capability present in bytecode", points: -15 },
  { rule: "Fee-control capability present in bytecode", points: -10 },
  { rule: "Upgradeable proxy (EIP-1967 implementation set) or upgrade functions present", points: -15 },
  { rule: "No liquidity pair on the main V2 factory", points: -15 },
  { rule: "Owner holds more than 10% of total supply", points: -10 },
];

export function bandFor(score) {
  if (score >= 80) return "LOWER RISK";
  if (score >= 60) return "MODERATE";
  if (score >= 40) return "HIGH";
  return "EXTREME";
}

function selectorOf(signature) {
  return ethersId(signature).slice(0, 10); // 0x + 4 bytes
}

// --- JSON-RPC with per-endpoint fallback ---------------------------------

async function rpcOnce(endpoint, method, params, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ctrl.signal,
    });
    if (!res.ok) return { transport: true, detail: `HTTP ${res.status}` };
    const json = await res.json();
    if (json.error) {
      // Execution revert / method error: a definitive answer from the chain,
      // not a transport failure — do not fall through to the next RPC.
      return { revert: true, detail: json.error.message || "rpc error" };
    }
    return { result: json.result };
  } catch (e) {
    return { transport: true, detail: String(e && e.message ? e.message : e) };
  } finally {
    clearTimeout(timer);
  }
}

// Returns { result } on success, { revert: true } on execution error,
// throws only when every endpoint failed at the transport level.
async function rpc(chainCfg, method, params, timeoutMs = 6000) {
  let lastDetail = "no endpoints";
  for (const endpoint of chainCfg.rpcs) {
    const out = await rpcOnce(endpoint, method, params, timeoutMs);
    if (!out.transport) return { ...out, endpoint };
    lastDetail = out.detail;
  }
  throw new Error(`All RPC endpoints failed for ${method}: ${lastDetail}`);
}

async function ethCall(chainCfg, to, signature, args, argTypes, blockTag) {
  const data =
    selectorOf(signature) +
    (argTypes.length ? coder.encode(argTypes, args).slice(2) : "");
  const out = await rpc(chainCfg, "eth_call", [{ to, data }, blockTag]);
  if (out.revert || !out.result || out.result === "0x") return null;
  return out.result;
}

function decode(types, data) {
  try {
    return coder.decode(types, data);
  } catch {
    return null;
  }
}

function decodeString(data) {
  const asString = decode(["string"], data);
  if (asString) return asString[0];
  // Legacy tokens (e.g. old MKR) return bytes32 instead of a string.
  const asBytes = decode(["bytes32"], data);
  if (asBytes) {
    const hex = asBytes[0].slice(2);
    let s = "";
    for (let i = 0; i < hex.length; i += 2) {
      const code = parseInt(hex.slice(i, i + 2), 16);
      if (code === 0) break;
      s += String.fromCharCode(code);
    }
    return s || null;
  }
  return null;
}

function pctOf(part, whole) {
  if (whole === 0n) return null;
  return Number((part * 10000n) / whole) / 100;
}

function formatUnits(raw, decimals) {
  const neg = raw < 0n;
  const digits = (neg ? -raw : raw).toString().padStart(decimals + 1, "0");
  const intPart = decimals === 0 ? digits : digits.slice(0, -decimals);
  const fracPart = decimals === 0 ? "" : digits.slice(-decimals).replace(/0+$/, "");
  return (neg ? "-" : "") + intPart + (fracPart ? "." + fracPart : "");
}

// --- The scan --------------------------------------------------------------

export async function scanToken(chainKey, tokenInput) {
  const chainCfg = CHAINS[chainKey];
  if (!chainCfg) throw Object.assign(new Error(`Unknown chain: ${chainKey}`), { status: 400 });
  if (!/^0x[0-9a-fA-F]{40}$/.test(tokenInput || "")) {
    throw Object.assign(new Error("Invalid token address format"), { status: 400 });
  }
  const token = getAddress(tokenInput); // checksummed
  const tokenLower = token.toLowerCase();

  const findings = [];
  const evidence = {};
  const add = (severity, code, message, ev) =>
    findings.push({ severity, code, message, ...(ev ? { evidence: ev } : {}) });

  // Pin everything to one block so the report is reproducible.
  const blockOut = await rpc(chainCfg, "eth_blockNumber", []);
  const blockNumber = parseInt(blockOut.result, 16);
  const blockTag = "0x" + blockNumber.toString(16);
  evidence.blockNumber = blockNumber;
  evidence.rpcEndpoint = blockOut.endpoint;

  const report = {
    tool: "Sentinel — Token Risk Guard",
    version: "1.0.0",
    chain: chainKey,
    chainLabel: chainCfg.label,
    token,
    blockNumber,
    blockTag,
    scannedAt: new Date().toISOString(),
    disclaimer:
      "Heuristic screening aid only — not financial advice, not a guarantee of safety.",
  };

  // 1. Code presence
  const codeOut = await rpc(chainCfg, "eth_getCode", [token, blockTag]);
  const code = codeOut.revert ? "0x" : codeOut.result || "0x";
  evidence.codeBytes = (code.length - 2) / 2;
  if (code === "0x" || code.length <= 2) {
    report.verdict = "NOT_A_CONTRACT";
    report.score = null;
    report.band = null;
    add("high", "NOT_A_CONTRACT", "Address holds no deployed bytecode at the pinned block — it is not a contract.");
    report.findings = findings;
    report.evidence = evidence;
    return report;
  }

  // 2. ERC-20 metadata
  const [nameRaw, symbolRaw, decimalsRaw, supplyRaw] = await Promise.all([
    ethCall(chainCfg, token, "name()", [], [], blockTag),
    ethCall(chainCfg, token, "symbol()", [], [], blockTag),
    ethCall(chainCfg, token, "decimals()", [], [], blockTag),
    ethCall(chainCfg, token, "totalSupply()", [], [], blockTag),
  ]);
  const name = nameRaw ? decodeString(nameRaw) : null;
  const symbol = symbolRaw ? decodeString(symbolRaw) : null;
  const decimalsDec = decimalsRaw ? decode(["uint256"], decimalsRaw) : null;
  const decimals = decimalsDec ? Number(decimalsDec[0]) : null;
  const supplyDec = supplyRaw ? decode(["uint256"], supplyRaw) : null;
  const totalSupply = supplyDec ? supplyDec[0] : null;
  const standardErc20 = !!(name && symbol && decimals !== null && totalSupply !== null);
  report.tokenInfo = {
    name,
    symbol,
    decimals,
    totalSupplyRaw: totalSupply !== null ? totalSupply.toString() : null,
    totalSupplyFormatted:
      totalSupply !== null && decimals !== null ? formatUnits(totalSupply, decimals) : null,
    standardErc20,
  };
  evidence.totalSupplyRaw = report.tokenInfo.totalSupplyRaw;
  if (!standardErc20) {
    add("medium", "NOT_STANDARD_ERC20", "name()/symbol()/decimals()/totalSupply() did not all answer — not a standard ERC-20 interface.");
  }

  // 3. Ownership
  const ownerRaw = await ethCall(chainCfg, token, "owner()", [], [], blockTag);
  let owner = null;
  let ownerNote;
  if (ownerRaw) {
    const dec = decode(["address"], ownerRaw);
    if (dec) owner = getAddress(dec[0]);
  }
  const renounced = owner !== null && owner.toLowerCase() === ZERO_ADDRESS;
  if (owner === null) ownerNote = "no owner() function";
  else if (renounced) ownerNote = "ownership renounced (owner is the zero address)";
  else ownerNote = "live owner present";
  report.ownership = { owner, renounced: owner === null ? null : renounced, note: ownerNote };
  evidence.ownerRaw = owner;
  if (owner && !renounced) {
    add("medium", "LIVE_OWNER", `Contract has a live owner: ${owner}. Owner powers below apply to a real, controllable address.`);
  } else if (renounced) {
    add("info", "RENOUNCED", "Ownership is renounced (owner() returns the zero address).");
  } else {
    add("info", "NO_OWNER_FN", "Contract exposes no owner() function.");
  }

  // 4. Pausable state
  const pausedRaw = await ethCall(chainCfg, token, "paused()", [], [], blockTag);
  let pausable = null;
  if (pausedRaw) {
    const dec = decode(["bool"], pausedRaw);
    if (dec) pausable = { hasPausedFunction: true, currentlyPaused: Boolean(dec[0]) };
  }
  report.pausable = pausable || { hasPausedFunction: false, currentlyPaused: null };
  if (pausable) {
    add(pausable.currentlyPaused ? "high" : "medium", "PAUSABLE",
      pausable.currentlyPaused
        ? "Contract is pausable and is CURRENTLY PAUSED — transfers are halted."
        : "Contract is pausable (paused() exists); the owner can halt transfers.");
    evidence.currentlyPaused = pausable.currentlyPaused;
  }

  // 5. EIP-1967 proxy
  const implOut = await rpc(chainCfg, "eth_getStorageAt", [token, EIP1967_IMPL_SLOT, blockTag]);
  let implementation = null;
  if (!implOut.revert && implOut.result && implOut.result !== "0x" + "0".repeat(64)) {
    const dec = decode(["address"], implOut.result);
    if (dec && dec[0].toLowerCase() !== ZERO_ADDRESS) implementation = getAddress(dec[0]);
  }
  report.proxy = { isProxy: !!implementation, implementation, slot: EIP1967_IMPL_SLOT };
  evidence.eip1967Implementation = implementation;
  if (implementation) {
    add("high", "UPGRADEABLE_PROXY", `EIP-1967 proxy — logic can be replaced by upgrading to implementation ${implementation}. Today's behaviour is not the final behaviour.`);
  }

  // 6. Dangerous-selector scan of the runtime bytecode
  const codeHex = code.slice(2).toLowerCase();
  const capabilities = {};
  const capabilityDetails = [];
  for (const [group, sigs] of Object.entries(CAPABILITY_GROUPS)) {
    const present = [];
    for (const sig of sigs) {
      const sel = selectorOf(sig);
      if (codeHex.includes(sel.slice(2))) {
        present.push(sig);
        capabilityDetails.push({ group, signature: sig, selector: sel });
      }
    }
    if (present.length) capabilities[group] = present;
  }
  report.capabilities = capabilities;
  report.capabilityDetails = capabilityDetails;
  const groupSeverity = { MINT: "high", BLACKLIST: "high", PAUSE: "medium", FEE_CONTROL: "medium", UPGRADE: "high", OWNER_CONTROL: "medium", WITHDRAW: "low" };
  const groupLabel = {
    MINT: "Mint — new supply can be created",
    PAUSE: "Pause — transfers can be halted",
    BLACKLIST: "Blacklist — addresses can be frozen out",
    FEE_CONTROL: "Fee control — transfer fees / limits can be changed",
    UPGRADE: "Upgrade — logic-replacement functions present",
    OWNER_CONTROL: "Owner control — ownership can be transferred by function",
    WITHDRAW: "Withdraw — funds can be pulled by a privileged function",
  };
  for (const [group, sigs] of Object.entries(capabilities)) {
    add(groupSeverity[group], `CAP_${group}`,
      `${groupLabel[group]}. Selector present in deployed bytecode — capability likely available to the owner: ${sigs.join(", ")}.`);
  }

  // 7. Liquidity on the main V2 factory
  const isSelfQuote = tokenLower === chainCfg.quote.toLowerCase();
  let liquidity;
  if (isSelfQuote) {
    liquidity = {
      factory: chainCfg.factory, factoryName: chainCfg.factoryName,
      quoteAsset: chainCfg.quote, quoteSymbol: chainCfg.quoteSymbol,
      status: "self_quote_asset", hasPair: null, pair: null,
      note: `This token IS the chain's wrapped native asset (${chainCfg.quoteSymbol}) — it is the quote asset other pairs are built against, so a pair-against-itself check does not apply.`,
    };
    add("info", "SELF_QUOTE", liquidity.note);
  } else {
    const pairRaw = await ethCall(chainCfg, chainCfg.factory, "getPair(address,address)",
      [token, chainCfg.quote], ["address", "address"], blockTag);
    let pair = null;
    if (pairRaw) {
      const dec = decode(["address"], pairRaw);
      if (dec && dec[0].toLowerCase() !== ZERO_ADDRESS) pair = getAddress(dec[0]);
    }
    liquidity = {
      factory: chainCfg.factory, factoryName: chainCfg.factoryName,
      quoteAsset: chainCfg.quote, quoteSymbol: chainCfg.quoteSymbol,
      status: pair ? "pair_found" : "no_pair", hasPair: !!pair, pair,
    };
    if (pair) {
      const [reservesRaw, balRaw] = await Promise.all([
        ethCall(chainCfg, pair, "getReserves()", [], [], blockTag),
        ethCall(chainCfg, token, "balanceOf(address)", [pair], ["address"], blockTag),
      ]);
      const resDec = reservesRaw ? decode(["uint256", "uint256", "uint256"], reservesRaw) : null;
      const balDec = balRaw ? decode(["uint256"], balRaw) : null;
      if (resDec) {
        liquidity.reserves = { reserve0: resDec[0].toString(), reserve1: resDec[1].toString(), blockTimestampLast: Number(resDec[2]) };
        evidence.pairReserves = liquidity.reserves;
      }
      if (balDec) {
        liquidity.tokenBalanceInPairRaw = balDec[0].toString();
        liquidity.pctOfSupplyInPair = totalSupply ? pctOf(balDec[0], totalSupply) : null;
        evidence.pairTokenBalanceRaw = liquidity.tokenBalanceInPairRaw;
      }
      add("info", "LIQUIDITY_PAIR", `${chainCfg.factoryName} pair exists: ${pair}` +
        (liquidity.pctOfSupplyInPair !== null ? ` holding ${liquidity.pctOfSupplyInPair}% of total supply.` : "."));
    } else {
      add("medium", "NO_V2_LIQUIDITY", `No ${chainCfg.factoryName} pair against ${chainCfg.quoteSymbol} — no V2 liquidity found on the main factory.`);
    }
  }
  report.liquidity = liquidity;

  // 8. Owner concentration
  let concentration = { ownerBalanceRaw: null, ownerPctOfSupply: null };
  if (owner && !renounced && totalSupply) {
    const balRaw = await ethCall(chainCfg, token, "balanceOf(address)", [owner], ["address"], blockTag);
    const balDec = balRaw ? decode(["uint256"], balRaw) : null;
    if (balDec) {
      concentration = {
        ownerBalanceRaw: balDec[0].toString(),
        ownerPctOfSupply: pctOf(balDec[0], totalSupply),
      };
      evidence.ownerBalanceRaw = concentration.ownerBalanceRaw;
      if (concentration.ownerPctOfSupply !== null && concentration.ownerPctOfSupply > 10) {
        add("medium", "OWNER_CONCENTRATION", `Owner holds ${concentration.ownerPctOfSupply}% of total supply — a single wallet can move the market.`);
      }
    }
  }
  report.concentration = concentration;

  // --- Scoring (published weights, fully explainable) ----------------------
  const deductions = [];
  const deduct = (rule, points, detail) => deductions.push({ rule, points, detail });
  const has = (g) => !!capabilities[g];

  if (owner && !renounced) deduct("Ownership not renounced (a live owner() exists)", -15, `owner = ${owner}`);
  if (has("MINT")) deduct("Mint capability present in bytecode", -20, capabilities.MINT.join(", "));
  if (has("PAUSE")) deduct("Pause capability present in bytecode", -10, capabilities.PAUSE.join(", "));
  if (has("BLACKLIST")) deduct("Blacklist capability present in bytecode", -15, capabilities.BLACKLIST.join(", "));
  if (has("FEE_CONTROL")) deduct("Fee-control capability present in bytecode", -10, capabilities.FEE_CONTROL.join(", "));
  if (implementation || has("UPGRADE"))
    deduct("Upgradeable proxy (EIP-1967 implementation set) or upgrade functions present", -15,
      implementation ? `implementation = ${implementation}` : capabilities.UPGRADE.join(", "));
  if (!isSelfQuote && !liquidity.hasPair)
    deduct("No liquidity pair on the main V2 factory", -15, `no ${chainCfg.factoryName} pair vs ${chainCfg.quoteSymbol}`);
  if (concentration.ownerPctOfSupply !== null && concentration.ownerPctOfSupply > 10)
    deduct("Owner holds more than 10% of total supply", -10, `owner holds ${concentration.ownerPctOfSupply}%`);

  const score = Math.max(0, 100 + deductions.reduce((a, d) => a + d.points, 0));
  report.score = score;
  report.band = bandFor(score);
  report.verdict = report.band;
  report.deductions = deductions;
  report.scoring = { start: 100, floor: 0, weights: WEIGHTS };
  report.findings = findings;
  report.evidence = evidence;
  return report;
}
