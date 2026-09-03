// scripts/measure_testnet.js
//
// Final measurement session. Generating all the figures for the paper in a single run.
// 1) Table 3: single transaction gas per operation (non-timeout path)
// 2) Table 4: N=100 verification (proof gen, gas, latency)
// 3) fail-early: gas rejection due to status and invalid proof
//
// Run: npx hardhat run scripts/measure_testnet.js --network amoy
//
// Not measured (requires time manipulation; already tested on localhost):
// 1) finalizeRevocation timeout SUSPENDED/CONTESTED
// 2) rejection due to expiration
// The figures were obtained from the localhost session and labeled as described in the paper.
//
// All time calculations use block.timestamp (chain time) rather than Date.now() to ensure birthCutoff always aligns with the contract's _validCutoff.

const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const fs   = require("fs");
const path = require("path");
require("dotenv").config();

const core = require("./issuerCore");

const WASM = path.join(__dirname, "..", "circuits", "identity_check_js", "identity_check.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "identity_check_final.zkey");

const CFG = {
  N_VERIFY:      100,
  COHORT_SIZE:   5,
  AGE_THRESHOLD: 18,
  REGION:        3273n,
  DELAY_MS:      1500,   // Inter-transaction delay to prevent flooding the Amoy RPC.
};

const GAS = {
  maxPriorityFeePerGas: 30000000000n,  // 30 Gwei
  maxFeePerGas:         60000000000n,  // 60 Gwei
};

// util
function fmtProof(p) {
  return {
    a: [p.pi_a[0], p.pi_a[1]],
    b: [[p.pi_b[0][1], p.pi_b[0][0]], [p.pi_b[1][1], p.pi_b[1][0]]],
    c: [p.pi_c[0], p.pi_c[1]],
  };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function stats(a) {
  if (!a.length) return { n: 0, mean: 0, sd: 0, min: 0, max: 0 };
  const n = a.length, mean = a.reduce((x, y) => x + y, 0) / n;
  const sd = Math.sqrt(a.reduce((x, y) => x + (y - mean) ** 2, 0) / n);
  return { n, mean: +mean.toFixed(4), sd: +sd.toFixed(4), min: Math.min(...a), max: Math.max(...a) };
}
function ci95(a) {
  if (a.length < 2) return [0, 0];
  const n = a.length, mean = a.reduce((x, y) => x + y, 0) / n;
  const sd = Math.sqrt(a.reduce((x, y) => x + (y - mean) ** 2, 0) / (n - 1));
  const h = 1.96 * sd / Math.sqrt(n);
  return [+(mean - h).toFixed(2), +(mean + h).toFixed(2)];
}
async function chainNow() { return (await ethers.provider.getBlock("latest")).timestamp; }

async function birthFromChain(yearsOld) {
  const now = await chainNow();
  return BigInt(now - Math.floor(yearsOld * 365.25 * 24 * 3600)) + core.EPOCH_OFFSET;
}
async function birthCutoffFromChain(ageThreshold) {
  const now = BigInt(await chainNow());
  const today = (now / 86400n) * 86400n;
  return today - BigInt(ageThreshold) * core.SECONDS_PER_YEAR + core.EPOCH_OFFSET;
}

async function mintOne(zkSBT, issuer, chainId, contract, holder, expiry) {
  const secretID = BigInt(ethers.keccak256(ethers.toUtf8Bytes("secretID:" + holder.address))) % core.SNARK_FIELD;
  const secretSalt = core.randomSalt();
  const birthTimestamp = await birthFromChain(30);
  const domicileCode = CFG.REGION;
  const commitment = await core.computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode });
  const cid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
  const nonce = await zkSBT.issuanceNonce(holder.address);
  const sig = await core.signMint(issuer, { chainId, contract, holder: holder.address, commitmentBytes32: commitment.bytes32, cid, expiry: BigInt(expiry), nonce });
  const rcpt = await (await zkSBT.connect(issuer).mintIdentity(holder.address, commitment.bytes32, cid, expiry, nonce, sig, GAS)).wait();
  const tokenId = await zkSBT.holderToken(holder.address);
  return { rcpt, tokenId, cred: { secretID, secretSalt, birthTimestamp, domicileCode } };
}

async function buildVerifyProof(zkSBT, chainId, contract, cred, verifierAddr, explicitNonce) {
  const nonce = (explicitNonce !== undefined)
    ? explicitNonce
    : await zkSBT.verifierNonce(verifierAddr);
  const challenge = core.verifyChallenge({ chainId, contract, verifier: verifierAddr, nonce });
  const birthCutoff = await birthCutoffFromChain(CFG.AGE_THRESHOLD);
  const input = {
    onChainHash:      (await core.computeCommitment(cred)).field.toString(),
    birthCutoff:      birthCutoff.toString(),
    regionCode:       cred.domicileCode.toString(),
    sessionChallenge: challenge.toString(),
    secretID:         cred.secretID.toString(),
    secretSalt:       cred.secretSalt.toString(),
    birthTimestamp:   cred.birthTimestamp.toString(),
    domicileCode:     cred.domicileCode.toString(),
  };
  const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { ...fmtProof(proof), birthCutoff };
}
async function callVerify(zkSBT, caller, tokenId, pr) {
  let predicted;
  try {
    predicted = await zkSBT.connect(caller).verifyIdentityAccess.staticCall(
      tokenId, pr.a, pr.b, pr.c, CFG.AGE_THRESHOLD, pr.birthCutoff, CFG.REGION
    );
  } catch { predicted = false; }

  const tx = await zkSBT.connect(caller).verifyIdentityAccess(tokenId, pr.a, pr.b, pr.c, CFG.AGE_THRESHOLD, pr.birthCutoff, CFG.REGION, GAS);
  const rcpt = await tx.wait();

  const accepted = rcpt.status === 1 && predicted === true;
  return { gas: Number(rcpt.gasUsed), accepted, rcpt };
}

async function main() {
  console.log("=".repeat(60));
  console.log("zkSBT — Testnet Measurement");
  console.log("=".repeat(60));

  const dep = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployment.json"), "utf8"));
  const net = await ethers.provider.getNetwork();
  if (net.chainId.toString() !== dep.chainId) throw new Error(`chainId active ${net.chainId} != deployment.json ${dep.chainId}`);
  const chainId = net.chainId, contract = dep.zkSBT;
  const [issuer] = await ethers.getSigners();
  if (issuer.address.toLowerCase() !== dep.issuer.toLowerCase()) throw new Error("The signer is not the deployment issuer");
  const zkSBT = await ethers.getContractAt("ZkSBT", contract);
  const verifierAddr = issuer.address;

  const bal = await ethers.provider.getBalance(issuer.address);
  console.log("Balance:", ethers.formatEther(bal), "POL\n");

  const results = { table4: {}, verify: { proofGen: [], gas: [], latency: [] }, rejection: {} };

  // PHASE 1: Table 3 Single gas (non-timeout operation)
  console.log("[Phase 1] Table 3 — single transaction gas");
  const holderW = ethers.Wallet.createRandom().connect(ethers.provider);
  /// fund the holder so they can submit a dispute
  await (await issuer.sendTransaction({ to: holderW.address, value: ethers.parseEther("0.5"), ...GAS })).wait();

  const m = await mintOne(zkSBT, issuer, chainId, contract, holderW, 0);
  results.table3.mint = Number(m.rcpt.gasUsed);
  console.log("  mint                :", results.table3.mint.toLocaleString());
  await sleep(CFG.DELAY_MS);

  { /// first requestRevoke
    const rcpt = await (await zkSBT.connect(issuer).requestRevoke(m.tokenId, "measure", [], GAS)).wait();
    results.table3.requestRevoke = Number(rcpt.gasUsed);
    console.log("  requestRevoke       :", results.table3.requestRevoke.toLocaleString());
    await sleep(CFG.DELAY_MS);
  }
  { /// disputeRevocation
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const challenge = core.disputeChallenge({ chainId, contract, tokenId: m.tokenId, disputeCount: dc });
    const birthCutoff = await birthCutoffFromChain(CFG.AGE_THRESHOLD);
    const input = {
      onChainHash: (await core.computeCommitment(m.cred)).field.toString(),
      birthCutoff: birthCutoff.toString(), regionCode: m.cred.domicileCode.toString(),
      sessionChallenge: challenge.toString(),
      secretID: m.cred.secretID.toString(), secretSalt: m.cred.secretSalt.toString(),
      birthTimestamp: m.cred.birthTimestamp.toString(), domicileCode: m.cred.domicileCode.toString(),
    };
    const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const pr = fmtProof(proof);
    const rcpt = await (await zkSBT.connect(holderW).disputeRevocation(m.tokenId, pr.a, pr.b, pr.c, birthCutoff, CFG.REGION, GAS)).wait();
    results.table3.disputeRevocation = Number(rcpt.gasUsed);
    console.log("  disputeRevocation   :", results.table3.disputeRevocation.toLocaleString());
    await sleep(CFG.DELAY_MS);
  }
  { /// resolveDispute uphold=true (mnemonic deploy panel)
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const mn = ethers.Mnemonic.fromPhrase(process.env.PANEL_MNEMONIC);
    const panel = []; for (let i = 0; i < 5; i++) panel.push(ethers.HDNodeWallet.fromMnemonic(mn, `m/44'/60'/1'/0/${i}`));
    const threshold = Number(await zkSBT.threshold());
    const payload = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "address", "bytes32", "uint256", "uint16", "bool"],
      [chainId, contract, core.domSep(core.DOM.VERDICT), m.tokenId, dc, true]
    ));
    const sorted = [...panel].sort((a, b) => BigInt(a.address) < BigInt(b.address) ? -1 : 1).slice(0, threshold);
    const sigs = []; for (const w of sorted) sigs.push(await w.signMessage(ethers.getBytes(payload)));
    const rcpt = await (await zkSBT.connect(issuer).resolveDispute(m.tokenId, true, sigs, GAS)).wait();
    results.table3.resolveDispute = Number(rcpt.gasUsed);
    console.log("  resolveDispute      :", results.table3.resolveDispute.toLocaleString());
    await sleep(CFG.DELAY_MS);
  }

  // PHASE 2: fail-early status, invalid proof
  console.log("\n[Phase 2] fail-early gas");
  { /// status non-VALID
    const h = ethers.Wallet.createRandom();
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h, 0);
    const pr = await buildVerifyProof(zkSBT, chainId, contract, mm.cred, verifierAddr);
    await (await zkSBT.connect(issuer).requestRevoke(mm.tokenId, "reject test", [], GAS)).wait();
    const { gas, accepted } = await callVerify(zkSBT, issuer, mm.tokenId, pr);
    if (accepted) throw new Error("Status ought to be rejected");
    results.rejection.status = gas;
    console.log("  reject status    :", gas.toLocaleString());
    await sleep(CFG.DELAY_MS);
  }
  { /// invalid proof
    const h = ethers.Wallet.createRandom();
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h, 0);
    const nfresh = await zkSBT.verifierNonce(verifierAddr);
    const pr = await buildVerifyProof(zkSBT, chainId, contract, mm.cred, verifierAddr, nfresh);
    const bad = { ...pr, a: [ (BigInt(pr.a[0]) ^ 1n).toString(), pr.a[1] ] };
    const { gas, accepted, rcpt } = await callVerify(zkSBT, issuer, mm.tokenId, bad);
    if (accepted) throw new Error("Proof ought to be rejected");
    
    if (gas > 5_000_000) {
      console.warn("  Proof gas anomaly (" + gas + "), status tx: " + rcpt.status + " — skipped");
      results.rejection.invalid_proof = null;
    } else {
      results.rejection.invalid_proof = gas;
    }
    console.log("  Reject proof     :", results.rejection.invalid_proof === null ? "anomaly, check manually" : gas.toLocaleString());
    await sleep(CFG.DELAY_MS);
  }

  // PHASE 3: N=100 verification
  console.log("\n[Phase 3] Verifikasi N=" + CFG.N_VERIFY);
  const cohort = [];
  for (let k = 0; k < CFG.COHORT_SIZE; k++) {
    const h = ethers.Wallet.createRandom();
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h, 0);
    cohort.push({ ...mm.cred, tokenId: mm.tokenId });
    process.stdout.write("  mint cohort " + (k + 1) + "/" + CFG.COHORT_SIZE + "\r");
    await sleep(CFG.DELAY_MS);
  }
  console.log("\n  cohort ready, start verification.");

  const csv = [];
  let rejectedCount = 0;
  for (let i = 0; i < CFG.N_VERIFY; i++) {
    const c = cohort[i % cohort.length];
    /// Read the nonce from the chain at each iteration.
    const vNonce = await zkSBT.verifierNonce(verifierAddr);
    const t0 = Date.now();
    const pr = await buildVerifyProof(zkSBT, chainId, contract, c, verifierAddr, vNonce);
    const pgMs = Date.now() - t0;
    const t1 = Date.now();
    const { gas, accepted } = await callVerify(zkSBT, issuer, c.tokenId, pr);
    const latMs = Date.now() - t1;
    if (!accepted) rejectedCount++;
    results.verify.proofGen.push(pgMs);
    results.verify.gas.push(gas);
    results.verify.latency.push(latMs);
    csv.push(["valid", i + 1, c.tokenId.toString(), pgMs, gas, latMs, accepted ? "success" : "rejected"].join(","));
    process.stdout.write("  verify " + (i + 1) + "/" + CFG.N_VERIFY + " (rejected: " + rejectedCount + ")\r");
    if (CFG.DELAY_MS) await sleep(CFG.DELAY_MS);
  }
  console.log("\n  done. Rejected: " + rejectedCount + "/" + CFG.N_VERIFY);
  if (rejectedCount > 0) {
    console.warn("  Existing " + rejectedCount + " real rejections. Filter CSV outcome=success before statistics.");
  }

  const warm = results.verify.proofGen.slice(1);
  const pgFull = stats(results.verify.proofGen), pgWarm = stats(warm), pgCI = ci95(warm);
  const g = stats(results.verify.gas), l = stats(results.verify.latency), lCI = ci95(results.verify.latency);

  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "verify_100.csv"), ["scenario,index,tokenId,proofGenMs,gasUsed,latencyMs,outcome", ...csv].join("\n"));
  fs.writeFileSync(path.join(outDir, "results_testnet.json"), JSON.stringify({
    table3: results.table3,
    rejection: results.rejection,
    verify_summary: {
      proofGen_full: pgFull, proofGen_warm: pgWarm, proofGen_warm_ci95: pgCI,
      gas: g, latency: l, latency_ci95: lCI,
    },
  }, null, 2));
  console.log("Written: results/verify_100.csv, results/results_testnet.json\n");

  console.log("=".repeat(60));
  console.log("RESULT SUMMARY");
  console.log("=".repeat(60));
  console.log("Table 3 (single gas):");
  for (const [k, v] of Object.entries(results.table3)) console.log("  " + k.padEnd(20) + v.toLocaleString());
  console.log("\nfail-early:");
  console.log("  reject status        " + results.rejection.status.toLocaleString());
  const ip = results.rejection.invalid_proof;
  console.log("  reject proof invalid   " + (ip == null ? "N/A (gasUsed RPC anomaly; see notes)" : ip.toLocaleString()));
  console.log("  (rejection of the proof to run full pairing; status is much cheaper)");
  console.log("\nTable 4 (N=100 verification):");
  console.log("  proof gen full  : mean " + pgFull.mean + " ms, SD " + pgFull.sd + ", max " + pgFull.max);
  console.log("  proof gen warm  : mean " + pgWarm.mean + " ms, SD " + pgWarm.sd + ", 95% CI [" + pgCI[0] + ", " + pgCI[1] + "]");
  console.log("  gas             : mean " + g.mean + ", range [" + g.min + ", " + g.max + "]");
  console.log("  latency         : mean " + l.mean + " ms, SD " + l.sd + ", 95% CI [" + lCI[0] + ", " + lCI[1] + "]");
  console.log("=".repeat(60));

  process.exit(0);
}

main().catch((e) => { console.error("\n[FATAL]", e.message || e); process.exit(1); });