// scripts/measure_scalability.js
//
// Scalability curve of the three operations versus registry size.
// Demonstrating that gas costs for verify, revoke, and dispute operations remain constant relative to the number of registry entries.
//
// Methodology (as described in the paper):
// 1) Verification is performed on fixed tokenIds (#1 and the middle one) at each checkpoint, as the verification process is read-only and repeatable.
// 2) Revoke and Dispute operations alter the permanent state (VALID -> SUSPENDED -> CONTESTED), meaning re-measurement cannot be performed on the same token; instead, measurement occurs using a fresh token at each checkpoint. The correct hypothesis is still tested because revoke/dispute operations affect a single "warm" slot regardless of the token's position; the test focuses on dependency regarding the number of entries rather than token age. The flow for a dispute victim is: mint -> revoke -> dispute (dispute requires the SUSPENDED state).
//
// npx hardhat run scripts/measure_scalability.js --network amoy

const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const fs   = require("fs");
const path = require("path");
require("dotenv").config();

const core = require("./issuerCore");

const WASM = path.join(__dirname, "..", "circuits", "identity_check_js", "identity_check.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "identity_check_final.zkey");

const CFG = {
  MAX: 1000,
  CHECKPOINTS: [10, 50, 100, 500, 1000],
  AGE_THRESHOLD: 18,
  REGION: 3273n,
  DELAY_MS: 150,
};
const GAS = { maxPriorityFeePerGas: 30000000000n, maxFeePerGas: 60000000000n };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function fmtProof(p) {
  return {
    a: [p.pi_a[0], p.pi_a[1]],
    b: [[p.pi_b[0][1], p.pi_b[0][0]], [p.pi_b[1][1], p.pi_b[1][0]]],
    c: [p.pi_c[0], p.pi_c[1]],
  };
}
async function chainNow() { return (await ethers.provider.getBlock("latest")).timestamp; }
async function birthFromChain(y) {
  const now = await chainNow();
  return BigInt(now - Math.floor(y * 365.25 * 24 * 3600)) + core.EPOCH_OFFSET;
}
async function birthCutoffFromChain(t) {
  const now = BigInt(await chainNow());
  const today = (now / 86400n) * 86400n;
  return today - BigInt(t) * core.SECONDS_PER_YEAR + core.EPOCH_OFFSET;
}

async function mintOne(zkSBT, issuer, chainId, contract, holder) {
  const secretID = BigInt(ethers.keccak256(ethers.toUtf8Bytes("secretID:" + holder.address))) % core.SNARK_FIELD;
  const secretSalt = core.randomSalt();
  const birthTimestamp = await birthFromChain(30);
  const domicileCode = CFG.REGION;
  const commitment = await core.computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode });
  const cid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
  const nonce = await zkSBT.issuanceNonce(holder.address);
  const sig = await core.signMint(issuer, { chainId, contract, holder: holder.address, commitmentBytes32: commitment.bytes32, cid, expiry: 0n, nonce });
  await (await zkSBT.connect(issuer).mintIdentity(holder.address, commitment.bytes32, cid, 0, nonce, sig, GAS)).wait();
  const tokenId = await zkSBT.holderToken(holder.address);
  return { tokenId, cred: { secretID, secretSalt, birthTimestamp, domicileCode } };
}

async function verifyProofFor(zkSBT, chainId, contract, cred, verifierAddr) {
  const nonce = await zkSBT.verifierNonce(verifierAddr);
  const challenge = core.verifyChallenge({ chainId, contract, verifier: verifierAddr, nonce });
  const birthCutoff = await birthCutoffFromChain(CFG.AGE_THRESHOLD);
  const input = {
    onChainHash: (await core.computeCommitment(cred)).field.toString(),
    birthCutoff: birthCutoff.toString(), regionCode: cred.domicileCode.toString(),
    sessionChallenge: challenge.toString(),
    secretID: cred.secretID.toString(), secretSalt: cred.secretSalt.toString(),
    birthTimestamp: cred.birthTimestamp.toString(), domicileCode: cred.domicileCode.toString(),
  };
  const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { ...fmtProof(proof), birthCutoff };
}

async function measureVerify(zkSBT, issuer, chainId, contract, cred, tokenId) {
  const pr = await verifyProofFor(zkSBT, chainId, contract, cred, issuer.address);
  const tx = await zkSBT.connect(issuer).verifyIdentityAccess(
    tokenId, pr.a, pr.b, pr.c, CFG.AGE_THRESHOLD, pr.birthCutoff, CFG.REGION, GAS);
  const rcpt = await tx.wait();
  return Number(rcpt.gasUsed);
}

async function disputeProofFor(zkSBT, chainId, contract, cred, tokenId, disputeCount) {
  const challenge = core.disputeChallenge({ chainId, contract, tokenId, disputeCount });
  const birthCutoff = await birthCutoffFromChain(CFG.AGE_THRESHOLD);
  const input = {
    onChainHash: (await core.computeCommitment(cred)).field.toString(),
    birthCutoff: birthCutoff.toString(), regionCode: cred.domicileCode.toString(),
    sessionChallenge: challenge.toString(),
    secretID: cred.secretID.toString(), secretSalt: cred.secretSalt.toString(),
    birthTimestamp: cred.birthTimestamp.toString(), domicileCode: cred.domicileCode.toString(),
  };
  const { proof } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { ...fmtProof(proof), birthCutoff };
}

async function measureRevokeDispute(zkSBT, issuer, chainId, contract) {
  const victim = ethers.Wallet.createRandom().connect(ethers.provider);
  await (await issuer.sendTransaction({ to: victim.address, value: ethers.parseEther("0.05"), ...GAS })).wait();
  const m = await mintOne(zkSBT, issuer, chainId, contract, victim);

  const rRev = await (await zkSBT.connect(issuer).requestRevoke(m.tokenId, "scalability probe", [], GAS)).wait();
  const gasRevoke = Number(rRev.gasUsed);
  await sleep(CFG.DELAY_MS);

  const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
  const pr = await disputeProofFor(zkSBT, chainId, contract, m.cred, m.tokenId, dc);
  const rDis = await (await zkSBT.connect(victim).disputeRevocation(
    m.tokenId, pr.a, pr.b, pr.c, pr.birthCutoff, CFG.REGION, GAS)).wait();
  const gasDispute = Number(rDis.gasUsed);

  return { gasRevoke, gasDispute };
}

async function main() {
  console.log("=".repeat(60));
  console.log("zkSBT — Scalability (3 ops) vs Registry Size (Testnet)");
  console.log("=".repeat(60));

  const dep = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployment.json"), "utf8"));
  const net = await ethers.provider.getNetwork();
  const chainId = net.chainId, contract = dep.zkSBT;
  const [issuer] = await ethers.getSigners();
  const zkSBT = await ethers.getContractAt("ZkSBT", contract);

  console.log("Balance:", ethers.formatEther(await ethers.provider.getBalance(issuer.address)), "POL");
  console.log("Target:", CFG.MAX, "| checkpoints:", CFG.CHECKPOINTS.join(", "), "\n");

  let firstCred = null, firstTokenId = null, midCred = null, midTokenId = null;
  const midTarget = Math.floor(CFG.MAX / 2);
  const rows = [];
  let extraMinted = 0;

  const runCheckpoint = async (size) => {
    console.log(`\n[checkpoint ${size}]`);
    {
      const g = await measureVerify(zkSBT, issuer, chainId, contract, firstCred, firstTokenId);
      console.log(`  verify  first (#${firstTokenId}): ${g.toLocaleString()}`);
      rows.push({ registrySize: size, op: "verify", position: `first#${firstTokenId}`, gas: g });
      await sleep(CFG.DELAY_MS);
    }
    if (midCred && Number(midTokenId) <= size) {
      const g = await measureVerify(zkSBT, issuer, chainId, contract, midCred, midTokenId);
      console.log(`  verify  mid   (#${midTokenId}): ${g.toLocaleString()}`);
      rows.push({ registrySize: size, op: "verify", position: `mid#${midTokenId}`, gas: g });
      await sleep(CFG.DELAY_MS);
    }
    {
      const { gasRevoke, gasDispute } = await measureRevokeDispute(zkSBT, issuer, chainId, contract);
      extraMinted += 1;
      console.log(`  revoke  fresh: ${gasRevoke.toLocaleString()}`);
      console.log(`  dispute fresh: ${gasDispute.toLocaleString()}`);
      rows.push({ registrySize: size, op: "revoke", position: "fresh", gas: gasRevoke });
      rows.push({ registrySize: size, op: "dispute", position: "fresh", gas: gasDispute });
      await sleep(CFG.DELAY_MS);
    }
  };

  const checkpointSet = new Set(CFG.CHECKPOINTS);
  for (let i = 1; i <= CFG.MAX; i++) {
    const holder = ethers.Wallet.createRandom();
    const m = await mintOne(zkSBT, issuer, chainId, contract, holder);
    if (i === 1) { firstCred = m.cred; firstTokenId = m.tokenId; }
    if (i === midTarget) { midCred = m.cred; midTokenId = m.tokenId; }
    process.stdout.write(`  mint ${i}/${CFG.MAX}\r`);
    if (CFG.DELAY_MS) await sleep(CFG.DELAY_MS);
    if (checkpointSet.has(i)) await runCheckpoint(i);
  }

  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const csv = ["registrySize,op,position,gasUsed"];
  for (const r of rows) csv.push(`${r.registrySize},${r.op},${r.position},${r.gas}`);
  fs.writeFileSync(path.join(outDir, "scalability.csv"), csv.join("\n"));
  fs.writeFileSync(path.join(outDir, "scalability.json"), JSON.stringify({ baseMinted: CFG.MAX, extraMinted, rows }, null, 2));
  console.log("\n\nWritten: results/scalability.csv, results/scalability.json");

  console.log("\n" + "=".repeat(60));
  console.log("Scalability Summary (per operation)");
  console.log("=".repeat(60));
  for (const op of ["verify", "revoke", "dispute"]) {
    const g = rows.filter((r) => r.op === op).map((r) => r.gas);
    if (!g.length) continue;
    const min = Math.min(...g), max = Math.max(...g);
    const mean = g.reduce((a, b) => a + b, 0) / g.length;
    console.log(`${op.padEnd(8)}: mean ${Math.round(mean).toLocaleString()}, range [${min.toLocaleString()}, ${max.toLocaleString()}], spread ${max - min} (${((max - min) / mean * 100).toFixed(3)}%)`);
  }
  console.log(`\nSmall spread per operation = gas independent of registry size (O(1) proof).`);
  process.exit(0);
}
main().catch((e) => { console.error("\n[FATAL]", e.message || e); process.exit(1); });