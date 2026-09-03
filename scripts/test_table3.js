// scripts/test_table3.js
//
// Completing Table 3 in testnet for three operations that have not yet been measured and do not require time manipulation:
//   - requestRevoke with quorum panel (second dispute)
//   - revokeAndReissue (two signatures)
//   - recoverCredential (quorum panel)
//
// finalizeRevocation is not measured here; it requires an expiration window—which on testnet means waiting 30 days. The gas cost is derived from and valid on localhost, as finalize does not utilize the pairing precompile; consequently, the cost is network-independent (consisting only of SSTORE and event operations, which are identical on localhost and testnet).
//
// npx hardhat run scripts/test_table3.js --network amoy

const { ethers } = require("hardhat");
const snarkjs = require("snarkjs");
const fs   = require("fs");
const path = require("path");
require("dotenv").config();

const core = require("./issuerCore");

const WASM = path.join(__dirname, "..", "circuits", "identity_check_js", "identity_check.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "identity_check_final.zkey");
const AGE_THRESHOLD = 18;
const REGION = 3273n;
const GAS = { maxPriorityFeePerGas: 30000000000n, maxFeePerGas: 60000000000n };

function fmtProof(p) {
  return {
    a: [p.pi_a[0], p.pi_a[1]],
    b: [[p.pi_b[0][1], p.pi_b[0][0]], [p.pi_b[1][1], p.pi_b[1][0]]],
    c: [p.pi_c[0], p.pi_c[1]],
  };
}
async function chainNow() { return (await ethers.provider.getBlock("latest")).timestamp; }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function mintOne(zkSBT, issuer, chainId, contract, holder) {
  const secretID = BigInt(ethers.keccak256(ethers.toUtf8Bytes("secretID:" + holder.address))) % core.SNARK_FIELD;
  const secretSalt = core.randomSalt();
  const now = await chainNow();
  const birthTimestamp = BigInt(now - Math.floor(30 * 365.25 * 24 * 3600)) + core.EPOCH_OFFSET;
  const domicileCode = REGION;
  const commitment = await core.computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode });
  const cid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
  const nonce = await zkSBT.issuanceNonce(holder.address);
  const sig = await core.signMint(issuer, { chainId, contract, holder: holder.address, commitmentBytes32: commitment.bytes32, cid, expiry: 0n, nonce });
  await (await zkSBT.connect(issuer).mintIdentity(holder.address, commitment.bytes32, cid, 0, nonce, sig, GAS)).wait();
  const tokenId = await zkSBT.holderToken(holder.address);
  return { tokenId, cred: { secretID, secretSalt, birthTimestamp, domicileCode }, cid };
}

async function disputeProof(zkSBT, chainId, contract, cred, tokenId, disputeCount) {
  const challenge = core.disputeChallenge({ chainId, contract, tokenId, disputeCount });
  const now = BigInt(await chainNow());
  const today = (now / 86400n) * 86400n;
  const birthCutoff = today - BigInt(AGE_THRESHOLD) * core.SECONDS_PER_YEAR + core.EPOCH_OFFSET;
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

function buildPanel() {
  const m = ethers.Mnemonic.fromPhrase(process.env.PANEL_MNEMONIC);
  const w = []; for (let i = 0; i < 5; i++) w.push(ethers.HDNodeWallet.fromMnemonic(m, `m/44'/60'/1'/0/${i}`));
  return w;
}
async function panelSign(panel, threshold, payloadHash) {
  const sorted = [...panel].sort((a, b) => BigInt(a.address) < BigInt(b.address) ? -1 : 1).slice(0, threshold);
  const sigs = []; for (const w of sorted) sigs.push(await w.signMessage(ethers.getBytes(payloadHash)));
  return sigs;
}

async function main() {
  console.log("=".repeat(60));
  console.log("zkSBT — Table 3 Completing (testnet)");
  console.log("=".repeat(60));

  const dep = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployment.json"), "utf8"));
  const net = await ethers.provider.getNetwork();
  const chainId = net.chainId, contract = dep.zkSBT;
  const [issuer] = await ethers.getSigners();
  const zkSBT = await ethers.getContractAt("ZkSBT", contract);
  const panel = buildPanel();
  const threshold = Number(await zkSBT.threshold());
  const out = {};

  const holderW = ethers.Wallet.createRandom().connect(ethers.provider);
  await (await issuer.sendTransaction({ to: holderW.address, value: ethers.parseEther("0.3"), ...GAS })).wait();

  /**
 * Prepare a token with disputeCount > 0 for the requestRevoke panel
 * - Plot: mint -> revoke1 -> dispute -> resolve(uphold) => disputeCount=1, status VALID
 */
  console.log("\n[setup] preparing the token with disputeCount>0");
  const m = await mintOne(zkSBT, issuer, chainId, contract, holderW);
  await (await zkSBT.connect(issuer).requestRevoke(m.tokenId, "setup revoke", [], GAS)).wait();
  await sleep(1500);
  {
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const pr = await disputeProof(zkSBT, chainId, contract, m.cred, m.tokenId, dc);
    await (await zkSBT.connect(holderW).disputeRevocation(m.tokenId, pr.a, pr.b, pr.c, pr.birthCutoff, REGION, GAS)).wait();
    await sleep(1500);
    const payload = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256","address","bytes32","uint256","uint16","bool"],
      [chainId, contract, core.domSep(core.DOM.VERDICT), m.tokenId, dc, true]
    ));
    const sigs = await panelSign(panel, threshold, payload);
    await (await zkSBT.connect(issuer).resolveDispute(m.tokenId, true, sigs, GAS)).wait();
    await sleep(1500);
  }

  // 1. requestRevoke with panel
  {
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const payload = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256","address","bytes32","uint256","uint16"],
      [chainId, contract, core.domSep(core.DOM.REVOKE), m.tokenId, dc]
    ));
    const sigs = await panelSign(panel, threshold, payload);
    const rcpt = await (await zkSBT.connect(issuer).requestRevoke(m.tokenId, "second revoke", sigs, GAS)).wait();
    out.requestRevoke_panel = Number(rcpt.gasUsed);
    console.log("  requestRevoke_panel :", out.requestRevoke_panel.toLocaleString());
    await sleep(1500);
  }

  // 2. revokeAndReissue (new token, VALID, two signatures)
  {
    const h2 = ethers.Wallet.createRandom().connect(ethers.provider);
    await (await issuer.sendTransaction({ to: h2.address, value: ethers.parseEther("0.05"), ...GAS })).wait();
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h2);
    const newSalt = core.randomSalt();
    const newCommit = await core.computeCommitment({ ...mm.cred, secretSalt: newSalt });
    const newCid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
    const issSig = await core.signReissue(issuer, { chainId, contract, oldTokenId: mm.tokenId, holder: h2.address, newCommitmentBytes32: newCommit.bytes32, newCid, newExpiry: 0n });
    const holSig = await core.signReissue(h2, { chainId, contract, oldTokenId: mm.tokenId, holder: h2.address, newCommitmentBytes32: newCommit.bytes32, newCid, newExpiry: 0n });
    const rcpt = await (await zkSBT.connect(issuer).revokeAndReissue(mm.tokenId, newCommit.bytes32, newCid, 0, issSig, holSig, GAS)).wait();
    out.revokeAndReissue = Number(rcpt.gasUsed);
    console.log("  revokeAndReissue    :", out.revokeAndReissue.toLocaleString());
    await sleep(1500);
  }

  // 3. recoverCredential (quorum panel)
  {
    const h3 = ethers.Wallet.createRandom().connect(ethers.provider);
    await (await issuer.sendTransaction({ to: h3.address, value: ethers.parseEther("0.05"), ...GAS })).wait();
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h3);
    const newHolder = ethers.Wallet.createRandom();
    const newSalt = core.randomSalt();
    const newCommit = await core.computeCommitment({ ...mm.cred, secretSalt: newSalt });
    const newCid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
    const h = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256","address","bytes32","uint256","address","address","bytes32","bytes32","uint32"],
      [chainId, contract, core.domSep(core.DOM.RECOVER), mm.tokenId, h3.address, newHolder.address, newCommit.bytes32, ethers.keccak256(ethers.toUtf8Bytes(newCid)), 0]
    ));
    const issSig = await issuer.signMessage(ethers.getBytes(h));
    const sigs = await panelSign(panel, threshold, h);
    const rcpt = await (await zkSBT.connect(issuer).recoverCredential(mm.tokenId, newHolder.address, newCommit.bytes32, newCid, 0, issSig, sigs, GAS)).wait();
    out.recoverCredential = Number(rcpt.gasUsed);
    console.log("  recoverCredential   :", out.recoverCredential.toLocaleString());
  }

  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "table_extend.json"), JSON.stringify(out, null, 2));

  console.log("\n" + "─".repeat(60));
  console.log("Written: results/table_extend.json");
  console.log("Combine with results.json (mint, requestRevoke, dispute, resolve)");
  console.log("and finalizeRevocation from localhost for Table 3 is complete.");
  console.log("─".repeat(60));
  process.exit(0);
}
main().catch((e) => { console.error("[FATAL]", e.message || e); process.exit(1); });