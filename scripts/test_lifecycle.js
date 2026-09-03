// scripts/test_lifecycle.js
//
// End-to-end functional testing for zkSBT—not an N=100 measurement. The goal is to verify that every path works and to gather single-transaction gas data for Table 3 before moving to the testnet.
//
// npx hardhat run scripts/test_lifecycle.js --network localhost
//
// The signature panel is derived from the same panel_mnemonic as deploy.js.

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

const PANEL_MNEMONIC =
  process.env.PANEL_MNEMONIC ||
  "test test test test test test test test test test test junk";

const gasTable = {};
function recordGas(label, rcpt) { gasTable[label] = Number(rcpt.gasUsed); }

function fmtProof(p) {
  return {
    a: [p.pi_a[0], p.pi_a[1]],
    b: [[p.pi_b[0][1], p.pi_b[0][0]], [p.pi_b[1][1], p.pi_b[1][0]]],
    c: [p.pi_c[0], p.pi_c[1]],
  };
}

async function increaseTime(seconds) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

function buildPanel() {
  const m = ethers.Mnemonic.fromPhrase(PANEL_MNEMONIC);
  const w = [];
  for (let i = 0; i < 5; i++) w.push(ethers.HDNodeWallet.fromMnemonic(m, `m/44'/60'/1'/0/${i}`));
  return w;
}

async function panelSign(panel, threshold, payloadHash) {
  const sorted = [...panel].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
  const chosen = sorted.slice(0, threshold);
  const sigs = [];
  for (const w of chosen) sigs.push(await w.signMessage(ethers.getBytes(payloadHash)));
  return sigs;
}

async function makeProof({ chainId, contract, zkSBT, cred, verifierAddr, domain, tokenId, disputeCount }) {
  let challenge;
  if (domain === "VERIFY") {
    const nonce = await zkSBT.verifierNonce(verifierAddr);
    challenge = core.verifyChallenge({ chainId, contract, verifier: verifierAddr, nonce });
  } else {
    challenge = core.disputeChallenge({ chainId, contract, tokenId, disputeCount });
  }
  const birthCutoff = core.computeBirthCutoff(AGE_THRESHOLD, Math.floor(Date.now() / 1000));
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

async function mintOne(zkSBT, issuer, chainId, contract, holderWallet) {
  const secretID = BigInt(ethers.keccak256(ethers.toUtf8Bytes("secretID:" + holderWallet.address))) % core.SNARK_FIELD;
  const secretSalt = core.randomSalt();
  const birthISO = new Date(Date.now() - 30 * 365.25 * 864e5).toISOString().slice(0, 10);
  const birthTimestamp = core.encodeBirth(birthISO);
  const domicileCode = REGION;
  const commitment = await core.computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode });
  const cid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
  const nonce = await zkSBT.issuanceNonce(holderWallet.address);
  const sig = await core.signMint(issuer, { chainId, contract, holder: holderWallet.address, commitmentBytes32: commitment.bytes32, cid, expiry: 0n, nonce });
  const tx = await zkSBT.connect(issuer).mintIdentity(holderWallet.address, commitment.bytes32, cid, 0, nonce, sig);
  const rcpt = await tx.wait();
  const tokenId = await zkSBT.holderToken(holderWallet.address);
  return { rcpt, tokenId, cred: { secretID, secretSalt, birthTimestamp, domicileCode }, commitment, cid };
}

async function main() {
  console.log("=".repeat(60));
  console.log("zkSBT — Lifecycle Functional Testing");
  console.log("=".repeat(60));

  const dep = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "deployment.json"), "utf8"));
  const net = await ethers.provider.getNetwork();
  const chainId = net.chainId, contract = dep.zkSBT;
  const [issuer, , holderSigner] = await ethers.getSigners(); 
  const zkSBT = await ethers.getContractAt("ZkSBT", contract);
  const panel = buildPanel();
  const threshold = Number(await zkSBT.threshold());
  const verifierAddr = issuer.address;

  const ok = (s) => console.log("  \u2713 " + s);

  // The holder for the dispute path must be able to submit transactions (onlyHolder), so use a Hardhat signer rather than an arbitrary wallet.
  const holderW = holderSigner;

  // 1. Mint
  let m = await mintOne(zkSBT, issuer, chainId, contract, holderW);
  recordGas("mint", m.rcpt);
  ok("[1] mint, tokenId=" + m.tokenId);

  // 2. Verify as positive
  {
    const pr = await makeProof({ chainId, contract, zkSBT, cred: m.cred, verifierAddr, domain: "VERIFY" });
    const tx = await zkSBT.connect(issuer).verifyIdentityAccess(m.tokenId, pr.a, pr.b, pr.c, AGE_THRESHOLD, pr.birthCutoff, REGION);
    const rcpt = await tx.wait();
    recordGas("verify", rcpt);
  
    const hit = rcpt.logs.some((l) => { try { return zkSBT.interface.parseLog(l).name === "AccessVerified"; } catch { return false; } });
    if (!hit) throw new Error("[2] Verify Positive does not broadcast AccessVerified");
    ok("[2] Positive verification received");
  }

  // 3. Verify as negative: invalid proof must be rejected
  {
    const pr = await makeProof({ chainId, contract, zkSBT, cred: m.cred, verifierAddr, domain: "VERIFY" });
    /// Make one of the proof elements invalid by flipping a bit in the first element of `a`
    const badA = [ (BigInt(pr.a[0]) ^ 1n).toString(), pr.a[1] ];
    let rejected = false;
    try {
      const tx = await zkSBT.connect(issuer).verifyIdentityAccess(m.tokenId, badA, pr.b, pr.c, AGE_THRESHOLD, pr.birthCutoff, REGION);
      const rcpt = await tx.wait();
      const hit = rcpt.logs.some((l) => { try { return zkSBT.interface.parseLog(l).name === "AccessVerified"; } catch { return false; } });
      rejected = !hit;  // Transaction successful but without AccessVerified = rejected (returns false)
    } catch {
      rejected = true;  // revert = rejected
    }
    if (!rejected) throw new Error("[3] Damaged proof ACCEPTED. Verifier not functioning");
    ok("[3] Negative verification rejected (the verifier is actually working)");
  }

  // 4. first requestRevoke (unilateral, empty array)
  {
    const tx = await zkSBT.connect(issuer).requestRevoke(m.tokenId, "misuse suspected", []);
    recordGas("requestRevoke", await tx.wait());
    if (Number(await zkSBT.statusOf(m.tokenId)) !== 1) throw new Error("[4] status is not SUSPENDED");
    ok("[4] first requestRevoke -> SUSPENDED");
  }

  // 5. disputeRevocation
  {
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const pr = await makeProof({ chainId, contract, zkSBT, cred: m.cred, verifierAddr, domain: "DISPUTE", tokenId: m.tokenId, disputeCount: dc });
    const tx = await zkSBT.connect(holderW).disputeRevocation(m.tokenId, pr.a, pr.b, pr.c, pr.birthCutoff, REGION);
    recordGas("disputeRevocation", await tx.wait());
    if (Number(await zkSBT.statusOf(m.tokenId)) !== 2) throw new Error("[5] status is not CONTESTED");
    ok("[5] disputeRevocation -> CONTESTED");
  }

  // 6. resolveDispute uphold=true
  {
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const payload = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "address", "bytes32", "uint256", "uint16", "bool"],
      [chainId, contract, core.domSep(core.DOM.VERDICT), m.tokenId, dc, true]
    ));
    const sigs = await panelSign(panel, threshold, payload);
    const tx = await zkSBT.connect(issuer).resolveDispute(m.tokenId, true, sigs);
    recordGas("resolveDispute", await tx.wait());
    if (Number(await zkSBT.statusOf(m.tokenId)) !== 0) throw new Error("[6] status is not VALID");
    ok("[6] resolveDispute uphold=true -> VALID (current disputeCount " + (await zkSBT.identities(m.tokenId)).disputeCount + ")");
  }

  // 7. The second requestRevoke now requires a panel quorum
  {
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    // must fail for lack of a quorum
    let blocked = false;
    try { await (await zkSBT.connect(issuer).requestRevoke(m.tokenId, "again", [])).wait(); }
    catch { blocked = true; }
    if (!blocked) throw new Error("[7] The second requestRevoke passed without a panel quorum");

    const payload = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "address", "bytes32", "uint256", "uint16"],
      [chainId, contract, core.domSep(core.DOM.REVOKE), m.tokenId, dc]
    ));
    const sigs = await panelSign(panel, threshold, payload);
    const tx = await zkSBT.connect(issuer).requestRevoke(m.tokenId, "again with panel", sigs);
    recordGas("requestRevoke_panel", await tx.wait());
    if (Number(await zkSBT.statusOf(m.tokenId)) !== 1) throw new Error("[7] status is not SUSPENDED");
    ok("[7] The second requestRevoke requires and receives a panel quorum");
  }

  // 8. dispute then resolveDispute uphold=false -> REVOKED
  {
    const dc = (await zkSBT.identities(m.tokenId)).disputeCount;
    const pr = await makeProof({ chainId, contract, zkSBT, cred: m.cred, verifierAddr, domain: "DISPUTE", tokenId: m.tokenId, disputeCount: dc });
    await (await zkSBT.connect(holderW).disputeRevocation(m.tokenId, pr.a, pr.b, pr.c, pr.birthCutoff, REGION)).wait();
    const payload = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "address", "bytes32", "uint256", "uint16", "bool"],
      [chainId, contract, core.domSep(core.DOM.VERDICT), m.tokenId, dc, false]
    ));
    const sigs = await panelSign(panel, threshold, payload);
    await (await zkSBT.connect(issuer).resolveDispute(m.tokenId, false, sigs)).wait();
    if (Number(await zkSBT.statusOf(m.tokenId)) !== 3) throw new Error("[8] status is not REVOKED");
    ok("[8] resolveDispute uphold=false -> REVOKED");
  }

  // 9. finalize timeout SUSPENDED -> REVOKED
  {
    const h = ethers.Wallet.createRandom().connect(ethers.provider);
    await (await issuer.sendTransaction({ to: h.address, value: ethers.parseEther("1") })).wait();
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h);
    await (await zkSBT.connect(issuer).requestRevoke(mm.tokenId, "no dispute", [])).wait();
    await increaseTime(31 * 24 * 3600);  // lewati CHALLENGE_WINDOW 30 hari
    const tx = await zkSBT.finalizeRevocation(mm.tokenId);
    recordGas("finalizeRevocation", await tx.wait());
    if (Number(await zkSBT.statusOf(mm.tokenId)) !== 3) throw new Error("[9] status is not REVOKED");
    ok("[9] finalize timeout SUSPENDED -> REVOKED");
  }

  // 10. finalize timeout CONTESTED -> VALID
  {
    const h = holderW;  // use signer to dispute
    
    const mm = await mintOne(zkSBT, issuer, chainId, contract, h);
    await (await zkSBT.connect(issuer).requestRevoke(mm.tokenId, "will time out", [])).wait();
    const dc = (await zkSBT.identities(mm.tokenId)).disputeCount;
    const pr = await makeProof({ chainId, contract, zkSBT, cred: mm.cred, verifierAddr, domain: "DISPUTE", tokenId: mm.tokenId, disputeCount: dc });
    await (await zkSBT.connect(h).disputeRevocation(mm.tokenId, pr.a, pr.b, pr.c, pr.birthCutoff, REGION)).wait();
    await increaseTime(2 * 24 * 3600);  // skip the 24-hour ARBITRATION_WINDOW
    await (await zkSBT.finalizeRevocation(mm.tokenId)).wait();
    if (Number(await zkSBT.statusOf(mm.tokenId)) !== 0) throw new Error("[10] status is not VALID");
    ok("[10] finalize timeout CONTESTED -> VALID");
    // Clean holderW so it is free for the next test.
    m = mm;
  }

  // 11. revokeAndReissue (two signatures)
  {
    const old = m.tokenId;
    const newSecretSalt = core.randomSalt();
    const newCommitment = await core.computeCommitment({ secretID: m.cred.secretID, secretSalt: newSecretSalt, birthTimestamp: m.cred.birthTimestamp, domicileCode: m.cred.domicileCode });
    const newCid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
    const issuerSig = await core.signReissue(issuer, { chainId, contract, oldTokenId: old, holder: holderW.address, newCommitmentBytes32: newCommitment.bytes32, newCid, newExpiry: 0n });
    const holderSig = await core.signReissue(holderW, { chainId, contract, oldTokenId: old, holder: holderW.address, newCommitmentBytes32: newCommitment.bytes32, newCid, newExpiry: 0n });
    const tx = await zkSBT.connect(issuer).revokeAndReissue(old, newCommitment.bytes32, newCid, 0, issuerSig, holderSig);
    recordGas("revokeAndReissue", await tx.wait());
    ok("[11] revokeAndReissue -> old token REVOKED, new token VALID");
  }

  // 12. recoverCredential (quorum panel)
  {
    const newHolder = ethers.Wallet.createRandom();
    const cur = await zkSBT.holderToken(holderW.address);
    const newSalt = core.randomSalt();
    const newCommitment = await core.computeCommitment({ secretID: m.cred.secretID, secretSalt: newSalt, birthTimestamp: m.cred.birthTimestamp, domicileCode: m.cred.domicileCode });
    const newCid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);
    const h = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "address", "bytes32", "uint256", "address", "address", "bytes32", "bytes32", "uint32"],
      [chainId, contract, core.domSep(core.DOM.RECOVER), cur, holderW.address, newHolder.address, newCommitment.bytes32, ethers.keccak256(ethers.toUtf8Bytes(newCid)), 0]
    ));
    const issuerSig = await issuer.signMessage(ethers.getBytes(h));
    const sigs = await panelSign(panel, threshold, h);
    const tx = await zkSBT.connect(issuer).recoverCredential(cur, newHolder.address, newCommitment.bytes32, newCid, 0, issuerSig, sigs);
    recordGas("recoverCredential", await tx.wait());
    ok("[12] recoverCredential -> credential moved to new wallet");
  }

  // Table 3
  console.log("\n" + "─".repeat(60));
  console.log("Single-transaction gas for Table 3:");
  for (const [k, v] of Object.entries(gasTable)) {
    console.log("  " + k.padEnd(22) + v.toLocaleString());
  }
  console.log("─".repeat(60));

  const outDir = path.join(__dirname, "..", "results");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "gas_table3.json"), JSON.stringify(gasTable, null, 2));
  console.log("Written: results/gas_table3.json");

  console.log("\nAll routes clear. Safe passage to testnet.");
  process.exit(0);
}

main().catch((e) => { console.error("\n[FAIL]", e.message || e); process.exit(1); });