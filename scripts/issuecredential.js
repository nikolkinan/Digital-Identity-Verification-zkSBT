// scripts/issuer/issueCredential.js
//
// CLI Issuer: generate a complete credential for the prototype/measurement.
// Output:
// 1) credentials/<holder>.json -> secret + commitment + signed mint payload
// 2) credentials/<holder>.input.json -> witness for snarkjs proof generation
//
// In the production environment, this step is executed by the Population and Civil Registration Agency infrastructure using sk_I within the HSM.
// In this script, sk_I is derived from the .env file, only for testnet.
//
// Run: node scripts/issuer/issueCredential.js --holder 0x... --birth 1990-05-17 --region 3273 --age 21

const { ethers } = require("ethers");
const fs   = require("fs");
const path = require("path");
require("dotenv").config();

const core = require("./issuerCore");

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

async function main() {
  // Parameter
  const holder   = arg("--holder");
  const birthISO = arg("--birth");                 // "YYYY-MM-DD"
  const region   = arg("--region");                // domicileCode == regionCode
  const ageThr   = arg("--age", "21");
  const expiry   = arg("--expiry", "0");           // 0 = no expiry
  const nonce    = arg("--nonce", "0");            // required == issuanceNonce[holder] on-chain

  if (!holder || !birthISO || !region) {
    throw new Error("Required: --holder <addr> --birth <YYYY-MM-DD> --region <code>");
  }
  if (!ethers.isAddress(holder)) throw new Error("Holder's address invalid");

  // Network and contract context
    /// deployment.json is written by deploy.js. The chainId and contract address are bound into the signature payload, so they must be taken from there, not typed.
  const depPath = path.join(__dirname, "..", "deployment.json");
  if (!fs.existsSync(depPath)) {
    throw new Error("deployment.json is missing. Run deploy.js first.");
  }
  const dep = JSON.parse(fs.readFileSync(depPath, "utf8"));
  const chainId  = BigInt(dep.chainId);
  const contract = dep.zkSBT;

  // Issuer key
  if (!process.env.PRIVATE_KEY) throw new Error("PRIVATE_KEY is missing from .env");
  const issuer = new ethers.Wallet(process.env.PRIVATE_KEY);
  if (issuer.address.toLowerCase() !== dep.issuer.toLowerCase()) {
    throw new Error(
      `PRIVATE_KEY (${issuer.address}) is not the deployed issuer (${dep.issuer}). ` +
      `Signature will be rejected by the contract.`
    );
  }

  // Secret identity
    /// The secretID prototype is derived deterministically from the holder's address to ensure reproducibility; in production, it is derived from actual population data.
  const secretID       = BigInt(ethers.keccak256(ethers.toUtf8Bytes("secretID:" + holder))) % core.SNARK_FIELD;
  const secretSalt     = core.randomSalt();  // required randomization per credential
  const birthTimestamp = core.encodeBirth(birthISO);
  const domicileCode   = BigInt(region);

  // Commitment
  const commitment = await core.computeCommitment({
    secretID, secretSalt, birthTimestamp, domicileCode,
  });

  // CID placeholder
    /// This production is the result of IPFS.pin(Enc(pk_H, d)). For on-chain measurement, a valid CID string is sufficient: what is measured is gas, not IPFS availability.
  const cid = "bafybeib" + ethers.hexlify(ethers.randomBytes(20)).slice(2);

  // Mint signature
  const signature = await core.signMint(issuer, {
    chainId, contract, holder,
    commitmentBytes32: commitment.bytes32,
    cid, expiry: BigInt(expiry), nonce: BigInt(nonce),
  });

  // Witness for proof (using default age threshold)
  const nowSec = Math.floor(Date.now() / 1000);
  const circuitInput = await core.buildCircuitInput({
    secretID, secretSalt, birthTimestamp, domicileCode,
    ageThreshold: ageThr, regionCode: domicileCode,
    /// sessionChallenge is initialized to 0 here; the test harness will replace it with the correct verifyChallenge/disputeChallenge value just before proving.
    sessionChallenge: 0n,
    nowUnixSeconds: nowSec,
  });

  // Write
  const outDir = path.join(__dirname, "..", "credentials");
  fs.mkdirSync(outDir, { recursive: true });

  const record = {
    holder,
    chainId: chainId.toString(),
    contract,
    /// secret (Upon production, it never leaves the possession of the Holder/Issuer.)
    secrets: {
      secretID:       secretID.toString(),
      secretSalt:     secretSalt.toString(),
      birthTimestamp: birthTimestamp.toString(),
      birthISO,
      domicileCode:   domicileCode.toString(),
    },
    /// for mintIdentity(...)
    mintCall: {
      holder,
      commitment: commitment.bytes32,
      cid,
      expiry: expiry.toString(),
      nonce:  nonce.toString(),
      signature,
    },
    ageThreshold: ageThr,
  };

  const base = path.join(outDir, holder.toLowerCase());
  fs.writeFileSync(base + ".json",       JSON.stringify(record, null, 2));
  fs.writeFileSync(base + ".input.json", JSON.stringify(circuitInput, null, 2));

  console.log("Credentials are created for", holder);
  console.log("  commitment :", commitment.bytes32);
  console.log("  cid        :", cid);
  console.log("  nonce      :", nonce);
  console.log("  files      :", path.relative(process.cwd(), base) + ".json (+ .input.json)");
  console.log("\nNote: sessionChallenge in .input.json is still 0.");
  console.log("The test harness will recalculate the correct challenge before proving.");
}

main().catch((e) => {
  console.error("ERROR:", e.message || e);
  process.exitCode = 1;
});