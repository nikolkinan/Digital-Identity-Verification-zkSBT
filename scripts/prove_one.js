// scripts/prove_one.js
//
// Generates a single Groth16 proof, then prints the proofing time (ms) to stdout as JSON: {"ms": <number>}. Executed as a separate process by measure_concurrency.js.
//
// The process runs separately because snarkjs uses the web-worker package internally, which causes conflicts when snarkjs is wrapped within a worker thread (resulting in a nested worker require(undefined) error). A separate process provides a clean Node instance with its own memory space and web-worker environment, avoiding conflicts while also enabling true CPU concurrency.
//
// node prove_one.js <seed>

const snarkjs = require("snarkjs");
const path = require("path");
const core = require("./issuerCore");
const { ethers } = require("ethers");

const WASM = path.join(__dirname, "..", "circuits", "identity_check_js", "identity_check.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "identity_check_final.zkey");

async function main() {
  const seed = process.argv[2] || "0";
  const secretID = BigInt(ethers.keccak256(ethers.toUtf8Bytes("id:" + seed))) % core.SNARK_FIELD;
  const secretSalt = core.randomSalt();
  const birthTimestamp = 1000000000n + core.EPOCH_OFFSET;
  const domicileCode = 3273n;
  const commitment = await core.computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode });
  const birthCutoff = 1700000000n + core.EPOCH_OFFSET;
  const sessionChallenge = BigInt(ethers.keccak256(ethers.toUtf8Bytes("ch:" + seed))) % core.SNARK_FIELD;

  const input = {
    onChainHash: commitment.field.toString(),
    birthCutoff: birthCutoff.toString(),
    regionCode: domicileCode.toString(),
    sessionChallenge: sessionChallenge.toString(),
    secretID: secretID.toString(),
    secretSalt: secretSalt.toString(),
    birthTimestamp: birthTimestamp.toString(),
    domicileCode: domicileCode.toString(),
  };

  const t0 = Date.now();
  await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ms = Date.now() - t0;
  
  console.log(JSON.stringify({ ms }));
  process.exit(0);
}
main().catch((e) => { console.error(JSON.stringify({ error: e.message })); process.exit(1); });