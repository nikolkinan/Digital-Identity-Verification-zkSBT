// scripts/deploy.js

const { ethers, network, artifacts } = require("hardhat");
const fs   = require("fs");
const path = require("path");

const PANEL_SIZE = 5;
const THRESHOLD  = 3;

// The panel must be reproducible: its private key is used to sign the verdict in the resolveDispute and recoverCredential tests. Store this phrase in the .env file; do not commit it. While this is not a production secret for the testnet, losing the phrase means losing the ability to test the panel.
const PANEL_MNEMONIC =
  process.env.PANEL_MNEMONIC ||
  "test test test test test test test test test test test junk";

async function main() {
  const [issuer] = await ethers.getSigners();
  const net = await ethers.provider.getNetwork();

  console.log("─".repeat(60));
  console.log("Network :", network.name, "| chainId:", net.chainId.toString());
  console.log("Issuer  :", issuer.address);

  // The chainId is bound into every signature payload. Deploying on one chain and testing on another will cause all signatures to fail with misleading error messages, so this value is logged and stored.

  const bal = await ethers.provider.getBalance(issuer.address);
  console.log("Balance :", ethers.formatEther(bal), "POL");
  if (bal === 0n) {
    throw new Error("Balance issuer 0 POL. Top up testnet account before deploying.");
  }

  // 1. Reject expired Verifier.sol
  const vArtifact = await artifacts.readArtifact("Groth16Verifier");
  const vp = vArtifact.abi.find((f) => f.name === "verifyProof");
  if (!vp) throw new Error("verifyProof not found in Groth16Verifier ABI");

  const pubType = vp.inputs[3].type;
  if (pubType !== "uint256[4]") {
    throw new Error(
      `Expired Verifier: pubSignals is ${pubType} type, should be uint256[4].\n` +
      `New circuit has 4 public inputs. Please re-run:\n` +
      `  snarkjs groth16 setup identity_check.r1cs <ptau> circuit_0000.zkey\n` +
      `  snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey\n` +
      `  snarkjs zkey export solidityverifier circuit_final.zkey contracts/Verifier.sol`
    );
  }
  console.log("Verifier: arity OK (" + pubType + ")");

  // 2. Arbitration panel
  const mnemonic = ethers.Mnemonic.fromPhrase(PANEL_MNEMONIC);
  const panel = [];
  for (let i = 0; i < PANEL_SIZE; i++) {
    /// The path is separated from the issuer account to ensure there are never any collisions.
    panel.push(ethers.HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/1'/0/${i}`));
  }
  const panelAddrs = panel.map((w) => w.address);

  /// The constructor rejects arbitrator == issuer, but it is better to fail here with a clear error message rather than inside the EVM.
  if (panelAddrs.some((a) => a.toLowerCase() === issuer.address.toLowerCase())) {
    throw new Error("Arbitrator address is the same as issuer address. Change the derivation path.");
  }
  if (new Set(panelAddrs.map((a) => a.toLowerCase())).size !== PANEL_SIZE) {
    throw new Error("Duplicate arbitrator addresses found.");
  }

  console.log("Panel   :", THRESHOLD + "-of-" + PANEL_SIZE);
  panelAddrs.forEach((a, i) => console.log("   [" + i + "]", a));

  /// Signature verdicts must be sorted in ascending order based on the signer's address. This order is stored so that the test does not need to recalculate it.
  const signingOrder = [...panelAddrs].sort((a, b) =>
    BigInt(a) < BigInt(b) ? -1 : 1
  );

  // 3. Deploy
  console.log("─".repeat(60));

  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  const vRcpt = await verifier.deploymentTransaction().wait();
  console.log("Verifier deployed:", verifierAddress, "| gas:", vRcpt.gasUsed.toString());

  const ZkSBT = await ethers.getContractFactory("ZkSBT");
  const zkSBT = await ZkSBT.deploy(
    verifierAddress,
    issuer.address,
    panelAddrs,
    THRESHOLD
    // ,
  );
  await zkSBT.waitForDeployment();
  const zkSBTAddress = await zkSBT.getAddress();
  const zRcpt = await zkSBT.deploymentTransaction().wait();
  console.log("ZkSBT    deployed:", zkSBTAddress, "| gas:", zRcpt.gasUsed.toString());

  // 4. Sanity check post-deploy
  const onChainThreshold = await zkSBT.threshold();
  const onChainPanelSize = await zkSBT.arbitratorCount();
  if (Number(onChainThreshold) !== THRESHOLD || Number(onChainPanelSize) !== PANEL_SIZE) {
    throw new Error("Configuration of the on-chain panel does not match the script.");
  }

  // 5. Save, don't copy manually
  const out = {
    network:        network.name,
    chainId:        net.chainId.toString(),
    deployedAt:     new Date().toISOString(),
    issuer:         issuer.address,
    verifier:       verifierAddress,
    zkSBT:          zkSBTAddress,
    threshold:      THRESHOLD,
    panelSize:      PANEL_SIZE,
    arbitrators:    panelAddrs,
    signingOrder,
    deploymentGas: {
      verifier: vRcpt.gasUsed.toString(),
      zkSBT:    zRcpt.gasUsed.toString(),
    },
  };

  const outPath = path.join(__dirname, "..", "deployment.json");
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

  console.log("─".repeat(60));
  console.log("Written to deployment.json. Test reads from this file,");
  console.log("don't copy addresses manually to CONFIG.");
}

main().catch((e) => {
  console.error(e.message || e);
  process.exitCode = 1;
});