# zkSBT: Zero-Knowledge Soulbound Token

Reference implementation for the paper zkSBT: Zero-Knowledge Soulbound Token, a privacy-preserving digital identity framework integrating Groth16 zk-SNARKs with non-transferable Soulbound Tokens, featuring a governed revocation mechanism with cryptographic holder dispute rights.

Deployed and measured on the Polygon Amoy testnet.

# What this repository contains

This is a proof-of-concept research prototype, not production software. It reproduces the constructions and measurements reported in the paper.

```bash
circuits/                    Circom identity circuit and compiled artifacts
  identity_check.circom      Four-constraint identity circuit (Poseidon-4)
contracts/
  ZkSBT.sol                  Lifecycle contract (mint, verify, revoke, dispute,
                             adjudicate, finalize, recover); non-transferable by
                             construction
  Verifier.sol               Groth16 verifier (generated from the proving key)
scripts/
  issuerCore.js              Issuer primitives (Poseidon commitment, signing,
                             session/dispute challenges)
  issueCredential.js         Issuer issuance pipeline
  deploy.js                  Deploys both contracts, derives the arbitration panel
  test_lifecycle.js          Functional test of all lifecycle paths
  measure_testnet.js         Gas + proof-gen + latency campaign (N=100)
  test_table3.js             Gas for reissuance, recovery, panel-revocation
  measure_scalability.js     Gas vs registry size (10..1000), three operations
  measure_concurrency.js     Proof-generation throughput vs parallelism
  prove_one.js               Single-proof helper (used by the concurrency harness)
results/                     Measurement outputs (CSV/JSON) reported in the paper
```

# Requirements
- Node.js 18+
- Circom 2.x and SnarkJS (for circuit compilation and proving)
- A funded Polygon Amoy account (testnet POL) for on-chain measurement

# Installation

#### *Clone this repository*

```bash
git clone https://github.com/nikolkinan/Digital-Identity-Verification-zkSBT
```
#### *Go to folder directory*
```bash
cd Digital-Identity-Verification-zkSBT
```

#### *Install the project using*

#### *NPM*

```bash
npm install
```

#### *Setup*

```bash
cp .env.example .env      # then fill in your own values 
```

Required environment variables (see .env.example):

- PRIVATE_KEY Issuer/deployer account private key (testnet only)
- PANEL_MNEMONIC Mnemonic from which the arbitration panel keys are derived
- AMOY_RPC_URL Polygon Amoy RPC endpoint

Never commit .env. It is listed in .gitignore.

## Reproducing the measurements

#### 1. Compile the circuit and run the trusted setup (see circuits/README)

#### 2. Deploy

```bash
npx hardhat run scripts/deploy.js --network amoy
```

#### 3. Functional check

```bash
npx hardhat run scripts/test_lifecycle.js --network amoy
```

#### 4. Main campaign (gas, proof-gen, latency, N=100)

```bash
npx hardhat run scripts/measure_testnet.js --network amoy
```

#### 5. Scalability (gas vs registry size)

```bash
npx hardhat run scripts/measure_scalability.js --network amoy
```

#### 6. Concurrency (proof-gen throughput; runs locally, no testnet)

```bash
node scripts/measure_concurrency.js
```
