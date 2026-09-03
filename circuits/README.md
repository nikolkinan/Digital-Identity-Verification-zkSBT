# Circuit: identity_check

Arithmetic circuit for the zkSBT identity relation, written in Circom 2 and proven
with Groth16 via SnarkJS. The circuit enforces four constraints over a private
witness and four public inputs (Poseidon-4 commitment integrity, birth-timestamp
age comparison, domicile equality, and a session-challenge binding), compiling to
806 R1CS constraints.

## Files in this directory

```
identity_check.circom         Circuit source
identity_check.r1cs           Compiled constraint system
identity_check.sym            Symbol file (signal names, for debugging)
identity_check_js/            WebAssembly witness generator
  identity_check.wasm
  generate_witness.js
  witness_calculator.js
pot12_0000.ptau               Powers of Tau, phase 1, initial
pot12_0001.ptau               Powers of Tau, phase 1, after one contribution
pot12_final.ptau              Powers of Tau, phase 1, finalized (prepared)
identity_check_0000.zkey      Groth16 key, phase 2, initial
identity_check_0001.zkey      Groth16 key, phase 2, after one contribution
identity_check_final.zkey     Groth16 proving key, finalized (used by scripts)
verification_key.json         Verification key (exported from the final zkey)
```

The proving pipeline in `scripts/` uses `identity_check_js/identity_check.wasm`
and `identity_check_final.zkey`.

## Requirements

- Circom 2.x  (https://docs.circom.io/getting-started/installation/)
- SnarkJS     (`npm install -g snarkjs`)
- circomlib   (for the Poseidon template used by the circuit)

## Reproducing the circuit artifacts

The committed artifacts above were produced by the steps below. The trusted-setup
contributions use fixed entropy strings here for reproducibility; a real deployment
must use a multi-party ceremony with independent, secret contributions, as
discussed in the paper (Assumption 1).

### 1. Compile the circuit

```bash
circom identity_check.circom --r1cs --wasm --sym
```

This produces `identity_check.r1cs`, `identity_check.sym`, and the
`identity_check_js/` witness generator.

Inspect the constraint count to confirm it matches the paper (806):

```bash
snarkjs r1cs info identity_check.r1cs
```

### 2. Powers of Tau (phase 1, circuit-independent)

`pot12` supports circuits up to 2^12 = 4096 constraints, which covers this
circuit's 806.

```bash
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau \
  --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
```

### 3. Groth16 setup (phase 2, circuit-specific)

```bash
snarkjs groth16 setup identity_check.r1cs pot12_final.ptau identity_check_0000.zkey
snarkjs zkey contribute identity_check_0000.zkey identity_check_0001.zkey \
  --name="First phase-2 contribution" -v
# finalize (beacon); use a real random beacon in production
snarkjs zkey beacon identity_check_0001.zkey identity_check_final.zkey \
  0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 \
  -n="Final beacon"
```

### 4. Export the verification key

```bash
snarkjs zkey export verificationkey identity_check_final.zkey verification_key.json
```

The Solidity verifier contract is generated from the final zkey:

```bash
snarkjs zkey export solidityverifier identity_check_final.zkey ../contracts/Verifier.sol
```

## Generating a proof

With an `input.json` matching the circuit's expected signals:

```bash
node identity_check_js/generate_witness.js \
  identity_check_js/identity_check.wasm input.json witness.wtns
snarkjs groth16 prove identity_check_final.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```

The scripts in `../scripts/` automate witness construction and proving with
correctly formatted inputs; see the top-level README.

## Security note on trusted setup

The zkey files here are reproducible artifacts for a proof of concept. Their
security depends on at least one honest contributor having discarded their secret
during the ceremony. The fixed entropy shown above is for reproducibility only and
provides no security. A production deployment must run a real multi-party ceremony,
as stated in the paper.