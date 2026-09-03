// scripts/issuer/issuerCore.js
//
// Pure function on the Issuer side. Performs no network I/O. Reused by the CLI credential generator and the measurement test harness.


const { ethers }   = require("ethers");
const circomlibjs  = require("circomlibjs");

// The constant that must be identical to ZkSBT.sol
const EPOCH_OFFSET     = 2208988800n;   // 1900-01-01 -> 1970-01-01, seconds
const SECONDS_PER_YEAR = 31557600n;     // 365.25 days

/// Domain separator: the raw string must match exactly the one hashed with keccak in the contract. The contract uses keccak256("zkSBT.MINT"), and so on.
const DOM = {
  MINT:    "zkSBT.MINT",
  REISSUE: "zkSBT.REISSUE",
  VERIFY:  "zkSBT.VERIFY",
  DISPUTE: "zkSBT.DISPUTE",
  VERDICT: "zkSBT.VERDICT",
  REVOKE:  "zkSBT.REVOKE",
  RECOVER: "zkSBT.RECOVER",
};

function domSep(name) {
  /// The contract stores DOM_* as bytes32 = keccak256(string). The contract payload encodes that bytes32 value, so here, too, it must be the bytes32 result of the keccak hash, not the raw string.
  return ethers.keccak256(ethers.toUtf8Bytes(name));
}

// Poseidon 
let _poseidon = null;
async function getPoseidon() {
  if (!_poseidon) _poseidon = await circomlibjs.buildPoseidon();
  return _poseidon;
}

// Encoding birthTimestamp
  /// birthTimestamp = Unix birth seconds + epoch_offset. The offset prevents birth times prior to 1970 from becoming negative values ​​that wrap around within the prime field. The circuit and _validCutoff in the contract assume this encoding.
function encodeBirth(birthDateISO) {
  const unix = BigInt(Math.floor(new Date(birthDateISO + "T00:00:00Z").getTime() / 1000));
  return unix + EPOCH_OFFSET;
}

// Commitment Poseidon(4)
/// Required input sequence: (secretID, secretSalt, birthTimestamp, domicileCode).
async function computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode }) {
  const poseidon = await getPoseidon();
  const F = poseidon.F;
  const h = poseidon([secretID, secretSalt, birthTimestamp, domicileCode]);
  /// F.toObject -> BigInt in the field. The on-chain commitment is stored as bytes32.
  const asBig = F.toObject(h);
  return {
    field: asBig,                                 
    bytes32: ethers.zeroPadValue(ethers.toBeHex(asBig), 32),
  };
}

// Random Salt
function randomSalt() {
  return BigInt(ethers.hexlify(ethers.randomBytes(31)));
}

// Mint payload signature
  /// Must match the mintIdentity function in the contract.
async function signMint(issuerWallet, { chainId, contract, holder, commitmentBytes32, cid, expiry, nonce }) {
  const inner = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "bytes32", "address", "bytes32", "bytes32", "uint32", "uint256"],
    [
      chainId,
      contract,
      domSep(DOM.MINT),
      holder,
      commitmentBytes32,
      ethers.keccak256(ethers.toUtf8Bytes(cid)),  // contract: keccak256(bytes(_cid))
      expiry,
      nonce,
    ]
  );
  const payloadHash = ethers.keccak256(inner);
  /// signMessage on the raw bytes of the hash (not the hex string) = EIP-191 prefix applied to 32 bytes, equivalent to toEthSignedMessageHash(payloadHash) in the contract.
  return issuerWallet.signMessage(ethers.getBytes(payloadHash));
}

// Payload reissue signature (Requires the signatures of the Issuer and the Holder)
async function signReissue(wallet, { chainId, contract, oldTokenId, holder, newCommitmentBytes32, newCid, newExpiry }) {
  const inner = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "bytes32", "uint256", "address", "bytes32", "bytes32", "uint32"],
    [
      chainId, contract, domSep(DOM.REISSUE),
      oldTokenId, holder, newCommitmentBytes32,
      ethers.keccak256(ethers.toUtf8Bytes(newCid)), newExpiry,
    ]
  );
  return wallet.signMessage(ethers.getBytes(ethers.keccak256(inner)));
}

// Birth cutoff for an age threshold
function computeBirthCutoff(ageThreshold, nowUnixSeconds) {
  const now   = BigInt(nowUnixSeconds);
  const today = (now / 86400n) * 86400n;
  const span  = BigInt(ageThreshold) * SECONDS_PER_YEAR;
  if (today < span) throw new Error("ageThreshold is too large for the current timestamp");
  return today - span + EPOCH_OFFSET;
}

// Session challenge (replicating on-chain calculations)
const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function verifyChallenge({ chainId, contract, verifier, nonce }) {
  const enc = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "bytes32", "address", "uint256"],
    [chainId, contract, domSep(DOM.VERIFY), verifier, nonce]
  );
  return BigInt(ethers.keccak256(enc)) % SNARK_FIELD;
}

function disputeChallenge({ chainId, contract, tokenId, disputeCount }) {
  const enc = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "bytes32", "uint256", "uint16"],
    [chainId, contract, domSep(DOM.DISPUTE), tokenId, disputeCount]
  );
  return BigInt(ethers.keccak256(enc)) % SNARK_FIELD;
}

// Complete build witness for the circuit
async function buildCircuitInput({ secretID, secretSalt, birthTimestamp, domicileCode, ageThreshold, regionCode, sessionChallenge, nowUnixSeconds }) {
  const birthCutoff = computeBirthCutoff(ageThreshold, nowUnixSeconds);
  const { field: commitmentField } = await computeCommitment({ secretID, secretSalt, birthTimestamp, domicileCode });

  /// domicileCode must be the same as regionCode
  if (BigInt(domicileCode) !== BigInt(regionCode)) {
    throw new Error("domicileCode != regionCode: Constraint C will fail");
  }
  /// birthTimestamp must be <= birthCutoff
  if (BigInt(birthTimestamp) > birthCutoff) {
    throw new Error("birthTimestamp > birthCutoff: Holder is too young for the age threshold");
  }

  return {
    // public
    onChainHash:      commitmentField.toString(),
    birthCutoff:      birthCutoff.toString(),
    regionCode:       BigInt(regionCode).toString(),
    sessionChallenge: BigInt(sessionChallenge).toString(),
    // private
    secretID:         BigInt(secretID).toString(),
    secretSalt:       BigInt(secretSalt).toString(),
    birthTimestamp:   BigInt(birthTimestamp).toString(),
    domicileCode:     BigInt(domicileCode).toString(),
  };
}

module.exports = {
  EPOCH_OFFSET, SECONDS_PER_YEAR, SNARK_FIELD, DOM,
  domSep, getPoseidon, encodeBirth, computeCommitment, randomSalt,
  signMint, signReissue, computeBirthCutoff,
  verifyChallenge, disputeChallenge, buildCircuitInput,
};