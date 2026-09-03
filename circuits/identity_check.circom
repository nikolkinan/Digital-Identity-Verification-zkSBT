pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * birthTimestamp encoding convention:
 *   birthTimestamp = unixSeconds + 2208988800
 *   The offset 2208988800 is the interval between 1900-01-01 and 1970-01-01 in seconds.
 *   Without the offset, individuals born before 1970 would have negative unix timestamps, which would wrap around to very large values in the prime field and break the comparator.
 *   The Issuer and smart contract MUST use the same offset.
 *
 * The order of public inputs binds to pubSignals[] in Verifier.sol. Do not change this without modifying the contract:
 *   pubSignals[0] = onChainHash
 *   pubSignals[1] = birthCutoff
 *   pubSignals[2] = regionCode
 *   pubSignals[3] = sessionChallenge
 */

template IdentityCheck() {

    // Public inputs
    signal input onChainHash;        // pubSignals[0]  anchor Poseidon from registry
    signal input birthCutoff;        // pubSignals[1]  the contract is calculated starting from the ageThreshold
    signal input regionCode;         // pubSignals[2]  policy Verifier
    signal input sessionChallenge;   // pubSignals[3]  session challenge binding

    // Private inputs (witness)
    signal input secretID;
    signal input secretSalt;
    signal input birthTimestamp;     // seconds since 1900-01-01
    signal input domicileCode;

    // Constraint A: commitment integrity
    // Binding the four attributes. The input order must be identical to that used by the Issuer in Algorithm 2; otherwise, the commitment will never match.
    component hasher = Poseidon(4);
    hasher.inputs[0] <== secretID;
    hasher.inputs[1] <== secretSalt;
    hasher.inputs[2] <== birthTimestamp;
    hasher.inputs[3] <== domicileCode;

    onChainHash === hasher.out;

    // Constraint B: age threshold via birth date cutoff
    // Being born on or before the cutoff means meeting the age threshold.
    // A 64-bit width provides significant headroom for offset values (~4e9).
    // The validity of the birthTimestamp range follows from Constraint A: its value is bound to the commitment created by the Issuer, not chosen by the prover.
    component bornBefore = LessEqThan(64);
    bornBefore.in[0] <== birthTimestamp;
    bornBefore.in[1] <== birthCutoff;
    bornBefore.out === 1;

    // Constraint C: domicile binding
    domicileCode === regionCode;

    // Constraint D: session challenge binding
    // A public input that does not appear in any constraint has a zero wire polynomial; consequently, its IC element becomes the identity, and its value has no effect on the Groth16 verification equation. This means an attacker is free to alter its value. A single multiplication forces it into the R1CS.
    signal sessionChallengeSq;
    sessionChallengeSq <== sessionChallenge * sessionChallenge;
}

component main {public [onChainHash, birthCutoff, regionCode, sessionChallenge]} = IdentityCheck();