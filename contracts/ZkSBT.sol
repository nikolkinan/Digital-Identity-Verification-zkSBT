// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface IVerifier {
    function verifyProof(
        uint[2]    calldata a,
        uint[2][2] calldata b,
        uint[2]    calldata c,
        uint[4]    memory   input
    ) external view returns (bool);
}

contract ZkSBT {
    using ECDSA for bytes32;

    string public name   = "CitizenIdentitySBT";
    string public symbol = "CZK";

    uint32 public constant CHALLENGE_WINDOW   = 30 days;
    uint32 public constant ARBITRATION_WINDOW = 1 days;

    uint256 public constant EPOCH_OFFSET     = 2208988800;   // 1900-01-01 -> 1970-01-01
    uint256 public constant SECONDS_PER_YEAR = 31557600;     // 365.25 days

    uint256 public constant SNARK_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 private constant DOM_MINT    = keccak256("zkSBT.v2.MINT");
    bytes32 private constant DOM_REISSUE = keccak256("zkSBT.v2.REISSUE");
    bytes32 private constant DOM_VERIFY  = keccak256("zkSBT.v2.VERIFY");
    bytes32 private constant DOM_DISPUTE = keccak256("zkSBT.v2.DISPUTE");
    bytes32 private constant DOM_VERDICT = keccak256("zkSBT.v2.VERDICT");
    bytes32 private constant DOM_REVOKE  = keccak256("zkSBT.v2.REVOKE");
    bytes32 private constant DOM_RECOVER = keccak256("zkSBT.v2.RECOVER");

    enum Status { VALID, SUSPENDED, CONTESTED, REVOKED }

    struct IdentityData {
        bytes32 commitment;      // Slot 1
        // -- Slot 2, tepat 32 byte --
        Status  status;          //  1 B
        uint32  expiry;          //  4 B   ; 0 = without expiry
        address holder;          // 20 B
        uint32  deadline;        //  4 B   ; SUSPENDED: dispute deadline
                                 //        ; CONTESTED: panel decision deadline
        uint16  disputeCount;    //  2 B
        bool    exists;          //  1 B
        // -- Slot 3+ --
        string  cid;
    }

    address   public immutable issuerSigner;
    IVerifier public immutable zkpVerifier;

    address[] public arbitrators;
    uint8     public immutable threshold;
    mapping(address => bool) public isArbitrator;

    mapping(uint256 => IdentityData) public identities;
    mapping(address => uint256) public holderToken;
    mapping(address => uint256) public issuanceNonce;   // anti-replay mint
    mapping(address => uint256) public verifierNonce;   // anti-replay verification

    uint256 private _tokenCounter;

    event MintedzkSBT(uint256 indexed tokenId, address indexed holder, bytes32 commitment, uint256 timestamp);
    event AccessVerified(uint256 indexed tokenId, address indexed verifier, uint256 timestamp);
    event CredentialRevoked(uint256 indexed tokenId, string reason, uint16 disputeCount, uint256 timestamp);
    event DisputeFiled(uint256 indexed tokenId, uint16 disputeCount, uint256 birthCutoff, uint256 regionCode, uint256 timestamp);
    event DisputeAdjudicated(uint256 indexed tokenId, uint16 disputeCount, bool upheldHolder, uint256 timestamp);
    event DisputeTimedOut(uint256 indexed tokenId, uint16 disputeCount, uint256 timestamp);
    event RevocationFinalized(uint256 indexed tokenId, uint256 timestamp);
    event CredentialReissued(uint256 indexed oldTokenId, uint256 indexed newTokenId, address indexed holder, uint256 timestamp);
    event CredentialRecovered(uint256 indexed oldTokenId, uint256 indexed newTokenId, address oldHolder, address newHolder, uint256 timestamp);

    modifier onlyIssuer() {
        require(msg.sender == issuerSigner, "Only issuer");
        _;
    }
    modifier tokenExists(uint256 tokenId) {
        require(identities[tokenId].exists, "Token not found");
        _;
    }
    modifier onlyHolder(uint256 tokenId) {
        require(msg.sender == identities[tokenId].holder, "Not credential holder");
        _;
    }

    constructor(
        address   _verifierAddress,
        address   _issuerSigner,
        address[] memory _arbitrators,
        uint8     _threshold
    ) {
        require(_verifierAddress != address(0) && _issuerSigner != address(0), "Zero address");
        require(_arbitrators.length >= 3, "Panel too small");
        require(_threshold >= 2 && _threshold <= _arbitrators.length, "Invalid threshold");

        for (uint256 i = 0; i < _arbitrators.length; i++) {
            address arb = _arbitrators[i];
            require(arb != address(0), "Zero arbitrator");
            require(arb != _issuerSigner, "Arbitrator cannot be issuer");
            require(!isArbitrator[arb], "Duplicate arbitrator");
            isArbitrator[arb] = true;
            arbitrators.push(arb);
        }

        zkpVerifier  = IVerifier(_verifierAddress);
        issuerSigner = _issuerSigner;
        threshold    = _threshold;
    }

    // ALGORITHM 3 - Mint

    function mintIdentity(
        address _holder,
        bytes32 _commitment,
        string  calldata _cid,
        uint32  _expiry,
        uint256 _nonce,
        bytes   calldata _signature
    ) external {
        require(_holder != address(0), "Zero holder");
        require(_nonce == issuanceNonce[_holder], "Bad issuance nonce");

        bytes32 payload = keccak256(abi.encode(
            block.chainid, address(this), DOM_MINT,
            _holder, _commitment, keccak256(bytes(_cid)), _expiry, _nonce
        ));
        require(
            MessageHashUtils.toEthSignedMessageHash(payload).recover(_signature) == issuerSigner,
            "Invalid issuer signature"
        );

        uint256 existing = holderToken[_holder];
        require(
            existing == 0 || identities[existing].status == Status.REVOKED,
            "Holder already has an active credential"
        );

        issuanceNonce[_holder] = _nonce + 1;
        _mint(_holder, _commitment, _cid, _expiry);
    }

    function _mint(
        address _holder,
        bytes32 _commitment,
        string  calldata _cid,
        uint32  _expiry
    ) internal returns (uint256 tokenId) {
        _tokenCounter++;
        tokenId = _tokenCounter;

        IdentityData storage id = identities[tokenId];
        id.commitment   = _commitment;
        id.status       = Status.VALID;
        id.expiry       = _expiry;
        id.holder       = _holder;
        id.deadline     = 0;
        id.disputeCount = 0;
        id.exists       = true;
        id.cid          = _cid;

        holderToken[_holder] = tokenId;
        emit MintedzkSBT(tokenId, _holder, _commitment, block.timestamp);
    }

    // ALGORITHM 5 - Verify

    function verifyIdentityAccess(
        uint256    tokenId,
        uint[2]    calldata a,
        uint[2][2] calldata b,
        uint[2]    calldata c,
        uint256    ageThreshold,
        uint256    birthCutoff,
        uint256    regionCode
    ) external returns (bool) {
        IdentityData storage id = identities[tokenId];

        if (!id.exists)                                     return false;
        if (id.status != Status.VALID)                      return false;
        if (id.expiry != 0 && block.timestamp >= id.expiry) return false;
        if (!_validCutoff(ageThreshold, birthCutoff))       return false;

        uint256 nonce = verifierNonce[msg.sender];
        uint[4] memory pub;
        pub[0] = uint256(id.commitment);
        pub[1] = birthCutoff;
        pub[2] = regionCode;
        pub[3] = uint256(keccak256(abi.encode(
            block.chainid, address(this), DOM_VERIFY, msg.sender, nonce
        ))) % SNARK_FIELD;

        if (!zkpVerifier.verifyProof(a, b, c, pub)) return false;

        verifierNonce[msg.sender] = nonce + 1;
        emit AccessVerified(tokenId, msg.sender, block.timestamp);
        return true;
    }

    function _validCutoff(uint256 ageThreshold, uint256 birthCutoff)
        internal view returns (bool)
    {
        uint256 today = (block.timestamp / 1 days) * 1 days;
        uint256 span  = ageThreshold * SECONDS_PER_YEAR;
        if (today < span) return false;
        uint256 c0 = today - span + EPOCH_OFFSET;
        return birthCutoff == c0 || birthCutoff == c0 - 1 days;
    }

    // ALGORITHM 6 - Revoke (suspend)
    //   Initial unilateral withdrawal; repeated withdrawal requires a panel quorum.

    function requestRevoke(
        uint256 tokenId,
        string  calldata reason,
        bytes[] calldata panelSignatures
    ) external onlyIssuer tokenExists(tokenId) {
        IdentityData storage id = identities[tokenId];
        require(id.status == Status.VALID, "Must be VALID");

        if (id.disputeCount > 0) {
            _requireQuorum(keccak256(abi.encode(
                block.chainid, address(this), DOM_REVOKE, tokenId, id.disputeCount
            )), panelSignatures);
        }

        id.status   = Status.SUSPENDED;
        id.deadline = uint32(block.timestamp + CHALLENGE_WINDOW);

        emit CredentialRevoked(tokenId, reason, id.disputeCount, block.timestamp);
    }

    // ALGORITHM 7 - Dispute (raising a case, not making a decision)

    function disputeRevocation(
        uint256    tokenId,
        uint[2]    calldata a,
        uint[2][2] calldata b,
        uint[2]    calldata c,
        uint256    birthCutoff,
        uint256    regionCode
    ) external tokenExists(tokenId) onlyHolder(tokenId) {
        IdentityData storage id = identities[tokenId];
        require(id.status == Status.SUSPENDED, "Must be SUSPENDED");
        require(block.timestamp < id.deadline, "Challenge window expired");

        uint[4] memory pub;
        pub[0] = uint256(id.commitment);
        pub[1] = birthCutoff;
        pub[2] = regionCode;
        pub[3] = uint256(keccak256(abi.encode(
            block.chainid, address(this), DOM_DISPUTE, tokenId, id.disputeCount
        ))) % SNARK_FIELD;

        require(zkpVerifier.verifyProof(a, b, c, pub), "Invalid dispute proof");

        id.status   = Status.CONTESTED;
        id.deadline = uint32(block.timestamp + ARBITRATION_WINDOW);

        emit DisputeFiled(tokenId, id.disputeCount, birthCutoff, regionCode, block.timestamp);
    }

    // ALGORITHM 8 - Adjudicate (panel decision)

    function resolveDispute(
        uint256 tokenId,
        bool    upholdHolder,
        bytes[] calldata signatures
    ) external tokenExists(tokenId) {
        IdentityData storage id = identities[tokenId];
        require(id.status == Status.CONTESTED, "Must be CONTESTED");
        require(block.timestamp < id.deadline, "Arbitration window expired");

        uint16 dc = id.disputeCount;
        _requireQuorum(keccak256(abi.encode(
            block.chainid, address(this), DOM_VERDICT, tokenId, dc, upholdHolder
        )), signatures);

        id.disputeCount = dc + 1;
        id.deadline     = 0;
        id.status       = upholdHolder ? Status.VALID : Status.REVOKED;

        emit DisputeAdjudicated(tokenId, dc, upholdHolder, block.timestamp);
    }

    // ALGORITHM 9 - Finalize (closing both types of timeouts)

    function finalizeRevocation(uint256 tokenId) external tokenExists(tokenId) {
        IdentityData storage id = identities[tokenId];
        Status s = id.status;
        require(s == Status.SUSPENDED || s == Status.CONTESTED, "Not closable");
        require(block.timestamp >= id.deadline, "Window not expired");

        id.deadline = 0;

        if (s == Status.SUSPENDED) {
            id.status = Status.REVOKED;
            emit RevocationFinalized(tokenId, block.timestamp);
        } else {
            uint16 dc = id.disputeCount;
            id.disputeCount = dc + 1;
            id.status = Status.VALID;
            emit DisputeTimedOut(tokenId, dc, block.timestamp);
        }
    }

    // Consensual re-issuance (legitimate attribute update)

    function revokeAndReissue(
        uint256 oldTokenId,
        bytes32 newCommitment,
        string  calldata newCid,
        uint32  newExpiry,
        bytes   calldata issuerSig,
        bytes   calldata holderSig
    ) external tokenExists(oldTokenId) {
        IdentityData storage old = identities[oldTokenId];
        require(old.status == Status.VALID, "Must be VALID");
        address holder = old.holder;

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encode(
            block.chainid, address(this), DOM_REISSUE,
            oldTokenId, holder, newCommitment, keccak256(bytes(newCid)), newExpiry
        )));
        require(digest.recover(issuerSig) == issuerSigner, "Invalid issuer signature");
        require(digest.recover(holderSig) == holder,       "Invalid holder signature");

        old.status   = Status.REVOKED;
        old.deadline = 0;
        emit CredentialRevoked(oldTokenId, "Superseded by consensual reissuance", old.disputeCount, block.timestamp);

        uint256 newTokenId = _mint(holder, newCommitment, newCid, newExpiry);
        emit CredentialReissued(oldTokenId, newTokenId, holder, block.timestamp);
    }

    // ALGORITHM 10 - Recover (Lost key holder)

    function recoverCredential(
        uint256 oldTokenId,
        address newHolder,
        bytes32 newCommitment,
        string  calldata newCid,
        uint32  newExpiry,
        bytes   calldata issuerSig,
        bytes[] calldata panelSignatures
    ) external tokenExists(oldTokenId) {
        IdentityData storage old = identities[oldTokenId];
        require(old.status == Status.VALID || old.status == Status.REVOKED, "Not recoverable");
        require(newHolder != address(0), "Zero holder");
        require(
            holderToken[newHolder] == 0 ||
            identities[holderToken[newHolder]].status == Status.REVOKED,
            "New wallet already bound"
        );

        address oldHolder = old.holder;

        bytes32 h = keccak256(abi.encode(
            block.chainid, address(this), DOM_RECOVER,
            oldTokenId, oldHolder, newHolder, newCommitment, keccak256(bytes(newCid)), newExpiry
        ));
        require(
            MessageHashUtils.toEthSignedMessageHash(h).recover(issuerSig) == issuerSigner,
            "Invalid issuer signature"
        );
        _requireQuorum(h, panelSignatures);

        if (old.status == Status.VALID) {
            old.status   = Status.REVOKED;
            old.deadline = 0;
        }
        if (holderToken[oldHolder] == oldTokenId) holderToken[oldHolder] = 0;

        uint256 newTokenId = _mint(newHolder, newCommitment, newCid, newExpiry);
        emit CredentialRecovered(oldTokenId, newTokenId, oldHolder, newHolder, block.timestamp);
    }

    // Quorum panel

    function _requireQuorum(bytes32 payload, bytes[] calldata signatures) internal view {
        require(signatures.length >= threshold, "Insufficient signatures");
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(payload);

        address last = address(0);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);
            require(signer > last, "Signatures unsorted or duplicated");
            require(isArbitrator[signer], "Signer not an arbitrator");
            last = signer;
        }
    }

    // View

    function arbitratorCount() external view returns (uint256) {
        return arbitrators.length;
    }

    function statusOf(uint256 tokenId) external view returns (Status) {
        require(identities[tokenId].exists, "Token not found");
        return identities[tokenId].status;
    }

    // Non-transferability applies by construction: this contract does not implement any transfer, approval, or delegation functions.
    // Field holder does not change after minting except through recoverCredential which requires panel attestation.
}
