// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Quorum-attested release registry for Android APKs.
/// A release (app, versionCode, contentDigest) is trusted only when at least
/// k of the app's N registered builders have attested the same digest, the
/// version is not revoked, and the version is not below the app's floor.
contract ReleaseRegistry {
    struct App {
        address owner;
        uint8 threshold;
        uint8 builderCount;
        uint64 minVersion;
        bytes32 signerCertHash;
        bool exists;
    }

    enum Status {
        OK,
        UNKNOWN_APP,
        SIGNER_MISMATCH,
        REVOKED,
        BELOW_VERSION_FLOOR,
        QUORUM_NOT_REACHED
    }

    mapping(bytes32 => App) public apps;
    mapping(bytes32 => mapping(address => bool)) public isBuilder;
    // appId => version => digest => number of distinct builder attestations
    mapping(bytes32 => mapping(uint64 => mapping(bytes32 => uint8))) public attestCount;
    // appId => version => builder => already attested (one vote per builder per version)
    mapping(bytes32 => mapping(uint64 => mapping(address => bool))) public hasAttested;
    mapping(bytes32 => mapping(uint64 => bool)) public revoked;

    event AppRegistered(bytes32 indexed appId, address owner, uint8 threshold, uint8 builders);
    event Attested(bytes32 indexed appId, uint64 indexed version, bytes32 digest, address builder);
    event Revoked(bytes32 indexed appId, uint64 indexed version);
    event VersionFloorRaised(bytes32 indexed appId, uint64 minVersion);

    error AlreadyRegistered();
    error BadThreshold();
    error NotOwner();
    error NotBuilder();
    error AlreadyAttested();
    error FloorCannotDecrease();
    error DuplicateBuilder();

    modifier onlyOwner(bytes32 appId) {
        if (apps[appId].owner != msg.sender) revert NotOwner();
        _;
    }

    function appIdOf(string calldata packageName) public pure returns (bytes32) {
        return keccak256(bytes(packageName));
    }

    function registerApp(
        string calldata packageName,
        address[] calldata builders,
        uint8 threshold,
        bytes32 signerCertHash
    ) external returns (bytes32 appId) {
        appId = appIdOf(packageName);
        if (apps[appId].exists) revert AlreadyRegistered();
        if (threshold == 0 || threshold > builders.length || builders.length > 255) revert BadThreshold();
        for (uint256 i = 0; i < builders.length; i++) {
            if (isBuilder[appId][builders[i]]) revert DuplicateBuilder();
            isBuilder[appId][builders[i]] = true;
        }
        apps[appId] = App({
            owner: msg.sender,
            threshold: threshold,
            builderCount: uint8(builders.length),
            minVersion: 0,
            signerCertHash: signerCertHash,
            exists: true
        });
        emit AppRegistered(appId, msg.sender, threshold, uint8(builders.length));
    }

    function attest(bytes32 appId, uint64 version, bytes32 digest) external {
        if (!isBuilder[appId][msg.sender]) revert NotBuilder();
        if (hasAttested[appId][version][msg.sender]) revert AlreadyAttested();
        hasAttested[appId][version][msg.sender] = true;
        attestCount[appId][version][digest] += 1;
        emit Attested(appId, version, digest, msg.sender);
    }

    function revoke(bytes32 appId, uint64 version) external onlyOwner(appId) {
        revoked[appId][version] = true;
        emit Revoked(appId, version);
    }

    function raiseVersionFloor(bytes32 appId, uint64 minVersion) external onlyOwner(appId) {
        if (minVersion < apps[appId].minVersion) revert FloorCannotDecrease();
        apps[appId].minVersion = minVersion;
        emit VersionFloorRaised(appId, minVersion);
    }

    function verify(bytes32 appId, uint64 version, bytes32 digest, bytes32 certHash)
        external
        view
        returns (Status)
    {
        App storage a = apps[appId];
        if (!a.exists) return Status.UNKNOWN_APP;
        if (a.signerCertHash != certHash) return Status.SIGNER_MISMATCH;
        if (revoked[appId][version]) return Status.REVOKED;
        if (version < a.minVersion) return Status.BELOW_VERSION_FLOOR;
        if (attestCount[appId][version][digest] < a.threshold) return Status.QUORUM_NOT_REACHED;
        return Status.OK;
    }
}
