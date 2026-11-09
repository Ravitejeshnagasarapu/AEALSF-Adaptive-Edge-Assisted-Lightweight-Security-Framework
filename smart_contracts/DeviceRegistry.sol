pragma solidity ^0.8.19;

contract DeviceRegistry {
    enum DeviceState {
        UNREGISTERED,
        ACTIVE,
        MONITOR,
        ISOLATED,
        REVOKED
    }

    struct DeviceRecord {
        string deviceId;
        string deviceName;
        string deviceDescription;
        address walletAddress;
        bytes32 nizkPkFingerprint;
        bytes32 hePublicKeyHash;
        uint256 registeredAt;
        uint256 lastAuthenticatedAt;
        uint256 reputationScore;
        DeviceState state;
    }

    address public immutable governanceAdmin;
    mapping(string => DeviceRecord) private devicesById;
    mapping(address => string) private deviceIdByWallet;
    mapping(bytes32 => bool) private usedPkFingerprints;
    string[] public registeredDeviceIds;

    event DeviceRegistered(
        string indexed deviceId,
        address indexed walletAddress,
        string deviceName,
        bytes32 nizkPkFingerprint,
        uint256 timestamp
    );
    event DeviceStateUpdated(
        string indexed deviceId,
        DeviceState oldState,
        DeviceState newState,
        uint256 reputationScore
    );

    modifier onlyAdmin() {
        require(msg.sender == governanceAdmin, "DeviceRegistry: caller is not governance admin");
        _;
    }

    constructor() {
        governanceAdmin = msg.sender;
    }

    function registerDevice(
        string calldata deviceId,
        string calldata deviceName,
        string calldata deviceDescription,
        address walletAddress,
        bytes32 nizkPkFingerprint,
        bytes32 hePublicKeyHash
    ) external returns (bytes32 uniqueIdHash) {
        require(bytes(deviceId).length > 0, "DeviceRegistry: empty deviceId");
        require(bytes(deviceName).length > 0, "DeviceRegistry: empty deviceName");
        require(walletAddress != address(0), "DeviceRegistry: zero walletAddress");
        require(nizkPkFingerprint != bytes32(0), "DeviceRegistry: empty NIZK fingerprint");
        require(
            devicesById[deviceId].state == DeviceState.UNREGISTERED,
            "DeviceRegistry: deviceId already registered"
        );
        require(
            bytes(deviceIdByWallet[walletAddress]).length == 0,
            "DeviceRegistry: walletAddress already bound"
        );
        require(
            !usedPkFingerprints[nizkPkFingerprint],
            "DeviceRegistry: NIZK public key fingerprint already registered"
        );

        devicesById[deviceId] = DeviceRecord({
            deviceId: deviceId,
            deviceName: deviceName,
            deviceDescription: deviceDescription,
            walletAddress: walletAddress,
            nizkPkFingerprint: nizkPkFingerprint,
            hePublicKeyHash: hePublicKeyHash,
            registeredAt: block.timestamp,
            lastAuthenticatedAt: 0,
            reputationScore: 7500,
            state: DeviceState.ACTIVE
        });

        deviceIdByWallet[walletAddress] = deviceId;
        usedPkFingerprints[nizkPkFingerprint] = true;
        registeredDeviceIds.push(deviceId);

        emit DeviceRegistered(
            deviceId,
            walletAddress,
            deviceName,
            nizkPkFingerprint,
            block.timestamp
        );

        return keccak256(abi.encodePacked(deviceId, walletAddress, nizkPkFingerprint));
    }

    function verifyDeviceFingerprint(
        string calldata deviceId,
        bytes32 candidateFingerprint
    ) external view returns (bool) {
        DeviceRecord storage rec = devicesById[deviceId];
        if (rec.state != DeviceState.ACTIVE && rec.state != DeviceState.MONITOR) {
            return false;
        }
        return rec.nizkPkFingerprint == candidateFingerprint;
    }

    function updateDeviceReputationAndState(
        string calldata deviceId,
        uint256 newReputationScore,
        DeviceState newState
    ) external onlyAdmin {
        DeviceRecord storage rec = devicesById[deviceId];
        require(rec.state != DeviceState.UNREGISTERED, "DeviceRegistry: unknown device");
        DeviceState oldState = rec.state;
        rec.reputationScore = newReputationScore;
        rec.state = newState;
        emit DeviceStateUpdated(deviceId, oldState, newState, newReputationScore);
    }

    function getDevice(string calldata deviceId) external view returns (DeviceRecord memory) {
        require(
            devicesById[deviceId].state != DeviceState.UNREGISTERED,
            "DeviceRegistry: device not found"
        );
        return devicesById[deviceId];
    }
}
