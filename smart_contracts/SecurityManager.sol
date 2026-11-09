pragma solidity ^0.8.19;

contract SecurityManager {
    struct AuthSession {
        string deviceId;
        bytes32 proofHash;
        bytes32 nonceHash;
        uint256 authenticatedAt;
        uint256 expiresAt;
        bool valid;
    }

    struct EdgeNodeAuth {
        string edgeNodeId;
        bytes32 publicTokenHash;
        bool authorized;
        uint256 registeredAt;
    }

    address public immutable admin;
    uint256 public maxRequestsPerWindow = 25;
    uint256 public windowDurationSeconds = 10;
    uint256 public dynamicDifficultyLevel = 1;

    mapping(bytes32 => bool) public consumedNonces;
    mapping(string => AuthSession) public activeSessions;
    mapping(string => EdgeNodeAuth) public authorizedEdgeNodes;
    mapping(string => uint256) public windowStartByDevice;
    mapping(string => uint256) public requestCountByDevice;
    mapping(string => bool) public blockedMaliciousDevices;

    event AuthenticationVerified(
        string indexed deviceId,
        bytes32 indexed proofHash,
        uint256 expiresAt
    );
    event SecurityAnomalyDetected(
        string indexed deviceId,
        string reason,
        uint256 timestamp
    );
    event EdgeNodeAuthorized(string indexed edgeNodeId, bytes32 publicTokenHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "SecurityManager: unauthorized caller");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function authorizeEdgeNode(
        string calldata edgeNodeId,
        bytes32 publicTokenHash
    ) external onlyAdmin {
        require(bytes(edgeNodeId).length > 0, "SecurityManager: empty edgeNodeId");
        require(publicTokenHash != bytes32(0), "SecurityManager: invalid token hash");
        authorizedEdgeNodes[edgeNodeId] = EdgeNodeAuth({
            edgeNodeId: edgeNodeId,
            publicTokenHash: publicTokenHash,
            authorized: true,
            registeredAt: block.timestamp
        });
        emit EdgeNodeAuthorized(edgeNodeId, publicTokenHash);
    }

    function recordNIZKAuthentication(
        string calldata deviceId,
        bytes32 proofHash,
        bytes32 nonceHash,
        uint256 ttlSeconds,
        bool r1csVerified
    ) external returns (bool) {
        require(!blockedMaliciousDevices[deviceId], "SecurityManager: device blocked for anomaly");
        require(!consumedNonces[nonceHash], "SecurityManager: replay attack nonce detected");
        require(r1csVerified, "SecurityManager: invalid NIZK proof constraint check");

        if (block.timestamp > windowStartByDevice[deviceId] + windowDurationSeconds) {
            windowStartByDevice[deviceId] = block.timestamp;
            requestCountByDevice[deviceId] = 1;
        } else {
            requestCountByDevice[deviceId] += 1;
            if (requestCountByDevice[deviceId] > maxRequestsPerWindow) {
                blockedMaliciousDevices[deviceId] = true;
                emit SecurityAnomalyDetected(
                    deviceId,
                    "DDoS rate limit exceeded",
                    block.timestamp
                );
                revert("SecurityManager: rate limit exceeded, device blocked");
            }
        }

        consumedNonces[nonceHash] = true;
        uint256 expiresAt = block.timestamp + ttlSeconds;
        activeSessions[deviceId] = AuthSession({
            deviceId: deviceId,
            proofHash: proofHash,
            nonceHash: nonceHash,
            authenticatedAt: block.timestamp,
            expiresAt: expiresAt,
            valid: true
        });

        emit AuthenticationVerified(deviceId, proofHash, expiresAt);
        return true;
    }

    function isDeviceAuthenticated(string calldata deviceId) external view returns (bool) {
        if (blockedMaliciousDevices[deviceId]) {
            return false;
        }
        AuthSession storage sess = activeSessions[deviceId];
        return sess.valid && (block.timestamp <= sess.expiresAt);
    }
}
