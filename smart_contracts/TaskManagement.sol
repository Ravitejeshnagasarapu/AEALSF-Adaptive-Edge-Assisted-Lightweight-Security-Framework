pragma solidity ^0.8.19;

contract TaskManagement {
    enum ExecutionMode {
        LOCAL_SECURITY_MODE,
        HYBRID_SECURITY_MODE,
        EDGE_ASSISTED_SECURITY_MODE
    }

    enum TaskStatus {
        CREATED,
        OFFLOADED,
        COMPLETED,
        VERIFIED,
        REJECTED
    }

    struct TaskRecord {
        string taskId;
        string deviceId;
        string assignedNodeId;
        ExecutionMode mode;
        TaskStatus status;
        bytes32 inputPayloadHash;
        bytes32 resultPayloadHash;
        bytes32 edgeReceiptSignatureHash;
        uint256 createdAt;
        uint256 completedAt;
    }

    mapping(string => TaskRecord) private tasks;
    string[] public allTaskIds;

    event TaskCreated(
        string indexed taskId,
        string indexed deviceId,
        ExecutionMode mode,
        string assignedNodeId,
        bytes32 inputPayloadHash
    );
    event TaskResultSubmitted(
        string indexed taskId,
        string indexed assignedNodeId,
        bytes32 resultPayloadHash,
        bytes32 edgeReceiptSignatureHash
    );
    event TaskResultVerified(string indexed taskId, bool verified);

    function createTask(
        string calldata taskId,
        string calldata deviceId,
        string calldata assignedNodeId,
        ExecutionMode mode,
        bytes32 inputPayloadHash
    ) external {
        require(bytes(taskId).length > 0, "TaskManagement: empty taskId");
        require(bytes(deviceId).length > 0, "TaskManagement: empty deviceId");
        require(inputPayloadHash != bytes32(0), "TaskManagement: invalid inputPayloadHash");
        require(tasks[taskId].createdAt == 0, "TaskManagement: duplicate taskId");

        tasks[taskId] = TaskRecord({
            taskId: taskId,
            deviceId: deviceId,
            assignedNodeId: assignedNodeId,
            mode: mode,
            status: mode == ExecutionMode.LOCAL_SECURITY_MODE
                ? TaskStatus.CREATED
                : TaskStatus.OFFLOADED,
            inputPayloadHash: inputPayloadHash,
            resultPayloadHash: bytes32(0),
            edgeReceiptSignatureHash: bytes32(0),
            createdAt: block.timestamp,
            completedAt: 0
        });
        allTaskIds.push(taskId);

        emit TaskCreated(taskId, deviceId, mode, assignedNodeId, inputPayloadHash);
    }

    function submitTaskResult(
        string calldata taskId,
        string calldata executorNodeId,
        bytes32 resultPayloadHash,
        bytes32 edgeReceiptSignatureHash
    ) external {
        TaskRecord storage t = tasks[taskId];
        require(t.createdAt != 0, "TaskManagement: task does not exist");
        require(
            t.status == TaskStatus.CREATED || t.status == TaskStatus.OFFLOADED,
            "TaskManagement: task already finalized"
        );
        require(resultPayloadHash != bytes32(0), "TaskManagement: empty result hash");
        require(
            keccak256(bytes(t.assignedNodeId)) == keccak256(bytes(executorNodeId)),
            "TaskManagement: executorNodeId mismatch"
        );

        t.resultPayloadHash = resultPayloadHash;
        t.edgeReceiptSignatureHash = edgeReceiptSignatureHash;
        t.status = TaskStatus.COMPLETED;
        t.completedAt = block.timestamp;

        emit TaskResultSubmitted(
            taskId,
            executorNodeId,
            resultPayloadHash,
            edgeReceiptSignatureHash
        );
    }

    function verifyRetrievedResult(
        string calldata taskId,
        bytes32 candidateResultHash
    ) external returns (bool) {
        TaskRecord storage t = tasks[taskId];
        require(t.createdAt != 0, "TaskManagement: task not found");
        require(
            t.status == TaskStatus.COMPLETED || t.status == TaskStatus.VERIFIED,
            "TaskManagement: result not yet submitted"
        );

        if (t.resultPayloadHash == candidateResultHash && candidateResultHash != bytes32(0)) {
            t.status = TaskStatus.VERIFIED;
            emit TaskResultVerified(taskId, true);
            return true;
        } else {
            t.status = TaskStatus.REJECTED;
            emit TaskResultVerified(taskId, false);
            return false;
        }
    }

    function getTask(string calldata taskId) external view returns (TaskRecord memory) {
        require(tasks[taskId].createdAt != 0, "TaskManagement: task not found");
        return tasks[taskId];
    }
}
