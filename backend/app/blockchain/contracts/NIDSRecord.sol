// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NIDSRecord {
    address public owner;

    struct AlertRecord {
        bytes32 alertHash;
        uint256 timestamp;
        string severity;
    }

    struct IntegrityRecord {
        bytes32 fileHash;
        uint256 timestamp;
        string fileName;
    }

    mapping(string => AlertRecord) public alerts; // alertId -> record
    mapping(string => IntegrityRecord) public integrityHashes; // fileName -> hash

    event AlertResolved(string alertId, bytes32 alertHash, uint256 timestamp);
    event IncidentTriggered(string ipAddress, string reason, uint256 timestamp);
    event IntegrityUpdated(string fileName, bytes32 fileHash, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function recordAlert(string memory alertId, bytes32 alertHash, string memory severity) public {
        alerts[alertId] = AlertRecord(alertHash, block.timestamp, severity);
        emit AlertResolved(alertId, alertHash, block.timestamp);
    }

    function triggerIncidentResponse(string memory ipAddress, string memory reason) public {
        emit IncidentTriggered(ipAddress, reason, block.timestamp);
    }

    function updateIntegrityHash(string memory fileName, bytes32 fileHash) public onlyOwner {
        integrityHashes[fileName] = IntegrityRecord(fileHash, block.timestamp, fileName);
        emit IntegrityUpdated(fileName, fileHash, block.timestamp);
    }

    function getIntegrityHash(string memory fileName) public view returns (bytes32) {
        return integrityHashes[fileName].fileHash;
    }
}
