// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract DIDRegistry {
    // DID Document structure
    struct DIDDocument {
        string id;
        bytes publicKey;
        string serviceEndpoint;
    }

    // Mapping from DID to DIDDocument
    mapping(string => DIDDocument) private dids;

    // Events
    event DIDCreated(string indexed id, bytes publicKey, string serviceEndpoint);
    event DIDUpdated(string indexed id, bytes newPublicKey, string newServiceEndpoint);

    // Create a new DID
    function createDID(string memory id, string memory document_json) external {
        require(bytes(id).length > 0, "DID ID cannot be empty");
        require(bytes(dids[id].id).length == 0, "DID already exists");

        // Deserialize the JSON document
        DIDDocument memory document = abi.decode(bytes(document_json), (DIDDocument));
        require(keccak256(bytes(document.id)) == keccak256(bytes(id)), "DID ID mismatch");

        // Store the DID document
        dids[id] = document;
        emit DIDCreated(id, document.publicKey, document.serviceEndpoint);
    }

    // Resolve a DID to its document
    function resolveDID(string memory id) external view returns (string memory document_json) {
        require(bytes(dids[id].id).length > 0, "DID does not exist");
        DIDDocument memory document = dids[id];
        document_json = string(abi.encode(document));
    }

    // Update a DID document
    function updateDID(string memory id, string memory document_json) external {
        require(bytes(dids[id].id).length > 0, "DID does not exist");

        // Deserialize the JSON document
        DIDDocument memory document = abi.decode(bytes(document_json), (DIDDocument));
        require(keccak256(bytes(document.id)) == keccak256(bytes(id)), "DID ID mismatch");

        // Update the DID document
        dids[id] = document;
        emit DIDUpdated(id, document.publicKey, document.serviceEndpoint);
    }
}
