// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract CredentialRegistry {
    // Verifiable Credential structure
    struct VerifiableCredential {
        string id;
        string issuer;
        string subject;
        string[] claimKeys;
        string[] claimValues;
        bytes signature;
    }

    // Mapping from credential ID to VerifiableCredential
    mapping(string => VerifiableCredential) private credentials;

    // Array to track active credential IDs
    string[] public activeCredentialIds;

    // Events
    event CredentialIssued(string indexed id, string issuer, string subject);
    event CredentialRevoked(string indexed id);

    // Issue a new Verifiable Credential
    function issueCredential(string memory credential_json) external {
        // Deserialize the JSON credential
        VerifiableCredential memory credential = abi.decode(bytes(credential_json), (VerifiableCredential));
        require(bytes(credential.id).length > 0, "Credential ID cannot be empty");
        require(bytes(credentials[credential.id].id).length == 0, "Credential already exists");

        // Store the credential and update active IDs
        credentials[credential.id] = credential;
        activeCredentialIds.push(credential.id);
        emit CredentialIssued(credential.id, credential.issuer, credential.subject);
    }

    // Revoke a Verifiable Credential
    function revokeCredential(string memory credential_id) external {
        require(bytes(credential_id).length > 0, "Credential ID cannot be empty");
        require(bytes(credentials[credential_id].id).length > 0, "Credential does not exist");

        // Remove from activeCredentialIds using swap-and-pop
        for (uint256 i = 0; i < activeCredentialIds.length; i++) {
            if (keccak256(bytes(activeCredentialIds[i])) == keccak256(bytes(credential_id))) {
                activeCredentialIds[i] = activeCredentialIds[activeCredentialIds.length - 1];
                activeCredentialIds.pop();
                break;
            }
        }

        // Delete the credential
        delete credentials[credential_id];
        emit CredentialRevoked(credential_id);
    }

    // Verify a Verifiable Credential
    function verifyCredential(string memory credential_id) external view returns (bool) {
        require(bytes(credential_id).length > 0, "Credential ID cannot be empty");
        return bytes(credentials[credential_id].id).length > 0;
    }

    // Retrieve Merkle proof for a credential
    function getMerkleProof(string memory credential_id)
        public
        view
        returns (uint256 root, uint256[] memory path, uint8[] memory indices)
    {
        // Find the index of the credential_id in activeCredentialIds
        uint256 index = type(uint256).max;
        for (uint256 i = 0; i < activeCredentialIds.length; i++) {
            if (keccak256(bytes(activeCredentialIds[i])) == keccak256(bytes(credential_id))) {
                index = i;
                break;
            }
        }
        require(index != type(uint256).max, "Credential not found");

        // Compute the Merkle tree size (next power of 2)
        uint256 n = activeCredentialIds.length;
        uint256 depth = 0;
        while ((1 << depth) < n) depth++;
        uint256 tree_size = 1 << depth;

        // Compute leaves as uint256 hashes
        uint256[] memory leaves = new uint256[](tree_size);
        for (uint256 i = 0; i < n; i++) {
            leaves[i] = uint256(keccak256(bytes(activeCredentialIds[i])));
        }
        for (uint256 i = n; i < tree_size; i++) {
            leaves[i] = 0; // Pad with zeros
        }

        // Generate the proof
        path = new uint256[](depth);
        indices = new uint8[](depth);
        uint256 current_index = index;
        for (uint256 level = 0; level < depth; level++) {
            uint256 sibling_index = current_index ^ 1; // XOR to get sibling
            if (sibling_index < tree_size) {
                path[level] = leaves[sibling_index];
                indices[level] = uint8(current_index % 2); // 0 if left, 1 if right
            } else {
                path[level] = 0;
                indices[level] = uint8(current_index % 2);
            }
            current_index = current_index / 2; // Move to parent
        }

        // Compute and return the root
        root = computeRoot(leaves);
        return (root, path, indices);
    }

    // Helper function to compute the Merkle root
    function computeRoot(uint256[] memory leaves) internal pure returns (uint256) {
        uint256 n = leaves.length;
        if (n == 0) return 0;
        while (n > 1) {
            uint256 m = (n + 1) / 2;
            for (uint256 i = 0; i < m; i++) {
                if (2 * i + 1 < n) {
                    leaves[i] = uint256(keccak256(abi.encodePacked(leaves[2 * i], leaves[2 * i + 1])));
                } else {
                    leaves[i] = leaves[2 * i];
                }
            }
            n = m;
        }
        return leaves[0];
    }
}
