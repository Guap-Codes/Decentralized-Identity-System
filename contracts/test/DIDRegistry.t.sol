// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";
import "../src/DIDRegistry.sol";

contract DIDRegistryTest is Test {
    DIDRegistry registry;

    function setUp() public {
        registry = new DIDRegistry();
    }

    function testCreateDID() public {
        string memory id = "did:example:123";
        string memory document_json =
            '{"id":"did:example:123","publicKey":"0x010203","serviceEndpoint":"https://example.com"}';

        // Create a new DID
        registry.createDID(id, document_json);

        // Resolve the DID
        string memory resolved_document_json = registry.resolveDID(id);

        // Decode the resolved document JSON
        DIDRegistry.DIDDocument memory resolved_document =
            abi.decode(bytes(resolved_document_json), (DIDRegistry.DIDDocument));

        // Assertions
        assertEq(resolved_document.id, id);
        assertEq(resolved_document.publicKey, hex"010203");
        assertEq(resolved_document.serviceEndpoint, "https://example.com");
    }
}
