// contracts/src/Paymaster.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract Paymaster {
    function sponsorTransaction(address target, bytes calldata data) external payable {
        (bool success,) = target.call(data);
        require(success, "Transaction failed");
    }
}
