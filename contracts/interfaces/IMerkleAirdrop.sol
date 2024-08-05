// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IMerkleAirdrop {
    function claim(uint256 index, uint256 amount, bytes32[] calldata merkleProof) external;
}
