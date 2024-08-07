// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

library StructMath {
    function to88(uint256 a) internal pure returns (uint88 c) {
        require(a <= type(uint88).max, "AutoRoll: uint88 Overflow");
        c = uint88(a);
    }
    function to80(uint256 a) internal pure returns (uint80 c) {
        require(a <= type(uint80).max, "AutoRoll: uint40 Overflow");
        c = uint80(a);
    }
    function to40(uint256 a) internal pure returns (uint40 c) {
        require(a <= type(uint40).max, "AutoRoll: uint40 Overflow");
        c = uint40(a);
    }
}