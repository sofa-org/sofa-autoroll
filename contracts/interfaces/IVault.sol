// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IVault {
    struct MintParams {
        uint256 expiry;
        uint256[2] anchorPrices;
        uint256 makerCollateral;
        uint256 deadline;
        address maker;
        bytes makerSignature;
    }
    struct MintParamsEarn {
        uint256 expiry;
        uint256[2] anchorPrices;
        uint256 collateralAtRisk;
        uint256 makerCollateral;
        uint256 deadline;
        address maker;
        bytes makerSignature;
    }
    
    function mint(uint256 totalCollateral, MintParams calldata params, address referral) external;
    function mint(uint256 totalCollateral, MintParamsEarn calldata params, address referral) external;
    //for struct BurnProductTrend
    function burn(uint256 expiry, uint256[2] calldata anchorPrices, uint256 isMaker) external;
    //for struct BurnProductDNT
    function burn(uint256 term, uint256 expiry, uint256[2] calldata anchorPrices, uint256 isMaker) external;
    //for struct BurnProductDNTEarn
    function burn(uint256 term, uint256 expiry, uint256[2] calldata anchorPrices, uint256 collateralAtRiskPercentage, uint256 isMaker) external;
    //for struct BurnProductTrendEarn
    function burn(uint256 expiry, uint256[2] calldata anchorPrices, uint256 collateralAtRiskPercentage, uint256 isMaker) external;

}