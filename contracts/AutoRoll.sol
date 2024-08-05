// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./interfaces/IVault.sol";
import "./interfaces/IMerkleAirdrop.sol";


/**
 * @dev The contract interacts with SOFA vaults (mint & burn) periodically
 * Delegated by users, it earns for users.
 * It is like a fund for users to purchase and redeem.
 * Can be modified to upgradeable if needed
 */
contract AutoRoll is Ownable, ERC20 {
    using SafeERC20 for IERC20;
    
    struct MintProduct {
        address vault;
        uint256 totalCollateral;
        //IVault.MintParams params;
        uint256[2] anchorPrices;
        uint256 makerCollateral;
        uint256 deadline;
        address maker;
        bytes makerSignature;
    }
    struct MintProductEarn {
        address vault;
        uint256 totalCollateral;
        //IVault.MintParamsEarn params;
        uint256[2] anchorPrices;
        uint256 collateralAtRisk;
        uint256 makerCollateral;
        uint256 deadline;
        address maker;
        bytes makerSignature;
    }
    struct BurnProductDNTEarn {
        address vault;
        uint256 term;
        uint256[2] anchorPrices;
        uint256 collateralAtRiskPercentage;
        uint256 isMaker;
    }
    struct BurnProductDNT {
        address vault;
        uint256 term;
        uint256[2] anchorPrices;
        uint256 isMaker;
    }
    struct BurnProductTrend { 
        address vault;
        uint256[2] anchorPrices;
        uint256 isMaker;
    }
    struct BurnProductTrendEarn {
        address vault;
        uint256[2] anchorPrices;
        uint256 collateralAtRiskPercentage;
        uint256 isMaker;
    }
    //constant
    bytes32 private constant EIP712DOMAIN_TYPEHASH = 
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    //different names but same content
    bytes32 private constant PORTFOLIOMINT_TYPEHASH =
        keccak256("PortfolioMint(address[] vaultMint,uint256 nonceMint)");
    bytes32 private constant PORTFOLIOBURN_TYPEHASH =
        keccak256("PortfolioBurn(address[] vaultBurn,uint256 nonceBurn)");
    //immutable
    bytes32 public immutable DOMAIN_SEPARATOR;
    IERC20 public immutable collateral;
    IMerkleAirdrop public immutable merkleAirdrop;
    address public manager; //signer of the portfolio, verified on-chain
    int256 public nonce; //portfolio tx number
    

    //event
    event LogSetManager(address indexed manager);

    //modifier


    constructor(
        string memory _name, //fund token name
        string memory _symbol, //fund token symbol
        IERC20 _collateral, //should be well known, because of cross contract call
        address _manager,   //shold be well prepared before set
        IMerkleAirdrop _merkleAirdrop, //MerkleAirdrop address
        address[] memory vaults //all possible SOFA vaults, must be reliable
    ) ERC20(_name, _symbol) {
        collateral = _collateral;
        manager = _manager;
        merkleAirdrop = _merkleAirdrop;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            EIP712DOMAIN_TYPEHASH,
            keccak256("AutoRoll"),
            keccak256("1.0"),
            block.chainid,
            address(this)
        ));
        //approve max for SOFA vaults
        for (uint256 i = 0; i < vaults.length; i++) {
            collateral.safeApprove(vaults[i], type(uint256).max);
        }
    }


    // ============ users ============

    /**
     * @dev users deposit collateral token to this contract
     */
    function deposit(
        uint256 amount
    ) external {
        //transfer collateral from the user to this contract
        collateral.safeTransferFrom(msg.sender, address(this), amount);
        //compute share
        //_mint(msg.sender, shares);

    }
    
    /**
     * @dev users withdraw collateral token to this contract
     */
    function withdraw(
        uint256 shares
    ) external {

    }

    /**
     * @dev users claim collateral from this contract, can use merkleroot style?
     */

    /**
     * @dev users claim RCH from this contract, use merkleroot style?
     */
    

    // ============ anyone as operator ============
    
    /**
     * @dev An operator can mint SOFA vaults with collateral balance in this contract.
     * Two loops for surge and earn, because their interfaces are different.
     * Therefor, the operator should sort the format for surge and earn according to the interface before call,
     * in order to save gas.
     * 
     * NOTE: Referral incentives can compensate gas cost, as anyone can be an operator
     */
    function mint(
        uint256 expiry, //all vaults have the same expiry, less calldata less gas
        MintProduct[] calldata mintProducts,
        MintProductEarn[] calldata mintProductEarns,
        address referral,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes memory encodeVaults = "";
        //surges
        for (uint256 i = 0; i < mintProducts.length; i++) {
            IVault(mintProducts[i].vault).mint(
                mintProducts[i].totalCollateral, 
                //mintProducts[i].params, 
                IVault.MintParams({
                    expiry: expiry,
                    anchorPrices: mintProducts[i].anchorPrices,
                    makerCollateral: mintProducts[i].makerCollateral,
                    deadline: mintProducts[i].deadline,
                    maker: mintProducts[i].maker,
                    makerSignature: mintProducts[i].makerSignature
                }),
                referral);
            encodeVaults = abi.encode(encodeVaults, mintProducts[i].vault);
        }
        //earns
        for (uint256 i = 0; i < mintProductEarns.length; i++) {
            IVault(mintProductEarns[i].vault).mint(
                mintProductEarns[i].totalCollateral, 
                //mintProductEarns[i].params,
                IVault.MintParamsEarn({
                    expiry: expiry,
                    anchorPrices: mintProductEarns[i].anchorPrices,
                    collateralAtRisk: mintProductEarns[i].collateralAtRisk,
                    makerCollateral: mintProductEarns[i].makerCollateral,
                    deadline: mintProductEarns[i].deadline,
                    maker: mintProductEarns[i].maker,
                    makerSignature: mintProductEarns[i].makerSignature
                }),
                referral);
            encodeVaults = abi.encode(encodeVaults, mintProductEarns[i].vault);
        }
        //verify signature
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                PORTFOLIOMINT_TYPEHASH,
                keccak256(encodeVaults),
                nonce++
            ))
        ));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == manager, "AutoRoll: mint invalid signature");
    }

    /**
     * @dev An operator can burn SOFA vault token for collateral into this contract.
     * Four loops for different vaults, because their interfaces are different.
     * Therefor, the operator should sort the format for dnts and trends according to the interface before call,
     * in order to save gas.
     * Function mint and burn have similar interface style, which are easy to call.
     */
    function burn(
        uint256 expiry, //all vaults have the same expiry, less calldata less gas
        BurnProductDNTEarn[] calldata burnProductDNTEarns,
        BurnProductDNT[] calldata burnProductDNTs,
        BurnProductTrend[] calldata burnProductTrends,
        BurnProductTrendEarn[] calldata burnProductTrendEarns,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes memory encodeVaults = "";
        for (uint256 i = 0; i < burnProductDNTEarns.length; i++) {
            IVault(burnProductDNTEarns[i].vault).burn(
                burnProductDNTEarns[i].term,
                expiry,
                burnProductDNTEarns[i].anchorPrices,
                burnProductDNTEarns[i].collateralAtRiskPercentage,
                burnProductDNTEarns[i].isMaker
            );
            encodeVaults = abi.encode(encodeVaults, burnProductDNTEarns[i].vault);
        }
        for (uint256 i = 0; i < burnProductDNTs.length; i++) {
            IVault(burnProductDNTs[i].vault).burn(
                burnProductDNTs[i].term,
                expiry,
                burnProductDNTs[i].anchorPrices,
                burnProductDNTs[i].isMaker
            );
            encodeVaults = abi.encode(encodeVaults, burnProductDNTs[i].vault);
        }
        for (uint256 i = 0; i < burnProductTrends.length; i++) {
            IVault(burnProductTrends[i].vault).burn(
                expiry,
                burnProductTrends[i].anchorPrices,
                burnProductTrends[i].isMaker
            );
            encodeVaults = abi.encode(encodeVaults, burnProductTrends[i].vault);
        }
        for (uint256 i = 0; i < burnProductTrendEarns.length; i++) {
            IVault(burnProductTrendEarns[i].vault).burn(
                expiry,
                burnProductTrendEarns[i].anchorPrices,
                burnProductTrendEarns[i].collateralAtRiskPercentage,
                burnProductTrendEarns[i].isMaker
            );
            encodeVaults = abi.encode(encodeVaults, burnProductTrendEarns[i].vault);
        }
        //verify signature
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                PORTFOLIOBURN_TYPEHASH,
                keccak256(encodeVaults),
                nonce++
            ))
        ));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == manager, "AutoRoll: burn invalid signature");
    }
    
    /**
     * @dev An operator can claim to this contract
     */
    function claimRCHOp(
        uint256 index, 
        uint256 amount, 
        bytes32[] calldata merkleProof
    ) external {
        merkleAirdrop.claim(index, amount, merkleProof);
    }


    // ============ administrator ============

    /**
     * @dev The admin can modify manager address if needed.
     */
    function setManager(address _manager) external onlyOwner {
        require(_manager != manager, "AutoRoll: the same manager");
        manager = _manager;
        emit LogSetManager(_manager);
    }

}