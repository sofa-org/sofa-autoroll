// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./interfaces/IVault.sol";
import "./interfaces/IMerkleAirdrop.sol";
import "./libraries/StructMath.sol";


/**
 * @dev The contract interacts with SOFA vaults (mint & burn) periodically
 * Delegated by users, it earns for users.
 * It is like a fund for users to purchase and redeem.
 * Can be modified to upgradeable if needed
 */
contract AutoRoll is Ownable, ERC20 {
    using SafeERC20 for IERC20Metadata;
    using SafeERC20 for IERC20;
    using StructMath for uint256;
    
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

    struct UserDeposit {    //total 1 word to save storage
        uint88 amount;      //user deposit amount that is not claimShared
        uint88 lastAmount;  //last amount
        uint40 round;       //round No. when user deposit
        uint40 lastRound;   //last round
    }
    struct UserWithdraw {   //total 1 word to save storage ###width should be modified
        uint88 shares;      //user withdraw shares that is not claimCollateral
        uint40 round;       //round No. when user withdraw
    }    
    struct RoundAmount {   //total 1 word to save storage  ###width should be modified
        uint88 deposit;    //users' total deposit amount in this round
        uint88 net;        //Collateral amount at the end of the round
        uint80 rch;        //total RCH claimed in this round. 80 is the smallest bitwidth for RCH
        uint88 withdraw;  //users' total withdraw shares in this round before burn
        uint88 shares;    //total (claimed + unclaimed) shares according to net
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
    IERC20 public immutable rch;
    IERC20Metadata public immutable collateral;
    IMerkleAirdrop public immutable merkleAirdrop;

    address public manager; //signer of the portfolio, verified on-chain
    uint256 public nonce; //portfolio tx number
    uint256 public round; //investment epoch, begin at mint and end at burn
    bool public rchClaimed; //operator has claimed RCH in this round
    bool public burned; //burn has happened in this round
    mapping(address => UserDeposit) public userDeposit;
    mapping(uint256 => RoundAmount) public roundAmount;
    mapping(address => UserWithdraw) public userWithdraw;

    //event
    event LogSetManager(address indexed manager);
    event LogDeposit(address indexed user, uint256 amount);
    event LogDepositRevoke(address indexed user, uint256 amount);
    event LogClaimShare(address indexed user, uint256 shares);
    event LogClaimRCH(address indexed user, uint256 amount);


    //modifier

    /**
     * @dev AutoRoll token has the same decimals with the collateral token, which save computing unit
     * Basic types are used in the interface, to make it easy read.
     */
    constructor(
        string memory _name, //fund token name
        string memory _symbol, //fund token symbol
        address _collateral, //should be well known, because of cross contract call
        address _rch,         //RCH address, may be different on different chains
        address _manager,   //shold be well prepared before set
        address _merkleAirdrop, //MerkleAirdrop address
        address[] memory vaults //all possible SOFA vaults, must be reliable
    ) ERC20(_name, _symbol) {
        collateral = IERC20Metadata(_collateral);
        rch = IERC20(_rch);
        manager = _manager;
        merkleAirdrop = IMerkleAirdrop(_merkleAirdrop);

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

    /**
     * @dev AutoRoll token has the same decimals with the collateral token, which save computing unit
     * It is consistent with SOFA vaults
     */
    function decimals() public view virtual override returns (uint8) {
        return collateral.decimals();
    }

    // ============ users ============
    
    /**
     * @dev one can claim share for others
     */
    function claimShare(address user) public {
        //checking should not revert, because of internal call
        //###storage ref should
        uint256 depositRound = userDeposit[user].round;
        if (round != depositRound && userDeposit[user].amount != 0) {
            uint256 shares;
            if (round != 0) {
                shares = userDeposit[user].amount * roundAmount[depositRound].shares / roundAmount[depositRound].net;
            } else {
                shares = userDeposit[user].amount;
            }
            _mint(user, shares);
            userDeposit[user].lastAmount = userDeposit[user].amount;
            userDeposit[user].amount = 0;
            userDeposit[user].lastRound = depositRound.to40();
            claimRCH(user);
            emit LogClaimShare(user, shares);
        }
    }
    
    /**
     * @dev one can claim RCH for others
     */
    function claimRCH(address user) public {
        //###the RCH should be accumulated, the method should be modified
        //what about use merkleroot style?
        claimShare(user);
        if (userDeposit[user].lastAmount != 0  && 
           (rchClaimed || ((round != 0) && userDeposit[user].lastRound != (round - 1)))) {
            uint256 amount = roundAmount[round - 1].rch * userDeposit[user].lastAmount / roundAmount[round - 1].deposit;
            userDeposit[user].lastAmount = 0;
            rch.safeTransfer(user, amount);
            emit LogClaimRCH(user, amount);
        }
         
    }

    /**
     * @dev users deposit collateral token to this contract
     * users can deposit at any time, as long as they have collateral tokens
     * must call claimRCH first, then claimShare
     */
    function deposit(uint256 amount) external {
        //invoke claimShare, which clean pending deposit amount
        claimShare(msg.sender);
        //update states
        //###storage ref should be used
        userDeposit[msg.sender].amount = (userDeposit[msg.sender].amount + amount).to88();
        userDeposit[msg.sender].round = round.to40();
        roundAmount[round].deposit = (roundAmount[round].deposit + amount).to88();

        //transfer collateral from the user to this contract
        collateral.safeTransferFrom(msg.sender, address(this), amount);
        emit LogDeposit(msg.sender, amount);
    }

    /**
     * @dev users revoke deposit
     * users can revoke deposit after deposit at the same round
     */
    function depositRevoke(uint256 amount) external {
        require(userDeposit[msg.sender].round == round, "AutoRoll: depositRevoke diff. round");
        require(userDeposit[msg.sender].amount >= amount, "AutoRoll: depositRevoke amount too large");
        userDeposit[msg.sender].amount = (userDeposit[msg.sender].amount - amount).to88();
        roundAmount[round].deposit = (roundAmount[round].deposit - amount).to88();
        collateral.safeTransfer(msg.sender, amount);
        //###is it ok not modify round?
        emit LogDepositRevoke(msg.sender, amount);
    }

    



    
    /**
     * @dev users withdraw collateral token to this contract
     */
    function withdraw(uint256 shares) external {
        claimCollateral(msg.sender);
        userWithdraw[msg.sender].shares = (userWithdraw[msg.sender].shares + shares).to88();
        userWithdraw[msg.sender].round = round.to40();
        roundAmount[round].withdraw = (roundAmount[round].withdraw + shares).to88();
        _burn(msg.sender, shares); //has shares checks
        //###emit 
    }

    /**
     * @dev users claim collateral from this contract, can use merkleroot style?
     */
    function claimCollateral(address user) public {
        if (userWithdraw[user].shares != 0 && (round != userWithdraw[user].round || burned)) {
            userWithdraw[user].shares = 0;
            uint256 withdrawRound = userWithdraw[user].round;
            uint256 amount = roundAmount[withdrawRound].net * userWithdraw[user].shares / roundAmount[withdrawRound].shares;
            collateral.safeTransfer(user, amount);
            //###emit
        }
    }

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
        if (round == 0) {
            roundAmount[0].shares = roundAmount[0].deposit;
        }
        //next round begin
        round++;
        rchClaimed = false;
        
        //###emit log
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
        //###may exceed range
        roundAmount[round].shares = roundAmount[round-1].shares - roundAmount[round].withdraw;
        roundAmount[round].net = ((collateral.balanceOf(address(this)) - roundAmount[round].deposit) 
                                 * roundAmount[round].shares / roundAmount[round-1].shares).to88();
        //###emit log
    }
    
    /**
     * @dev An operator can claim RCH to this contract
     * Claim as soon as possible, or users can't claim RCH of their own.
     * If not claimed at the end of this round, may prevent users deposit in the next round. 
     */
    function claimRCHOp(
        uint256 index,
        uint256 amount, 
        bytes32[] calldata merkleProof
    ) external {
        merkleAirdrop.claim(index, amount, merkleProof);
        rchClaimed = true;
        roundAmount[round-1].rch = amount.to80();
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

    // 

    

}