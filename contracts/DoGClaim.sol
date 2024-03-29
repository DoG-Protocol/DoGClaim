// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

error InsufficientBalance(uint256 requested, uint256 available);
error InvalidAddress(address addr);
error InvalidAmount(uint256 amount);
error InvalidTimestamp(uint256 timestamp);
error AlreadyClaimed(uint256 amount, uint256 timestamp);
error InvalidSignature(string message, address recovered, address signer);

contract DoGClaim is AccessControlUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    event ClaimSucceeded(address to, uint256 amount, uint256 timestamp);
    event BalanceLoaded(address loader, uint256 amount, uint256 balance);

    address public signer;
    address public feeWallet;
    address public token;
    mapping(bytes32 key => uint256) private _claims;
    mapping(address user => uint256) private _nonces;
    uint256 private _balance;
    uint256 private _feeRate;
    uint256 private _expiry;

    function initialize(address _token, address _signer, address _feeWallet, address _admin, uint256 _fee, uint256 _expiryTime) external initializer {
        AccessControlUpgradeable.__AccessControl_init();

        if (_token == address(0)) {
            revert InvalidAddress(_token);
        }

        if (_signer == address(0)) {
            revert InvalidAddress(_signer);
        }

        if (_feeWallet == address(0)) {
            revert InvalidAddress(_feeWallet);
        }

        if (_admin == address(0)) {
            revert InvalidAddress(_admin);
        }

        if (_fee > 100) {
            revert InvalidAmount(_fee);
        }

        if (_expiryTime == 0) {
            revert InvalidAmount(_expiryTime);
        }

        token = _token;
        signer = _signer;
        feeWallet = _feeWallet;
        _grantRole(ADMIN_ROLE, _admin);
        _feeRate = _fee;
        _expiry = _expiryTime;
    }

    function withdraw() external onlyRole(ADMIN_ROLE) {
        uint256 _oldBalance = _balance;
        if (_oldBalance == 0) {
            revert InsufficientBalance(_oldBalance, 0);
        }
        _balance = 0;

        IERC20(token).safeTransfer(_msgSender(), _oldBalance);
    }

    function load(uint256 amount) external onlyRole(ADMIN_ROLE) {
        if (amount == 0) {
            revert InvalidAmount(amount);
        }

        _balance = _balance + amount;
        IERC20(token).safeTransferFrom(_msgSender(), address(this), amount);
        emit BalanceLoaded(_msgSender(), amount, _balance);
    }

    function updateSignerWallet(address newSignerWallet) external onlyRole(ADMIN_ROLE) {
        if (newSignerWallet == address(0) || newSignerWallet == signer) {
            revert InvalidAddress(newSignerWallet);
        }
        signer = newSignerWallet;
    }

    function updateFeeWallet(address newFeeWallet) external onlyRole(ADMIN_ROLE) {
        if (newFeeWallet == address(0) || newFeeWallet == feeWallet) {
            revert InvalidAddress(newFeeWallet);
        }
        feeWallet = newFeeWallet;
    }

    function updateFeeRate(uint256 newFeeRate) external onlyRole(ADMIN_ROLE) {
        if (newFeeRate > 100 || newFeeRate == _feeRate) {
            revert InvalidAmount(newFeeRate);
        }
        _feeRate = newFeeRate;
    }

    function updateExpiry(uint256 newExpiry) external onlyRole(ADMIN_ROLE) {
        if (newExpiry == 0 || newExpiry == _expiry) {
            revert InvalidAmount(newExpiry);
        }
        _expiry = newExpiry;
    }

    function getClaimMessage(address user, uint256 amount, uint256 timestamp, uint256 nonce) private view returns (string memory) {
        string memory message = string.concat(
            Strings.toString(nonce),
            ":",
            Strings.toString(amount),
            ":",
            Strings.toHexString(uint160(user), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toHexString(uint160(address(this)), 20),
            ":",
            Strings.toString(timestamp)
        );
        return message;
    }

    function claim(uint256 amount, uint256 timestamp, bytes memory signature) external {
        if (amount > _balance) {
            revert InsufficientBalance(amount, _balance);
        }
        if (amount == 0) {
            revert InvalidAmount(amount);
        }

        uint256 providedTimestampInSeconds = timestamp / 1000;
        if (block.timestamp - providedTimestampInSeconds > _expiry * 1 minutes) {
            revert InvalidTimestamp(timestamp);
        }

        uint256 nonce = _nonces[_msgSender()];
        string memory message = getClaimMessage(_msgSender(), amount, timestamp, nonce);
        bytes32 messageHash = keccak256(abi.encodePacked(message));

        if (_claims[messageHash] == 1) {
            revert AlreadyClaimed(amount, timestamp);
        }

        bytes32 signedMessageHash = messageHash.toEthSignedMessageHash();

        address recovered = signedMessageHash.recover(signature);

        if (recovered != signer) {
            revert InvalidSignature(message, recovered, signer);
        }

        _claims[messageHash] = 1;
        _balance = _balance - amount;
        _nonces[_msgSender()] = _nonces[_msgSender()] + 1;

        uint256 feeAmount = amount * _feeRate / 100;
        uint256 withdrawAmount = amount - feeAmount;

        IERC20(token).safeTransfer(_msgSender(), withdrawAmount);

        if (feeAmount != 0) {
            IERC20(token).safeTransfer(feeWallet, feeAmount);
        }

        emit ClaimSucceeded(_msgSender(), amount, timestamp);
    }

    function checkClaim(address user, uint256 amount, uint256 timestamp, uint256 nonce) external view returns (bool) {
        string memory message = getClaimMessage(user, amount, timestamp, nonce);
        bytes32 messageHash = keccak256(abi.encodePacked(message));
        return _claims[messageHash] == 1;
    }

    function invalidateClaim(address user, uint256 amount, uint256 timestamp, uint256 nonce) external onlyRole(ADMIN_ROLE) {
        string memory message = getClaimMessage(user, amount, timestamp, nonce);
        bytes32 messageHash = keccak256(abi.encodePacked(message));
        _claims[messageHash] = 1;
    }

    function getBalance() external view returns (uint256) {
        return _balance;
    }

    function getNonce(address user) external view returns (uint256) {
        return _nonces[user];
    }
}
