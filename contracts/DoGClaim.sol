// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

error InsufficientBalance(uint256 requested, uint256 available);
error InvalidAddress(address addr);
error InvalidAmount(uint256 amount);
error InvalidTimestamp(uint256 timestamp);
error AlreadyClaimed(uint256 amount, uint256 timestamp);
error InvalidSignature(string message, address recovered, address signer);
error TransferFailed(address sender, address recipient, uint256 amount);

contract DoGClaim is AccessControlUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    event ClaimSucceeded(address to, uint256 amount, uint256 timestamp);
    event BalanceLoaded(address loader, uint256 amount, uint256 balance);

    address public signer;
    address public feeWallet;
    address public token;
    mapping(bytes32 key => bool) private _claims;
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

        token = _token;
        signer = _signer;
        feeWallet = _feeWallet;
        _grantRole(ADMIN_ROLE, _admin);

        if (_fee > 100) {
            revert InvalidAmount(_fee);
        }
        _feeRate = _fee;

        if (_expiryTime == 0) {
            revert InvalidAmount(_expiryTime);
        }
        _expiry = _expiryTime;
    }

    function withdraw() public onlyRole(ADMIN_ROLE) {
        if (_balance == 0) {
            revert InsufficientBalance(_balance, 0);
        }
        uint256 _oldBalance = _balance;
        _balance = 0;

        bool success = IERC20(token).transfer(_msgSender(), _oldBalance);
        if (!success) {
            revert TransferFailed(address(this), _msgSender(), _oldBalance);
        }
    }

    function load(uint256 amount) public onlyRole(ADMIN_ROLE) {
        if (amount == 0) {
            revert InvalidAmount(amount);
        }

        bool success = IERC20(token).transferFrom(_msgSender(), address(this), amount);
        if (!success) {
            revert TransferFailed(_msgSender(), address(this), amount);
        }
        _balance += amount;
        emit BalanceLoaded(_msgSender(), amount, _balance);
    }

    function updateSignerWallet(address newSignerWallet) public onlyRole(ADMIN_ROLE) {
        if (newSignerWallet == address(0)) {
            revert InvalidAddress(newSignerWallet);
        }
        signer = newSignerWallet;
    }

    function updateFeeWallet(address newFeeWallet) public onlyRole(ADMIN_ROLE) {
        if (newFeeWallet == address(0)) {
            revert InvalidAddress(newFeeWallet);
        }
        feeWallet = newFeeWallet;
    }

    function updateFeeRate(uint256 newFeeRate) public onlyRole(ADMIN_ROLE) {
        if (newFeeRate > 100) {
            revert InvalidAmount(newFeeRate);
        }
        _feeRate = newFeeRate;
    }

    function updateExpiry(uint256 newExpiry) public onlyRole(ADMIN_ROLE) {
        if (newExpiry == 0) {
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

    function claim(uint256 amount, uint256 timestamp, bytes memory signature) public {
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

        if (_claims[messageHash]) {
            revert AlreadyClaimed(amount, timestamp);
        }

        bytes32 signedMessageHash = messageHash.toEthSignedMessageHash();

        if (signedMessageHash.recover(signature) != signer) {
            revert InvalidSignature(message, signedMessageHash.recover(signature), signer);
        }

        _claims[messageHash] = true;
        _balance -= amount;
        _nonces[_msgSender()] += 1;

        uint256 feeAmount = amount * _feeRate / 100;
        uint256 withdrawAmount = amount - feeAmount;

        bool success = IERC20(token).transfer(_msgSender(), withdrawAmount);
        if (!success) {
            revert TransferFailed(address(this), _msgSender(), withdrawAmount);
        }

        if (feeAmount > 0) {
            success = IERC20(token).transfer(feeWallet, feeAmount);
            if (!success) {
                revert TransferFailed(address(this), feeWallet, feeAmount);
            }
        }

        emit ClaimSucceeded(_msgSender(), amount, timestamp);
    }

    function checkClaim(address user, uint256 amount, uint256 timestamp, uint256 nonce) public view returns (bool) {
        string memory message = getClaimMessage(user, amount, timestamp, nonce);
        bytes32 messageHash = keccak256(abi.encodePacked(message));
        return _claims[messageHash];
    }

    function invalidateClaim(address user, uint256 amount, uint256 timestamp, uint256 nonce) public onlyRole(ADMIN_ROLE) {
        string memory message = getClaimMessage(user, amount, timestamp, nonce);
        bytes32 messageHash = keccak256(abi.encodePacked(message));
        _claims[messageHash] = true;
    }

    function getBalance() public view returns (uint256) {
        return _balance;
    }

    function getNonce(address user) public view returns (uint256) {
        return _nonces[user];
    }
}
