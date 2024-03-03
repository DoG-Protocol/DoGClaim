// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

error InsufficientBalance(uint256 requested, uint256 available);
error InvalidAmount(uint256 amount);
error AlreadyClaimed(string claim);
error InvalidSignature(address signer, bytes32 hash);
error TransferFailed(address sender, address recipient, uint256 amount);

contract DoGClaim is AccessControlUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address public signer;
    address public feeWallet;
    address public token;
    mapping(bytes32 key => bool) private _claims;
    uint256 private _balance;

    function initialize(address _token, address _signer, address _feeWallet) external initializer {
        AccessControlUpgradeable.__AccessControl_init();

        token = _token;
        signer = _signer;
        feeWallet = _feeWallet;
    }

    function load(uint256 amount) public {
        if (amount <= 0) {
            revert InvalidAmount(amount);
        }

        bool success = IERC20(token).transferFrom(_msgSender(), address(this), amount);
        if (!success) {
            revert TransferFailed(_msgSender(), address(this), amount);
        }
        _balance += amount;
    }

    function claim(uint256 amount, string memory timestamp, bytes memory signature) public {
        if (amount > _balance) {
            revert InsufficientBalance(amount, _balance);
        }
        if (amount <= 0) {
            revert InvalidAmount(amount);
        }

        string memory message = string.concat(
            Strings.toString(amount),
            ":",
            Strings.toHexString(uint160(_msgSender()), 20),
            ":",
            timestamp
        );

        bytes32 messageHash = keccak256(abi.encodePacked(message));

        if (_claims[messageHash]) {
            revert AlreadyClaimed(message);
        }

        bytes32 signedMessageHash = messageHash.toEthSignedMessageHash();

        if (signedMessageHash.recover(signature) != signer) {
            revert InvalidSignature(signer, signedMessageHash);
        }

        _claims[messageHash] = true;
        _balance -= amount;

        uint256 feeAmount = amount / 5;
        uint256 withdrawAmount = amount - feeAmount;

        bool success = IERC20(token).transfer(_msgSender(), withdrawAmount);
        if (!success) {
            revert TransferFailed(address(this), _msgSender(), withdrawAmount);
        }

        success = IERC20(token).transfer(feeWallet, feeAmount);
        if (!success) {
            revert TransferFailed(address(this), feeWallet, feeAmount);
        }
    }
}
