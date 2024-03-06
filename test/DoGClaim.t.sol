// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {DoGClaim} from "../contracts/DoGClaim.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract DoGClaimTest is Test {
    DoGClaim public dogClaim;
    address public signerWallet;
    address public token;
    uint256 public amount;
    address public feeWallet;
    address public admin;
    using MessageHashUtils for bytes32;

    function setUp() public {
        signerWallet = vm.addr(1);
        feeWallet = vm.addr(3);
        admin = vm.addr(5);

        MockERC20 mockToken = new MockERC20("MockToken", "MTK");
        token = address(mockToken);
        dogClaim = new DoGClaim();
        amount = 10000000;

        vm.expectRevert();
        dogClaim.initialize(address(0), signerWallet, feeWallet, admin);

        vm.expectRevert();
        dogClaim.initialize(token, address(0), feeWallet, admin);

        vm.expectRevert();
        dogClaim.initialize(token, signerWallet, address(0), admin);

        vm.expectRevert();
        dogClaim.initialize(token, signerWallet, feeWallet, address(0));

        dogClaim.initialize(token, signerWallet, feeWallet, admin);
    }

    function claim(address sender, uint256 mintAmount) public {
        vm.warp(2 hours);
        uint256 ts = block.timestamp * 1000;
        string memory _msg = string.concat(
            Strings.toString(mintAmount),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toHexString(uint160(address(dogClaim)), 20),
            ":",
            Strings.toString(ts)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        dogClaim.claim(mintAmount, ts, signature);
    }

    function test_FailClaimNotLoaded() public {
        vm.prank(signerWallet);
        vm.expectRevert();

        claim(signerWallet, amount);
    }

    function test_FailClaimZero() public {
        vm.prank(signerWallet);
        vm.expectRevert();

        claim(signerWallet, 0);
    }

    function test_FailLoadInvalidAmount() public {
        vm.prank(signerWallet);
        vm.expectRevert();

        dogClaim.load(0);
    }

    function test_FailWithdrawEmpty() public {
        vm.prank(admin);
        vm.expectRevert();

        dogClaim.withdraw();
    }

    function test_FailLoadTooMuch() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        vm.expectRevert();
        claim(sender, amount + 1);
    }

    function test_loadAndClaim() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        claim(sender, 1);

        // Incorrect user
        vm.warp(2 hours);
        bool used = dogClaim.checkClaim(signerWallet, amount, block.timestamp * 1000);
        assertFalse(used, "Claim should not be used");
    }

    function test_FailReplay() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        claim(sender, 1);

        vm.prank(sender);
        vm.expectRevert();
        claim(sender, 1);
    }

    function test_FailInvalidSignature() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.warp(2 hours);

        vm.prank(sender);
        string memory _msg = string.concat(
            Strings.toString(1),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toHexString(uint160(address(dogClaim)), 20),
            ":",
            Strings.toString(block.timestamp * 1000)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert();
        dogClaim.claim(1000, block.timestamp * 1000, signature);
    }

    function test_FailInvalidTimestamp() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.warp(2 hours);
        uint256 ts = (block.timestamp - (1 hours + 1)) * 1000;

        vm.prank(sender);
        string memory _msg = string.concat(
            Strings.toString(amount),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toHexString(uint160(address(dogClaim)), 20),
            ":",
            Strings.toString(ts)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert();
        dogClaim.claim(amount, ts, signature);
    }

    function testFuzzClaim(address sender, uint256 _number) public {
        vm.assume(sender != address(0));
        vm.assume(_number > 0);

        uint256 ts = block.timestamp;

        vm.prank(sender);
        MockERC20(token).mint(sender, _number);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), _number);

        vm.prank(sender);
        dogClaim.load(_number);

        vm.prank(sender);
        string memory _msg = string.concat(
            Strings.toString(_number),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toHexString(uint160(address(dogClaim)), 20),
            ":",
            Strings.toString(ts)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        dogClaim.claim(_number, ts, signature);
    }

    function testFuzzLoad(address sender, uint256 _number) public {
        vm.assume(sender != address(0));
        vm.assume(_number > 0);

        vm.prank(sender);
        MockERC20(token).mint(sender, _number);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), _number);

        vm.prank(sender);
        dogClaim.load(_number);
    }

    function test_withdraw() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(admin);
        dogClaim.withdraw();
    }

    function test_FailWithdrawPermissions() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        vm.expectRevert();
        dogClaim.withdraw();
    }

    function test_getBalance() public {
        assertTrue(dogClaim.getBalance() == 0, "Initial balance should be 0");

        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        dogClaim.getBalance();
        assertTrue(dogClaim.getBalance() == amount, "Balance should be equal to amount");
    }

    function testFuzzClaimAndCheck(address sender, uint256 _number) public {
        vm.assume(sender != address(0));
        vm.assume(_number > 0);

        uint256 ts = block.timestamp;

        bool used = dogClaim.checkClaim(sender, _number, ts);
        assertFalse(used, "Claim should not yet be used");

        vm.prank(sender);
        MockERC20(token).mint(sender, _number);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), _number);

        vm.prank(sender);
        dogClaim.load(_number);

        vm.prank(sender);
        string memory _msg = string.concat(
            Strings.toString(_number),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toHexString(uint160(address(dogClaim)), 20),
            ":",
            Strings.toString(ts)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        dogClaim.claim(_number, ts, signature);

        used = dogClaim.checkClaim(sender, _number, ts);
        assertTrue(used, "Claim should be used");
    }
}