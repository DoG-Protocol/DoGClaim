// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {DoGClaim} from "../contracts/DoGClaim.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract DoGClaimTest is Test {
    DoGClaim public dogClaim;
    address public tester;
    address public token;
    uint256 public amount;
    address public feeWallet;
    address public admin;
    using MessageHashUtils for bytes32;

    function setUp() public {
        tester = vm.addr(1);
        feeWallet = vm.addr(3);
        admin = vm.addr(5);

        MockERC20 mockToken = new MockERC20("MockToken", "MTK");
        token = address(mockToken);
        dogClaim = new DoGClaim();
        amount = 10000000;

        dogClaim.initialize(token, tester, feeWallet, admin);
    }

    function claim(address sender, uint256 mintAmount, uint256 ts) public {
        string memory _msg = string.concat(
            Strings.toString(mintAmount),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toString(ts)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        dogClaim.claim(mintAmount, ts, signature);
    }

    function testFail_claimNotLoaded() public {
        vm.prank(tester);

        claim(tester, amount, block.timestamp);
    }

    function testFail_claimZero() public {
        vm.prank(tester);

        claim(tester, 0, block.timestamp);
    }

    function testFail_loadInvalidAmount() public {
        vm.prank(tester);
        dogClaim.load(0);
    }

    function testFail_withdrawEmpty() public {
        vm.prank(admin);
        dogClaim.withdraw();
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
        claim(sender, 1, block.timestamp);
    }

    function testFail_Replay() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        claim(sender, 1, block.timestamp);

        vm.prank(sender);
        claim(sender, 1, block.timestamp);
    }

    function testFail_InvalidSignature() public {
        address sender = vm.addr(2);

        vm.prank(sender);
        MockERC20(token).mint(sender, amount);

        vm.prank(sender);
        MockERC20(token).approve(address(dogClaim), amount);

        vm.prank(sender);
        dogClaim.load(amount);

        vm.prank(sender);
        string memory _msg = string.concat(
            Strings.toString(1),
            ":",
            Strings.toHexString(uint160(sender), 20),
            ":",
            Strings.toString(block.chainid),
            ":",
            Strings.toString(block.timestamp)
        );

        bytes32 message = keccak256(abi.encodePacked(_msg)).toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, message);

        bytes memory signature = abi.encodePacked(r, s, v);

        dogClaim.claim(1000, block.timestamp, signature);
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
}