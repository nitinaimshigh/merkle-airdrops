// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

 contract  MerkleAirdrop is EIP712 { 
    // some list of addresses
    // allow someone in the list to claim ERC20 tokens

    using SafeERC20 for IERC20;

    error MerkleAirdrop__InvalidProof();
    error MerkleAirdrop__AlreadyClaimed();
    error MerkleAirdrop__InvalidSignature();
    event Claim(address account, uint256 amount);

    address[] claimers;

    bytes32 private immutable i_merkleRoot;
    IERC20 private immutable i_airdropToken;
    bytes32 private constant MESSAGE_TYPEHASH = keccak256(
        "AirdropClaim(address account, uint256 amount)"
    );
    struct AirdropClaim {
        address account;
        uint256 amount;
    }

    mapping (address claimer => bool claimed) private s_hasClaimed;

    constructor(bytes32 merlkleRoot, IERC20 airdropToken) EIP712("MerkleAirdrop", "1") {
        i_merkleRoot = merlkleRoot;
        i_airdropToken = airdropToken;
    }

    function getMessageHash(address account, uint256 amount) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, AirdropClaim({account : account, amount : amount}))) );
    }

    function claim(
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if(s_hasClaimed[account]) {
            revert MerkleAirdrop__AlreadyClaimed();
        }
        if(!_isValidSignature(account, getMessageHash(account, amount), v, r, s)) {
            revert MerkleAirdrop__InvalidSignature();
        }
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(account, amount)))
        );

        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert MerkleAirdrop__InvalidProof();
        }
        s_hasClaimed[account] = true;
        emit Claim(account, amount);

        i_airdropToken.safeTransfer(account, amount);
    }

    function _isValidSignature(address account, bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure  returns(bool) {
        (address actulaSigner, ,) = ECDSA.tryRecover(digest, v, r, s); 
        return actulaSigner == account;       

    }

    function _getMerkleRoot() public view returns (bytes32) {
        return i_merkleRoot;
    }

    function _getAirdropToken() public view returns (IERC20) {
        return i_airdropToken;
    }

         
}




/*  MESSAGE_TYPEHASH is a constant bytes32 value that represents the typehash of the AirdropClaim struct.

In EIP-712, a typehash is a unique identifier for a specific data type, such as a struct or an array. It's used to identify the type of data being signed, and to ensure that the data is correctly formatted.

In this specific case, the MESSAGE_TYPEHASH constant is defined as:

solidity
CopyInsert
bytes32 private constant MESSAGE_TYPEHASH = keccak256(
    "AirdropClaim(address account, uint256 amount)"
);
Here's what's happening:

The keccak256 function is used to hash a string that represents the type of the AirdropClaim struct.
The string is a human-readable representation of the struct's type, including the names and types of its fields.
The resulting hash is a unique bytes32 value that represents the typehash of the AirdropClaim struct.
In other words, MESSAGE_TYPEHASH is a unique identifier that says "this is an AirdropClaim struct with an address field named account and a uint256 field named amount".

By using this typehash, the contract can ensure that the data being signed is correctly formatted and matches the expected type. This helps to prevent errors and ensures that the signature is valid. 


*/
