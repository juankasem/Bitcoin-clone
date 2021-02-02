const { Blockchain, Transaction} = require('./blockchain');
const EC = require('elliptic').ec
const ec = new EC('secp256k1');

// Calculate private key
const myKey = ec.keyFromPrivate("384r3fh3hf483h4fuh3f49389p3");

// Calculate public key (which doubles as your wallet address)
const myWalletAddress = myKey.getPublic('hex');


let blockChain = new Blockchain();

// Create a transaction & sign it with your key
const trans1 = new Transaction(myWalletAddress, "address2", 30);
trans1.signTransaction(myKey);
blockChain.addTransaction(trans1);

//Mine Block
console.log("start mining...");
blockChain.minePendingTransactions(myWalletAddress);

console.log("Balance of Juan is:", blockChain.getBalanceOfAddress(myWalletAddress));