const SHA256 = require('crypto-js/sha256');
const EC = require('elliptic').ec
const ec = new EC('secp256k1');

class Transaction{
    constructor(fromAddress, toAddress, amount){
        this.fromAddress =fromAddress;
        this.toAddress=toAddress;
        this.amount= amount;
    }

    calculateHash(){
         return SHA256(this.fromAddress, this.toAddress, this.amount).toString();
    }

    signTransaction(signingKey){
        if(signingKey.getPublic('hex') !== this.fromAddress){
            throw new Error('You cannot dign transaction for other wallets.');
        }
        const hashTx = this.calculateHash();
        const sig = signingKey.sign(hashTx, 'base64');
        this.signature = sig.toDER('hex');
    }

    isValid(){
      if(this.fromAddress == null) return true;


      if(!this.signature || his.signature.length == 0){
          throw new Error('No Signaturre in this transaction');
      }

      const publicKey = ec.keyFromPublic(this.fromAddress, 'hex');
      return publicKey.verify(this.calculateHash(), this.signature)
    }
}

class Block{
    constructor(timestamp, transactions, previousHash = ''){
        this.timestamp= timestamp,
        this.transactions= transactions;
        this.previousHash= previousHash;
        this.hash= this.calculateHash();
        this.nonce = 0;
    }

    calculateHash(){
      return SHA256(this.index + this.previousHash + this.timestamp + JSON.stringify(this.data) + this.nonce).toString();
    }

    mineBlock(){
        while(this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0")){
            this.nonce++;
            this.hash= this.calculateHash();
        }
    }

    hasValidTransaction(){
      for(const trans of this.transactions){
          if(!trans.isValid()){
              return false
          }
      }

      return true;
    }
}

class Blockchain{
    constructor(){
        this.chain = [this.createGenesisBlock()];
        this.difficulty = 5;
        this.pendingTransactions = [];
        this.miningReward= 100;
    }

    createGenesisBlock(){
        return new Block("01/02/2021", "Genesis Block", "0");
    }

    getLastBlock(){
      this.chain[this.chain.length - 1];
    }

    minePendingTransactions(miningRewardAddress){
     const rewardTrans = new Transaction(null, miningRewardAddress, this.miningReward);
     this.pendingTransactions.push(rewardTrans);

     let block = new Block(Date.now(), this.pendingTransactions, this.getLastBlock().hash);
     block.mineBlock(this.difficulty);
     this.chain.push(block);

     this.pendingTransactions= [];
    }

    addTransaction(transaction){
        if(!transaction.fromAddress || !transaction.toAddress){
            throw new Error('Transaction must include from & to addresses');
        }
        
        if(!transaction.isValid()){
            throw new Error('Cannot add invalid transaction to chain');
        }

        this.pendingTransactions.push(transaction);
    }

    getBalanceOfAddress(address){
        let balance = 0;

        for(const block of this.chain){
            for(const trans of block.transactions){
                if(trans.fromAddress == address){
                    balance -= trans.amount
                }

                if(trans.toAddress == address){
                    balance += trans.amount
                }
            }
        }

        return balance;
    }

    isChainvalid(){
        for(let i = 1; i < this.chain.length; i++){
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if(!currentBlock.hasValidTransaction()){
                return false;
            }

            if(currentBlock.hash !== this.calculateHash()){
                return false;
            }

            if (currentBlock.previousHash !== previousBlock.hash){
               return false;
            }

            return true;
        }
    }
}

module.exports.Blockchain = Blockchain;
module.exports.Transaction = Transaction;
