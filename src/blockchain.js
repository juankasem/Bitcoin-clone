const SHA256 = require('crypto-js/sha256');
const EC = require('elliptic').ec
const ec = new EC('secp256k1');

class Transaction{
    constructor(fromAddress, toAddress, amount){
        this.fromAddress =fromAddress;
        this.toAddress=toAddress;
        this.amount= amount;
        this.timestamp = Date.now();
    }

     /**
   * Creates a SHA256 hash of the transaction
   *
   * @returns {string}
   */
    calculateHash(){
         return SHA256(this.fromAddress, this.toAddress, this.amount + this.timestamp).toString();
    }

     /**
   * Signs a transaction with the given signingKey (which is an Elliptic keypair
   * object that contains a private key). The signature is then stored inside the
   * transaction object and later stored on the blockchain.
   *
   * @param {string} signingKey
   */
    signTransaction(signingKey){
        if(signingKey.getPublic('hex') !== this.fromAddress){
            throw new Error('You cannot sign transaction for other wallets.');
        }
        const hashTx = this.calculateHash();
        const sig = signingKey.sign(hashTx, 'base64');

        this.signature = sig.toDER('hex');
    }

     /**
   * Checks if the signature is valid (transaction has not been tampered with).
   * It uses the fromAddress as the public key.
   *
   * @returns {boolean}
   */
    isValid(){
      // If the transaction doesn't have a from address we assume it's a
      // mining reward and that it's valid
      if(this.fromAddress == null) return true;


      if(!this.signature || this.signature.length == 0){
          throw new Error('No Signature in this transaction');
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

    /**
     Returns the SHA256 of this block (by processing all the data stored
   * inside this block)
   *
   * @returns {string}
   */
    calculateHash(){
      return SHA256(this.previousHash + this.timestamp + JSON.stringify(this.transactions) + this.nonce).toString();
    }
   
     /**
   * Starts the mining process on the block. It changes the 'nonce' until the hash
   * of the block starts with enough zeros (= difficulty)
   *
   * @param {number} difficulty
   */
    mineBlock(difficulty){
        while(this.hash.substring(0, difficulty) !== Array(difficulty + 1).join('0')){
            this.nonce++;
            this.hash = this.calculateHash();
        }
    }

     /**
   * Validates all the transactions inside this block (signature + hash) and
   * returns true if everything checks out. False if the block is invalid.
   *
   * @returns {boolean}
   */
    hasValidTransactions(){
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

    /**
     * Creates first(genesis) block of the chain
   * @returns {Block}
   */
    createGenesisBlock(){
        return new Block(Date.parse("2021-02-01"), [], "0");
    }

      /**
   * Returns the latest block on our chain. Useful when you want to create a
   * new Block and you need the hash of the previous Block.
   *
   * @returns {Block[]}
   */
    getLatestBlock(){
      return this.chain[this.chain.length - 1];
    }
    
    /**
   * Takes all the pending transactions, puts them in a Block and starts the
   * mining process. It also adds a transaction to send the mining reward to
   * the given address.
   *
   * @param {string} miningRewardAddress
   */
    minePendingTransactions(miningRewardAddress){
     const rewardTrans = new Transaction(null, miningRewardAddress, this.miningReward);
     this.pendingTransactions.push(rewardTrans);

     let block = new Block(Date.now(), this.pendingTransactions, this.getLatestBlock().hash);
     block.mineBlock(this.difficulty);
     this.chain.push(block);

     this.pendingTransactions= [];
    }

      /**
   * Add a new transaction to the list of pending transactions (to be added
   * next time the mining process starts). This verifies that the given
   * transaction is properly signed.
   *
   * @param {Transaction} transaction
   */
    addTransaction(transaction){
        if(!transaction.fromAddress || !transaction.toAddress){
            throw new Error('Transaction must include from & to addresses');
        }
        
        if(!transaction.isValid()){
            throw new Error('Cannot add invalid transaction to chain');
        }

        if (transaction.amount <= 0) {
            throw new Error('Transaction amount should be greater than 0');
          }

        //Checks that the amount sent is not greater than existing balance
        if (this.chain.length > 1 && (this.getBalanceOfAddress(transaction.fromAddress) < transaction.amount)){
          throw new Error('Not enough balance');
        }

        this.pendingTransactions.push(transaction);
    }

     /**
   * Returns the balance of a given wallet address.
   *
   * @param {string} address
   * @returns {number} The balance of the wallet
   */
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
   
     /**
   * Returns a list of all transactions that happened
   * to and from the given wallet address.
   *
   * @param  {string} address
   * @return {Transaction[]}
   */
    getAllWalletTransactions(address){
        const transactions= [];

        for(const block of this.chain){
            for (const trans of block.transactions){
                if(trans.fromAddress == address || trans.toAddress == address){
                    transactions.push(trans)
                }
            }
        }

        return transactions;
    }

     /**
   * Loops over all the blocks in the chain and verify if they are properly
   * linked together and nobody has tampered with the hashes. By checking
   * the blocks it also verifies the (signed) transactions inside of them.
   *
   * @returns {boolean}
   */
    isChainvalid(){
        const realGenesisBlock = JSON.stringify(this.createGenesisBlock());

        // Check if the Genesis block hasn't been tampered with by comparing
        // the output of createGenesisBlock with the first block on our chain
        if(realGenesisBlock !== JSON.stringify(this.chain[0])){
            return false;
        }
        
        // Check the remaining blocks on the chain to see if there hashes and
        // signatures are correct
        for(let i = 1; i < this.chain.length; i++){
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if(!currentBlock.hasValidTransactions()){
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
module.exports.Block = Block;
module.exports.Transaction = Transaction;
