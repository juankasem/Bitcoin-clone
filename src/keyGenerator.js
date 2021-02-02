const EC = require('elliptic').ec
const ec = new EC('secp256k1');

// Generate a new key pair and convert them to hex-strings
const key = ec.genKeyPair();


const publickey = key.getPublic('hex');
const privatekey = key.getPrivate('hex');
