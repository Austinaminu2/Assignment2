const crypto = require('crypto');
const { keccak256 } = require('js-sha3');

// Generate ECDSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'secp256k1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

console.log("Private Key:", privateKey)
console.log("Public Key:", publicKey)

// Extract uncompressed public key (last 65 bytes, starts with 0x04)
const uncompressedPubKey = publicKey.slice(-65);

// Remove prefix byte (0x04)
const pubKeyNoPrefix = uncompressedPubKey.slice(1);

// Hash with Keccak-256 and take last 20 bytes (Ethereum address)
const address = '0x' + keccak256(pubKeyNoPrefix).slice(-40);

console.log('Ethereum Address:', address);

// Step 1: Hash the message
const message = 'My name is Austin Aminu';
const hash = crypto.createHash('sha256').update(message).digest();

console.log('Message Hash (SHA-256):', hash.toString('hex'));

// Step 2: Sign the hash using the private key
const signature = crypto.sign(null, hash, privateKey); // null = use digest algorithm from hash
console.log('Signature (hex):', signature.toString('hex'));

const verify = crypto.createVerify('SHA256');
verify.update(message);
verify.end();



const isValid = crypto.verify(null, hash, publicKey, signature);
console.log('Signature valid?', isValid);
