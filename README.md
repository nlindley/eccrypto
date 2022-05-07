# eccrypto

JavaScript Elliptic curve cryptography library for Node.js.

## Implementation details

- Use Node.js crypto module/library bindings where possible
- Promise-driven API
- Only secp256k1 curve, only SHA-512 (KDF), HMAC-SHA-256 (HMAC) and AES-256-CBC for ECIES
- Compressed key support

### Native crypto API limitations

#### crypto

ECDH only works in Node 0.11+ (see https://github.com/joyent/node/pull/5854), ECDSA only supports keys in PEM format (see https://github.com/joyent/node/issues/6904) and ECIES is not supported at all.

## Usage

### ECDSA

```js
var crypto = require("crypto");
var eccrypto = require("@nlindley/eccrypto");

// A new random 32-byte private key.
var privateKey = eccrypto.generatePrivate();
// Corresponding uncompressed (65-byte) public key.
var publicKey = eccrypto.getPublic(privateKey);

var str = "message to sign";
// Always hash you message to sign!
var msg = crypto.createHash("sha256").update(str).digest();

eccrypto.sign(privateKey, msg).then(function (sig) {
  console.log("Signature in DER format:", sig);
  eccrypto
    .verify(publicKey, msg, sig)
    .then(function () {
      console.log("Signature is OK");
    })
    .catch(function () {
      console.log("Signature is BAD");
    });
});
```

### ECDH

```js
var eccrypto = require("@nlindley/eccrypto");

var privateKeyA = eccrypto.generatePrivate();
var publicKeyA = eccrypto.getPublic(privateKeyA);
var privateKeyB = eccrypto.generatePrivate();
var publicKeyB = eccrypto.getPublic(privateKeyB);

eccrypto.derive(privateKeyA, publicKeyB).then(function (sharedKey1) {
  eccrypto.derive(privateKeyB, publicKeyA).then(function (sharedKey2) {
    console.log("Both shared keys are equal:", sharedKey1, sharedKey2);
  });
});
```

### ECIES

```js
var eccrypto = require("@nlindley/eccrypto");

var privateKeyA = eccrypto.generatePrivate();
var publicKeyA = eccrypto.getPublic(privateKeyA);
var privateKeyB = eccrypto.generatePrivate();
var publicKeyB = eccrypto.getPublic(privateKeyB);

// Encrypting the message for B.
eccrypto
  .encrypt(publicKeyB, Buffer.from("msg to b"))
  .then(function (encrypted) {
    // B decrypting the message.
    eccrypto.decrypt(privateKeyB, encrypted).then(function (plaintext) {
      console.log("Message to part B:", plaintext.toString());
    });
  });

// Encrypting the message for A.
eccrypto
  .encrypt(publicKeyA, Buffer.from("msg to a"))
  .then(function (encrypted) {
    // A decrypting the message.
    eccrypto.decrypt(privateKeyA, encrypted).then(function (plaintext) {
      console.log("Message to part A:", plaintext.toString());
    });
  });
```

## License

eccrypto - JavaScript Elliptic curve cryptography library

Written in 2014-2015 by Kagami Hiiragi <kagami@genshiken.org>. Forked in 2022 by Nicholas Lindley <me@thisoneplace.com>.

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
