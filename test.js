const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
const createHash = require("crypto").createHash;
const bufferEqual = require("buffer-equal");
const eccrypto = require("./");

const { expect } = chai;
chai.use(chaiAsPromised);

const msg = createHash("sha256").update("test").digest();
const otherMsg = createHash("sha256").update("test2").digest();
const shortMsg = createHash("sha1").update("test").digest();

const privateKey = Buffer.alloc(32);
privateKey.fill(1);
const publicKey = eccrypto.getPublic(privateKey);
const publicKeyCompressed = eccrypto.getPublicCompressed(privateKey);

const privateKeyA = Buffer.alloc(32);
privateKeyA.fill(2);
const publicKeyA = eccrypto.getPublic(privateKeyA);
const publicKeyACompressed = eccrypto.getPublicCompressed(privateKeyA);

const privateKeyB = Buffer.alloc(32);
privateKeyB.fill(3);
const publicKeyB = eccrypto.getPublic(privateKeyB);
const publicKeyBCompressed = eccrypto.getPublicCompressed(privateKeyB);

describe("Key conversion", () => {
  it("should allow to convert private key to public", () => {
    expect(Buffer.isBuffer(publicKey)).to.be.true;
    expect(publicKey.toString("hex")).to.equal(
      "041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1"
    );
  });

  it("should allow to convert private key to compressed public", () => {
    expect(Buffer.isBuffer(publicKeyCompressed)).to.be.true;
    expect(publicKeyCompressed.toString("hex")).to.equal(
      "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
    );
  });

  it("should throw on invalid private key", () => {
    expect(eccrypto.getPublic.bind(null, Buffer.from("00", "hex"))).to.throw(
      Error
    );
    expect(eccrypto.getPublic.bind(null, Buffer.from("test"))).to.throw(Error);
  });
});

describe("ECDSA", () => {
  it("should allow to sign and verify message", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).to.be.true;
    expect(sig.toString("hex")).to.equal(
      "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
    );
    await eccrypto.verify(publicKey, msg, sig);
  });

  it("should allow to sign and verify message using a compressed public key", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).to.be.true;
    expect(sig.toString("hex")).to.equal(
      "3044022078c15897a34de6566a0d396fdef660698c59fef56d34ee36bef14ad89ee0f6f8022016e02e8b7285d93feafafbe745702f142973a77d5c2fa6293596357e17b3b47c"
    );
    await eccrypto.verify(publicKeyCompressed, msg, sig);
  });

  it("shouldn't verify incorrect signature", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).to.be.true;
    await expect(eccrypto.verify(publicKey, otherMsg, sig)).to.eventually.be
      .rejected;
  });

  it("should reject promise on invalid key when signing", async () => {
    const k4 = Buffer.from("test");
    const k192 = Buffer.from(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "hex"
    );
    const k384 = Buffer.from(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "hex"
    );

    await expect(eccrypto.sign(k4, msg)).to.eventually.be.rejected;
    await expect(eccrypto.sign(k192, msg)).to.eventually.be.rejected;
    await expect(eccrypto.sign(k384, msg)).to.eventually.be.rejected;
  });

  it("should reject promise on invalid key when verifying", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).to.be.true;

    await expect(eccrypto.verify(Buffer.from("test"), msg, sig)).to.eventually
      .be.rejected;

    const badKey = Buffer.alloc(65);
    publicKey.copy(badKey);
    badKey[0] ^= 1;

    await expect(eccrypto.verify(badKey, msg, sig)).to.eventually.be.rejected;
  });

  it("should reject promise on invalid sig when verifying", async () => {
    const sig = await eccrypto.sign(privateKey, msg);
    expect(Buffer.isBuffer(sig)).to.be.true;

    sig[0] ^= 1;

    await expect(eccrypto.verify(publicKey, msg, sig)).to.eventually.be
      .rejected;
  });

  it("should allow to sign and verify messages less than 32 bytes", async () => {
    const sig = await eccrypto.sign(privateKey, shortMsg);
    expect(Buffer.isBuffer(sig)).to.be.true;
    expect(sig.toString("hex")).to.equal(
      "304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa"
    );
    await eccrypto.verify(publicKey, shortMsg, sig);
  });

  it("shouldn't sign and verify messages longer than 32 bytes", async () => {
    const longMsg = Buffer.alloc(40);
    const someSig = Buffer.from(
      "304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa",
      "hex"
    );

    await expect(eccrypto.sign(privateKey, longMsg)).to.eventually.be.rejected;
    await expect(
      eccrypto.verify(privateKey, longMsg, someSig)
    ).to.eventually.be.rejectedWith("Message is too long");
  });

  it("shouldn't sign and verify empty messages", async () => {
    const emptyMsg = Buffer.alloc(0);
    const someSig = Buffer.from(
      "304402204737396b697e5a3400e3aedd203d8be89879f97708647252bd0c17752ff4c8f302201d52ef234de82ce0719679fa220334c83b80e21b8505a781d32d94a27d9310aa",
      "hex"
    );
    await expect(eccrypto.sign(privateKey, emptyMsg)).to.eventually.be.rejected;
    await expect(
      eccrypto.verify(publicKey, emptyMsg, someSig)
    ).to.eventually.be.rejectedWith("Message should not be empty");
  });
});

describe("ECDH", () => {
  it("should derive shared secret from privkey A and pubkey B", async () => {
    const Px = await eccrypto.derive(privateKeyA, publicKeyB);

    expect(Buffer.isBuffer(Px)).to.be.true;
    expect(Px.length).to.equal(32);
    expect(Px.toString("hex")).to.equal(
      "aca78f27d5f23b2e7254a0bb8df128e7c0f922d47ccac72814501e07b7291886"
    );

    const Px2 = await eccrypto.derive(privateKeyB, publicKeyA);

    expect(Buffer.isBuffer(Px2)).to.be.true;
    expect(Px2.length).to.equal(32);
    expect(bufferEqual(Px, Px2)).to.be.true;
  });

  it("should derive shared secret from  privkey A and compressed pubkey B", async () => {
    const Px = await eccrypto.derive(privateKeyA, publicKeyBCompressed);

    expect(Buffer.isBuffer(Px)).to.be.true;
    expect(Px.length).to.equal(32);
    expect(Px.toString("hex")).to.equal(
      "aca78f27d5f23b2e7254a0bb8df128e7c0f922d47ccac72814501e07b7291886"
    );

    const Px2 = await eccrypto.derive(privateKeyB, publicKeyA);

    expect(Buffer.isBuffer(Px2)).to.be.true;
    expect(Px2.length).to.equal(32);
    expect(bufferEqual(Px, Px2)).to.be.true;
  });

  it("should reject promise on bad keys", async () => {
    await expect(eccrypto.derive(Buffer.from("test"), publicKeyB)).to.eventually
      .be.rejected;
    await expect(eccrypto.derive(publicKeyB, publicKeyB)).to.eventually.be
      .rejected;
    await expect(eccrypto.derive(privateKeyA, privateKeyA)).to.eventually.be
      .rejected;
    await expect(eccrypto.derive(privateKeyB, Buffer.from("test"))).to
      .eventually.be.rejected;
  });

  it("should reject promise on bad arguments", async () => {
    await expect(eccrypto.derive({}, {})).to.eventually.be.rejectedWith(
      /Bad private key/i
    );
  });
});

describe("ECIES", () => {
  const ephemPrivateKey = Buffer.alloc(32);
  ephemPrivateKey.fill(4);
  const ephemPublicKey = eccrypto.getPublic(ephemPrivateKey);
  const iv = Buffer.alloc(16);
  iv.fill(5);
  const ciphertext = Buffer.from("bbf3f0e7486b552b0e2ba9c4ca8c4579", "hex");
  const mac = Buffer.from(
    "dbb14a9b53dbd6b763dba24dc99520f570cdf8095a8571db4bf501b535fda1ed",
    "hex"
  );
  const encOpts = { ephemPrivateKey: ephemPrivateKey, iv: iv };
  const decOpts = {
    iv: iv,
    ephemPublicKey: ephemPublicKey,
    ciphertext: ciphertext,
    mac: mac,
  };

  it("should encrypt", async () => {
    const enc = await eccrypto.encrypt(
      publicKeyB,
      Buffer.from("test"),
      encOpts
    );

    expect(bufferEqual(enc.iv, iv)).to.be.true;
    expect(bufferEqual(enc.ephemPublicKey, ephemPublicKey)).to.be.true;
    expect(bufferEqual(enc.ciphertext, ciphertext)).to.be.true;
    expect(bufferEqual(enc.mac, mac)).to.be.true;
  });

  it("should decrypt", async () => {
    const msg = await eccrypto.decrypt(privateKeyB, decOpts);
    expect(msg.toString()).to.equal("test");
  });

  it("should encrypt and decrypt", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("to a"));
    const msg = await eccrypto.decrypt(privateKeyA, enc);
    expect(msg.toString()).to.equal("to a");
  });

  it("should encrypt and decrypt with message size > 15", async () => {
    const enc = await eccrypto.encrypt(
      publicKeyA,
      Buffer.from("message size that is greater than 15 for sure =)")
    );
    const msg = await eccrypto.decrypt(privateKeyA, enc);
    expect(msg.toString()).to.equal(
      "message size that is greater than 15 for sure =)"
    );
  });

  it("should encrypt with compressed public key", async () => {
    const enc = await eccrypto.encrypt(
      publicKeyBCompressed,
      Buffer.from("test"),
      encOpts
    );
    expect(bufferEqual(enc.iv, iv)).to.be.true;
    expect(bufferEqual(enc.ephemPublicKey, ephemPublicKey)).to.be.true;
    expect(bufferEqual(enc.ciphertext, ciphertext)).to.be.true;
    expect(bufferEqual(enc.mac, mac)).to.be.true;
  });

  it("should encrypt and decrypt with compressed public key", async () => {
    const enc = await eccrypto.encrypt(
      publicKeyACompressed,
      Buffer.from("to a")
    );
    const msg = await eccrypto.decrypt(privateKeyA, enc);
    expect(msg.toString()).to.equal("to a");
  });

  it("should encrypt and decrypt with generated private and public key", async () => {
    const privateKey = eccrypto.generatePrivate();
    const publicKey = eccrypto.getPublic(privateKey);
    const enc = await eccrypto.encrypt(
      publicKey,
      Buffer.from("generated private key")
    );
    const msg = await eccrypto.decrypt(privateKey, enc);
    expect(msg.toString()).to.equal("generated private key");
  });

  it("should reject promise on bad private key when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"));
    await expect(eccrypto.decrypt(privateKeyB, enc)).to.eventually.be.rejected;
  });

  it("should reject promise on bad IV when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"));

    enc.iv[0] ^= 1;

    await expect(eccrypto.decrypt(privateKeyA, enc)).to.eventually.be.rejected;
  });

  it("should reject promise on bad R when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"));

    enc.ephemPublicKey[0] ^= 1;

    await expect(eccrypto.decrypt(privateKeyA, enc)).to.eventually.be.rejected;
  });

  it("should reject promise on bad ciphertext when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"));

    enc.ciphertext[0] ^= 1;

    await expect(eccrypto.decrypt(privateKeyA, enc)).to.eventually.be.rejected;
  });

  it("should reject promise on bad MAC when decrypting", async () => {
    const enc = await eccrypto.encrypt(publicKeyA, Buffer.from("test"));
    const origMac = enc.mac;

    enc.mac = mac.subarray(1);

    await expect(eccrypto.decrypt(privateKeyA, enc)).to.eventually.be.rejected;

    enc.mac = origMac;
    enc.mac[10] ^= 1;

    await expect(eccrypto.decrypt(privateKeyA, enc)).to.eventually.be.rejected;
  });
});
