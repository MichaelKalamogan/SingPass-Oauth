const jose = require("node-jose");
const crypto = require("crypto");

async function generateKey() {
  let key = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });
  let cryptoKey = await jose.JWK.asKey(key.privateKey, "pem");
  console.log(key.privateKey);
  return cryptoKey;
}

async function generateJwks() {
  //Creating Signing Key
  let signingKey = await generateKey();
  let publicSigningKeyJSON = signingKey.toJSON();
  //Creating Encryption Key
  let encryptionKey = await generateKey();
  let publicEncryptionKeyJSON = encryptionKey.toJSON();
  let jwks = {
    keys: [
      {
        ...publicSigningKeyJSON,
        ...{ use: "sig" },
        ...{ crv: "P-256" },
        ...{ alg: "ES256" },
      },
      {
        ...publicEncryptionKeyJSON,
        ...{ use: "enc" },
        ...{ crv: "P-256" },
        ...{ alg: "ECDH-ES+A256KW" },
      },
    ],
  };
  return jwks;
}

module.exports = { generateJwks };
