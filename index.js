const express = require("express");
const bodyParser = require("body-parser");
const { SignJWT } = require("jose/jwt/sign");
const { parseJwk } = require("jose/jwk/parse");
const { jwtVerify } = require("jose/jwt/verify");
const crypto = require("crypto");
const uuid = require("uuid");
const axios = require("axios").default;
const qs = require("qs");
const dotenv = require("dotenv");
const PORT = process.env.PORT || 5000;
require("dotenv").config();
var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(function (req, res, next) {
  req.webtaskContext = {};
  const result = process.env;

  if (result.error) {
    throw result.error;
  }
  req.webtaskContext.data = result.parsed;

  next();
});

app.get("/ping", (req, res) => {
  res.send("pong");
});
app.get("/authorize", (req, res) => {
  const context = req.webtaskContext;
  if (!req.query.client_id) {
    return res.send(400, "missing client_id");
  }
  if (process.env.AUTH0_CLIENT_ID !== req.query.client_id) {
    return res.send(401, "invalid client_id");
  }
  var url = `https://${process.env.AUTH0_CUSTOM_DOMAIN}${req.url}&ndi_state=${req.query.state}&ndi_nonce=${req.query.code_challenge}&singpass=true`;
  res.redirect(url);
});

/**
 * /auth is for redirect based flow which is the recommended method now
 * note that we probably don't need a new endpoint for redirection since it can all happen with Auth0's native upstream idp parameter mapping.
 */
app.get("/auth", (req, res) => {
  if (!req.query.client_id) {
    return res.send(400, "missing client_id");
  }
  if (process.env.AUTH0_CLIENT_ID !== req.query.client_id) {
    return res.send(401, "invalid client_id");
  }

  // Parse the URL
  const urlObj = new URL(req.url, "https://id.singpass.gov.sg");

  // Remove the client_id parameter
  urlObj.searchParams.delete("client_id");

  // Reconstruct the URL without the client_id parameter
  const modifiedUrl = urlObj.toString();

  const url = `${modifiedUrl}&client_id=${process.env.SINGPASS_CLIENT_ID}&state=${req.query.state}&nonce=${req.query.code_challenge}`;
  console.log(url);
  res.redirect(url);
});

app.post("/token", async function (req, res) {
  try {
    const context = req.webtaskContext;
    const { client_id, client_secret, code, code_verifier, redirect_uri } =
      req.body;
    if (!client_id || !client_secret) {
      return res.send(400, "missing client_id / client_secret");
    }
    if (
      process.env.AUTH0_CLIENT_ID === client_id &&
      process.env.AUTH0_CLIENT_SECRET === client_secret
    ) {
      const client_assertion = await generatePrivateKeyJWT(context.data);
      var options = {
        method: "POST",
        url: `https://id.singpass.gov.sg/token`,
        headers: { "content-type": "application/x-www-form-urlencoded" },
        data: qs.stringify({
          grant_type: "authorization_code",
          client_id: process.env.SINGPASS_CLIENT_ID,
          client_assertion_type:
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: client_assertion,
          code: code,
          redirect_uri: redirect_uri,
        }),
      };
      try {
        const response = await axios.request(options);
        const { id_token } = response.data;
        const publicKey = await loadPublicKey(context.data);
        const code_v = new TextEncoder().encode(code_verifier);
        const code_v_s256 = crypto
          .createHash("sha256")
          .update(code_v)
          .digest("base64")
          .replace(/\//g, "_")
          .replace(/\+/g, "-")
          .replace(/=/g, "");
        console.log(`nonce expected: ${code_v_s256}`);
        const { payload, protectedHeader } = await jwtVerify(
          id_token,
          publicKey,
          {
            issuer: context.data.ISSUER,
            audience: context.data.CLIENT_ID,
          },
        );
        if (payload.nonce !== code_v_s256) {
          return res.send(400, "nonce mismatch");
        } else {
          response.data.payload = payload;
          return res.status(200).send(response.data);
        }
      } catch (error) {
        if (error.response) {
          return res.status(error.response.status).send(error.response.data);
        } else {
          // Something happened in setting up the request that triggered an Error
          console.log("Error", error.message);
          return res.status(500).send(error);
        }
      }
    } else {
      return res.send(401, "invalid request");
    }
  } catch (error) {
    console.log(error);
    res.status(500).json(error.message);
  }
});

app.post("/verify", async function (req, res) {
  try {
    const { id_token } = response.body;
    if (!id_token) {
      return res.status(400).send("ID_TOKEN required");
    }
    const publicKey = await loadPublicKey(context.data);
    const { payload, protectedHeader } = await jwtVerify(id_token, publicKey, {
      issuer: context.data.ISSUER,
      audience: context.data.CLIENT_ID,
    });
    return res.status(200).send(payload);
  } catch (error) {
    if (error.response) {
      return res.status(error.response.status).send(error.response.data);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.log("Error", error.message);
      return res.status(500).send(error);
    }
  }
});

async function loadPrivateKey(config) {
  try {
    const response = await axios.get(process.env.RELYING_PARTY_JWKS_ENDPOINT);
    const { keys } = response.data;
    keys[0].d = process.env.RELYING_PARTY_PRIVATE_KEY;
    return await parseJwk(keys[0], process.env.SINGPASS_SIGNING_ALG);
  } catch (e) {
    return e;
  }
}

async function loadPublicKey(config) {
  try {
    const response = await axios.get(
      `${process.env.SINGPASS_ENVIRONMENT}/.well-known/keys`,
    );
    return await parseJwk(
      response.data.keys[0],
      process.env.SINGPASS_SIGNING_ALG,
    );
  } catch (e) {
    return e;
  }
}

async function generatePrivateKeyJWT(config) {
  //const privateKeyPEM = crypto.createPrivateKey(config.PRIVATE_KEY.replace(/\\n/gm, '\n'));
  const key = await loadPrivateKey(config);
  const jwt = await new SignJWT({})
    .setProtectedHeader({
      alg: process.env.SINGPASS_SIGNING_ALG,
      kid: process.env.RELYING_PARTY_KID,
      typ: "JWT",
    })
    .setIssuedAt()
    .setIssuer(process.env.SINGPASS_CLIENT_ID)
    .setSubject(process.env.SINGPASS_CLIENT_ID)
    .setAudience(process.env.SINGPASS_ENVIRONMENT)
    .setExpirationTime("2m") // NDI will not accept tokens with an exp longer than 2 minutes since iat.
    .setJti(uuid.v4())
    .sign(key);
  return jwt;
}

app.listen(PORT, () => console.log(`Listening on ${PORT}`));
