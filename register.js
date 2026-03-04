import { BaseClient } from "@evex/linejs/base";
import { LINEStruct, Protocols } from "@evex/linejs/thrift";
import crypto from "node:crypto";
import https from "node:https";
import readline from "node:readline";
import nacl from "tweetnacl";
import xxhashInit from "xxhash-wasm";

// ============================================================
// Config — edit these values before running
// ============================================================
const UPDATE_NAME = true;
const DISPLAY_NAME = "moyashi_example";
const PASSWORD = "@moyashi0171R";
const DEVICE_MODEL = "SM-N950F";

// ============================================================
// Custom Errors
// ============================================================

class PaisError extends Error {
  constructor(method, code, message, raw) {
    super(`[${method}] Error ${code}: ${message}`);
    this.name = "PaisError";
    this.method = method;
    this.code = code;
    this.raw = raw;
  }
}

class LeGyTransportError extends Error {
  constructor(method, httpStatus, innerStatus, message) {
    super(`[${method}] Transport error (HTTP ${httpStatus}, x-lc=${innerStatus}): ${message}`);
    this.name = "LeGyTransportError";
    this.method = method;
    this.httpStatus = httpStatus;
    this.innerStatus = innerStatus;
  }
}

// ============================================================
// Helpers
// ============================================================

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (ans) => { rl.close(); resolve(ans); }));
}

function getSHA256Sum(...args) {
  const hash = crypto.createHash("sha256");
  for (const arg of args) hash.update(typeof arg === "string" ? Buffer.from(arg) : arg);
  return hash.digest();
}

function getIssuedAt() {
  return Buffer.from(`iat: ${Math.floor(Date.now() / 1000) * 60}\n`, "utf-8").toString("base64") + ".";
}

function getDigest(key, iat) {
  return crypto.createHmac("sha1", key).update(iat).digest("base64");
}

function createToken(authKey) {
  const [mid, ...rest] = authKey.split(":");
  const key = Buffer.from(rest.join(":"), "base64");
  const iat = getIssuedAt();
  return `${mid}:${iat}.${getDigest(key, iat)}`;
}

// ============================================================
// LEGY Encryption Layer
//
// LINE's LEGY proxy (gf.line.naver.jp/enc) wraps every
// registration request in AES-128-CBC encryption with a
// per-session ephemeral key transmitted via RSA-OAEP.
//
// Request:  encHeaders({x-lpqs:path}) + thriftBody → AES-CBC → + xxhash HMAC
// Response: AES-CBC decrypt → strip inner headers → thrift body
// ============================================================

const LINE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMC6HAYeMq4R59e2yRw6
W1OWT2t9aepiAp4fbSCXzRj7A29BOAFAvKlzAub4oxN13Nt8dbcB+ICAufyDnN5N
d3+vXgDxEXZ/sx2/wuFbC3B3evSNKR4hKcs80suRs8aL6EeWi+bAU2oYIc78Bbqh
Nzx0WCzZSJbMBFw1VlsU/HQ/XdiUufopl5QSa0S246XXmwJmmXRO0v7bNvrxaNV0
cbviGkOvTlBt1+RerIFHMTw3SwLDnCOolTz3CuE5V2OrPZCmC0nlmPRzwUfxoxxs
/6qFdpZNoORH/s5mQenSyqPkmH8TBOlHJWPH3eN1k6aZIlK5S54mcUb/oNRRq9wD
1wIDAQAB
-----END PUBLIC KEY-----`;

const LEGY_IV = Buffer.from([78, 9, 72, 62, 56, 245, 255, 114, 128, 18, 123, 158, 251, 92, 45, 51]);
const LEGY_LE = "7";
const LEGY_LCS_PREFIX = "0008";
const LEGY_GF_URL = "https://gf.line.naver.jp/enc";

// Per-session AES-128 key (generated once at startup)
const leGyAesKey = crypto.randomBytes(16);

// RSA-OAEP encrypt AES key → base64 → prepend prefix → x-lcs header
const xLcs = LEGY_LCS_PREFIX + crypto.publicEncrypt(
  { key: LINE_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
  leGyAesKey,
).toString("base64");

// LINE ANDROID app identity (version 26.2.0)
const X_LINE_APP = "ANDROID\t26.2.0\tAndroid OS\t15";
const USER_AGENT = "Line/26.2.0 A2342 15";

/** Serialize inner headers to LEGY binary format. */
function encHeaders(headers) {
  const keys = Object.keys(headers);
  const parts = [];
  parts.push(Buffer.from([(keys.length >> 8) & 0xff, keys.length & 0xff]));
  for (const k of keys) {
    const kBuf = Buffer.from(k, "ascii");
    const vBuf = Buffer.from(headers[k], "ascii");
    parts.push(Buffer.from([(kBuf.length >> 8) & 0xff, kBuf.length & 0xff]));
    parts.push(kBuf);
    parts.push(Buffer.from([(vBuf.length >> 8) & 0xff, vBuf.length & 0xff]));
    parts.push(vBuf);
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([
    Buffer.from([(body.length >> 8) & 0xff, body.length & 0xff]),
    body,
  ]);
}

/** Deserialize inner headers from decrypted LEGY response. */
function decHeaders(data) {
  let off = 0;
  const ri16 = () => { const v = (data[off] << 8) | data[off + 1]; off += 2; return v; };
  const dataLen = ri16() + 2;
  const count = ri16();
  const headers = {};
  for (let i = 0; i < count; i++) {
    const kl = ri16();
    const k = data.subarray(off, off + kl).toString("ascii"); off += kl;
    const vl = ri16();
    const v = data.subarray(off, off + vl).toString("ascii"); off += vl;
    headers[k] = v;
  }
  return { headers, data: data.subarray(dataLen) };
}

function pkcs7Pad(buf, bs) {
  const n = bs - (buf.length % bs);
  return Buffer.concat([buf, Buffer.alloc(n, n)]);
}

function pkcs7Unpad(buf) {
  const n = buf[buf.length - 1];
  return (n > 0 && n <= 16) ? buf.subarray(0, buf.length - n) : buf;
}

/** AES-128-CBC encrypt with PKCS7 padding. */
function leGyEncrypt(pt) {
  const c = crypto.createCipheriv("aes-128-cbc", leGyAesKey, LEGY_IV);
  c.setAutoPadding(true);
  return Buffer.concat([c.update(pt), c.final()]);
}

/** AES-128-CBC decrypt (mirrors CHRLINE decData). */
function leGyDecrypt(ct) {
  const padded = pkcs7Pad(ct, 16);
  const d = crypto.createDecipheriv("aes-128-cbc", leGyAesKey, LEGY_IV);
  d.setAutoPadding(false);
  const dec = Buffer.concat([d.update(padded), d.final()]);
  return pkcs7Unpad(dec.subarray(0, dec.length - 16));
}

/**
 * xxHash32-based HMAC for LEGY integrity verification.
 * outer = xxh32(opad ‖ bytes(xxh32(ipad ‖ data)))
 */
function leGyHmac(key, data, h) {
  const opad = Buffer.alloc(16);
  const ipad = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    opad[i] = 0x5c ^ key[i];
    ipad[i] = 0x36 ^ key[i];
  }
  const innerHex = (h.h32Raw(Buffer.concat([ipad, data]), 0) >>> 0)
    .toString(16).padStart(8, "0");
  const outerHex = (h.h32Raw(Buffer.concat([opad, Buffer.from(innerHex, "hex")]), 0) >>> 0)
    .toString(16).padStart(8, "0");
  return Buffer.from(outerHex, "hex");
}

// ============================================================
// Encrypted request transport
// ============================================================

const base = new BaseClient({ device: "ANDROID" });
let xxh = null;

/**
 * Send a thrift request through LEGY encryption.
 *
 * @param {Array}       args   Thrift args (nested arrays / LINEStruct)
 * @param {string}      method Thrift method name
 * @param {number}      ptype  3 = TBinary, 4 = TCompact
 * @param {string|null} token  Auth token (inner x-lt header)
 * @param {string}      path   API path (e.g. "/acct/pais/v1", "/S3")
 * @returns {*} Thrift response data (field 0)
 * @throws {PaisError}          on thrift-level exception
 * @throws {LeGyTransportError} on HTTP / LEGY-level failure
 */
async function leGyRequest(args, method, ptype = 3, token = null, path = "/acct/pais/v1") {
  if (!xxh) xxh = await xxhashInit();

  const protocol = Protocols[ptype];
  const body = base.thrift.writeThrift(args, method, protocol);

  const inner = token
    ? { "x-lt": token, "x-lpqs": path }
    : { "x-lpqs": path };

  const plaintext = Buffer.concat([encHeaders(inner), Buffer.from(body)]);

  const leInt = parseInt(LEGY_LE, 10);
  const fixBytes = (leInt & 4) === 4;
  let toEncrypt = fixBytes
    ? Buffer.concat([Buffer.from([leInt]), plaintext])
    : plaintext;

  let enc = leGyEncrypt(toEncrypt);
  if ((leInt & 2) === 2) {
    enc = Buffer.concat([enc, leGyHmac(leGyAesKey, enc, xxh)]);
  }

  const ptypeName = ptype === 3 ? "TBINARY" : "TCOMPACT";

  // Send via node:https to preserve tab characters in headers
  const { status, body: raw } = await new Promise((resolve, reject) => {
    const url = new URL(LEGY_GF_URL);
    const req = https.request({
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: "POST",
      headers: {
        "x-line-application": X_LINE_APP,
        "x-le": LEGY_LE,
        "x-lap": "5",
        "x-lpv": "1",
        "x-lcs": xLcs,
        "User-Agent": USER_AGENT,
        "content-type": `application/x-thrift; protocol=${ptypeName}`,
        "x-lal": "ja_JP",
        "x-lhm": "POST",
        "X-Line-Chrome-Version": "3.1.0",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate",
        "connection": "keep-alive",
        "Content-Length": enc.length,
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.on("error", reject);
    req.write(enc);
    req.end();
  });

  if (!raw.length) {
    throw new LeGyTransportError(method, status, null, "Empty response body");
  }

  // Decrypt (LEGY may encrypt even error responses)
  let dec;
  try {
    dec = leGyDecrypt(raw);
    if (fixBytes) dec = dec.subarray(1);
  } catch (e) {
    throw new LeGyTransportError(method, status, null, `Decryption failed: ${e.message}`);
  }

  const { headers: innerHeaders, data: thriftData } = decHeaders(dec);

  // Check LEGY inner status
  const innerStatus = innerHeaders["x-lc"];
  if (status !== 200 || (innerStatus && innerStatus !== "200")) {
    throw new LeGyTransportError(method, status, innerStatus,
      `Server rejected request (HTTP ${status}, x-lc=${innerStatus ?? "n/a"})`);
  }

  // Parse thrift response
  const parsed = base.thrift.readThrift(new Uint8Array(thriftData), protocol);

  // Thrift field 1 = exception
  if (parsed.data[1]) {
    const ex = parsed.data[1];
    throw new PaisError(method, ex[1], ex[2], ex);
  }

  return parsed.data[0];
}

/** PAIS registration request shorthand (TBinary, unauthenticated). */
const paisRequest = (args, name) => leGyRequest(args, name, 3, null, "/acct/pais/v1");

// ============================================================
// Key material for ECDH (generated once per run)
// ============================================================

const uuid = crypto.randomUUID().replace(/-/g, "");
const secretKey = nacl.randomBytes(32);
const keyPair = nacl.box.keyPair.fromSecretKey(secretKey);
const regNonce = crypto.randomBytes(16);

// ============================================================
// Registration Flow
// ============================================================

async function main() {
  // 1. Open registration session
  console.log("Step 1/11: Opening session...");
  const session = await paisRequest(
    LINEStruct.openSession_args({ request: { metaData: {} } }),
    "openSession",
  );
  const authSessionId = typeof session === "string" ? session : session[1];
  console.log(`  Session ID: ${authSessionId}`);

  // 2. Get country info
  console.log("Step 2/11: Getting country info...");
  const country = await paisRequest(
    LINEStruct.getCountryInfo_args({ authSessionId }),
    "getCountryInfo",
  );
  console.log(`  Country: ${country[1]}, GDPR restricted: ${country[2]}`);

  // 3. User input: phone number & region
  const phone = await ask("Phone number (e.g. 09012345678): ");
  const region = await ask("Region code (e.g. JP, TH, TW): ");

  // 4. Get phone verification methods
  console.log("Step 4/11: Getting verification methods...");
  const pv = await paisRequest(
    LINEStruct.getPhoneVerifMethodV2_args({
      request: {
        authSessionId,
        device: { udid: uuid, deviceModel: DEVICE_MODEL },
        userPhoneNumber: { phoneNumber: phone, countryCode: region },
      },
    }),
    "getPhoneVerifMethodV2",
  );
  const formattedPhone = pv[3];
  const verifMethods = pv[1];
  console.log(`  Formatted: ${formattedPhone}  Methods: [${verifMethods}]`);

  // 5. Request PIN code
  console.log("Step 5/11: Sending PIN code...");
  const sendPin = await paisRequest(
    LINEStruct.requestToSendPhonePinCode_args({
      request: {
        authSessionId,
        userPhoneNumber: { phoneNumber: formattedPhone, countryCode: region },
        verifMethod: verifMethods[0],
      },
    }),
    "requestToSendPhonePinCode",
  );
  console.log(`  PIN sent. Available methods: [${sendPin[1]}]`);

  // 6. Verify PIN code
  const pin = await ask("PIN code: ");
  console.log("Step 6/11: Verifying PIN...");
  const verify = await paisRequest(
    LINEStruct.verifyPhonePinCode_args({
      request: {
        authSessionId,
        userPhoneNumber: { phoneNumber: phone, countryCode: region },
        pinCode: pin,
      },
    }),
    "verifyPhonePinCode",
  );
  if (verify[11]) {
    console.log(`  Existing account found: "${verify[11][1]}"`);
  }
  console.log(`  accountExist=${verify[1]}, sameUdidExist=${verify[2]}, allowToRegister=${verify[3]}`);

  // 7. Validate profile (display name)
  console.log("Step 7/11: Validating profile...");
  await paisRequest(
    LINEStruct.validateProfile_args({ authSessionId, displayName: DISPLAY_NAME }),
    "validateProfile",
  );
  console.log(`  Profile OK: "${DISPLAY_NAME}"`);

  // 8. Exchange encryption keys (Curve25519 ECDH)
  console.log("Step 8/11: Exchanging encryption keys...");
  const b64Pub = Buffer.from(keyPair.publicKey).toString("base64");
  const b64Nonce = Buffer.from(regNonce).toString("base64");
  const exKey = await paisRequest(
    [
      [11, 1, authSessionId],
      [12, 2, [
        [8, 1, 1],
        [11, 2, b64Pub],
        [11, 3, b64Nonce],
      ]],
    ],
    "exchangeEncryptionKey",
  );

  const srvKey = Buffer.from(exKey[1], "base64");
  const srvNonce = Buffer.from(exKey[2], "base64");
  console.log("  Key exchange complete.");

  // 9. Derive shared secret & encrypt password
  console.log("Step 9/11: Encrypting password...");
  const { sharedKey } = await import("curve25519-js");
  const shared = sharedKey(secretKey, srvKey);

  const masterKey = getSHA256Sum(Buffer.from("master_key"), Buffer.from(shared), regNonce, srvNonce);
  const aesKey = getSHA256Sum(Buffer.from("aes_key"), masterKey);
  const hmacKey = getSHA256Sum(Buffer.from("hmac_key"), masterKey);

  const pwCipher = crypto.createCipheriv("aes-128-cbc", aesKey.subarray(0, 16), aesKey.subarray(16, 32));
  pwCipher.setAutoPadding(true);
  const pwEnc = Buffer.concat([pwCipher.update(PASSWORD, "utf-8"), pwCipher.final()]);
  const pwHmac = crypto.createHmac("sha256", hmacKey).update(pwEnc).digest();
  const encPwd = Buffer.concat([pwEnc, pwHmac]).toString("base64");
  console.log("  Password encrypted.");

  // 10. Set password
  console.log("Step 10/11: Setting password...");
  await paisRequest(
    [
      [11, 1, authSessionId],
      [12, 2, [
        [8, 1, 1],
        [11, 2, encPwd],
      ]],
    ],
    "setPassword",
  );
  console.log("  Password set.");

  // 11. Register account
  console.log("Step 11/11: Registering account...");
  const reg = await paisRequest(
    LINEStruct.registerPrimaryUsingPhoneWithTokenV3_args({ authSessionId }),
    "registerPrimaryUsingPhoneWithTokenV3",
  );

  const authKey = reg[1];
  const tokenResult = reg[2];
  const mid = reg[3];
  const primaryToken = createToken(authKey);

  console.log("\n===== Registration Complete =====");
  console.log(`MID:            ${mid}`);
  console.log(`AuthKey:        ${authKey}`);
  console.log(`PrimaryToken:   ${primaryToken}`);
  console.log(`AccessTokenV3:  ${tokenResult[1]}`);
  console.log(`RefreshToken:   ${tokenResult[2]}`);
  console.log(`DurationSec:    ${tokenResult[3]}`);
  console.log(`LoginSessionId: ${tokenResult[5]}`);
  console.log("=================================\n");

  // Optional: update display name via TalkService
  if (UPDATE_NAME) {
    console.log(`Updating display name to "${DISPLAY_NAME}"...`);
    try {
      await leGyRequest(
        [[8, 1, 0], [8, 2, 2], [11, 3, DISPLAY_NAME]],
        "updateProfileAttribute",
        4,              // TCompact for TalkService
        primaryToken,   // auth via inner x-lt header
        "/S3",          // TalkService endpoint (v1 token)
      );
      console.log("  Display name updated.");
    } catch (e) {
      console.error(`  Failed to update display name: ${e.message}`);
    }
  }

  console.log("Done!");
}

main().catch((err) => {
  if (err instanceof PaisError) {
    console.error(`\n[PAIS Error] ${err.method}: code=${err.code}`);
    console.error(`  ${err.message}`);
    if (err.code === 5 && err.raw?.[3]) {
      console.error("  Human verification may be required.");
      console.error(`  Metadata: ${JSON.stringify(err.raw[3])}`);
    }
  } else if (err instanceof LeGyTransportError) {
    console.error(`\n[Transport Error] ${err.message}`);
  } else {
    console.error("\n[Unexpected Error]", err);
  }
  process.exit(1);
});
