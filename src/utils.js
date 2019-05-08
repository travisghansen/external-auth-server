const crypto = require("crypto");
const queryString = require("query-string");
const URI = require("uri-js");
const uuidv4 = require("uuid/v4");

const algorithm = "aes-256-cbc";

function exit_failure(message = "", code = 1) {
  if (message) {
    console.log(message);
  }
  process.exit(code);
}

function md5(text) {
  return crypto
    .createHash("md5")
    .update(text)
    .digest("hex");
}

function encrypt(salt, text, encoding = "base64") {
  try {
    var cipher = crypto.createCipher(algorithm, salt);
    var encrypted = Buffer.concat([
      cipher.update(Buffer.from(text, "utf8")),
      cipher.final()
    ]);

    return encrypted.toString(encoding);
  } catch (exception) {
    throw new Error(exception.message);
  }
}

function decrypt(salt, text, encoding = "base64") {
  try {
    var decipher = crypto.createDecipher(algorithm, salt);
    var decrypted = Buffer.concat([
      decipher.update(Buffer.from(text, encoding)),
      decipher.final()
    ]);
    return decrypted.toString("utf8");
  } catch (exception) {
    throw new Error(exception.message);
  }
}

function base64_encode(text) {
  return Buffer.from(text, "utf8").toString("base64");
}

function base64_decode(text) {
  return Buffer.from(text, "base64").toString("utf8");
}

function generate_session_id() {
  return uuidv4();
}

function generate_csrf_id() {
  return uuidv4();
}

function get_parent_request_info(req) {
  const info = {};
  info.uri = get_parent_request_uri(req);
  info.parsedUri = URI.parse(info.uri);
  info.parsedQuery = JSON.parse(
    JSON.stringify(queryString.parse(info.parsedUri.query))
  );
  // not used currently but could be used for verify process
  info.method = req.headers["x-forwarded-method"];
  return info;
}

function get_parent_request_uri(req) {
  const originalRequestURI =
    req.headers["x-forwarded-proto"] +
    "://" +
    req.headers["x-forwarded-host"] +
    req.headers["x-forwarded-uri"];

  //x-forwarded-port
  /**
   * X-Forwarded-For: client, proxy1, proxy2
   * left-most being the original clien
   *
   * X-Forwarded-Proto: https (should only include 1 item)
   *
   * # Microsoft
   * Front-End-Https: on
   * X-Forwarded-Protocol: https
   * X-Forwarded-Ssl: on
   * X-Url-Scheme: https
   */

  return originalRequestURI;
}

function parse_basic_authorization_header(value) {
  let parts;
  const creds = {};
  parts = value.split(" ");

  creds.strategy = parts[0];

  parts = base64_decode(parts[1]);
  creds.username = parts.split(":")[0];
  creds.password = parts
    .split(":")
    .slice(1)
    .join(":");

  return creds;
}

function authorization_scheme_is(value, scheme) {
  const value_strategy = value.split(" ")[0];
  if (value_strategy.toLowerCase() == scheme.toLowerCase()) {
    return true;
  }

  return false;
}

function redirect_http_code(req) {
  return req.query.redirect_http_code ? req.query.redirect_http_code : 302;
}

function validateConfigToken(configToken) {}

module.exports = {
  exit_failure,
  encrypt,
  decrypt,
  md5,
  base64_encode,
  base64_decode,
  generate_session_id,
  generate_csrf_id,
  get_parent_request_uri,
  get_parent_request_info,
  validateConfigToken,
  parse_basic_authorization_header,
  authorization_scheme_is,
  redirect_http_code
};
