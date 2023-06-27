const crypto = require("crypto");
const Handlebars = require("handlebars");
const jsonata = require("jsonata");
const jp = require("jsonpath");
const jq = require("node-jq");
const jwksClient = require("jwks-rsa");
const queryString = require("query-string");
const { retrieveSigningKeys } = require("jwks-rsa/src/utils");
const URI = require("uri-js");
const { v4: uuidv4 } = require("uuid");

// https://crypto.stackexchange.com/questions/2310/what-is-the-difference-between-cbc-and-gcm-mode
const CRYPTO_ALGORITHM = "aes-256-cbc";
const CRYPTO_IV_LENGTH = 16;
const CRYPTO_KEY_LENGTH = 32;

/**
 * Typicially iv is not really a secret, and really is not here either. The
 * purpose of iv is to prevent attacks where attackers have 2+ of the same
 * input data where the ciphertext is the equal. However, the nature of the
 * encrypted data as used by eas is such that, generally speaking, a time
 * componenet is part of the input (ie: jwts, etc, etc), making the chance of
 * producing exact same encrypted data almost nil. For example, if you use
 * the same `config_token` input data twice to create/update the jwt, you will,
 * with near certainty, have 2 completely different ciphertexts.
 *
 * Best practice callls for using unique iv per-encryption process and then
 * storing the iv along with the ciphertext. With the generally stateless
 * nature of eas the challenges associated with storing the iv combined with:
 *
 * 1. encrypted data generally is never the same (due to iat, nbr, etc, etc)
 * 2. very little data is stored centrally (although some may be if using server-side tokens)
 * 3. the ephemeral nature of the remaining use-cases (`state` for callbacks, etc)
 *
 * we currently just set this statically. If the values changes any data using
 * the iv will be effectively negated including sessions, jwts, etc.
 *
 * https://stackoverflow.com/questions/39412760/what-is-an-openssl-iv-and-why-do-i-need-a-key-and-an-iv
 */
const ivSecret = process.env.EAS_ENCRYPT_IV_SECRET;
let iv;
if (ivSecret) {
  iv = crypto
    .createHash("sha256")
    .update(String(ivSecret))
    .digest("hex")
    .substr(0, CRYPTO_IV_LENGTH);
}

function exit_failure(message = "", code = 1) {
  if (message) {
    console.log(message);
  }
  process.exit(code);
}

function md5(text) {
  return crypto.createHash("md5").update(text).digest("hex");
}

function generate_crypto_key(salt) {
  return crypto
    .createHash("sha256")
    .update(String(salt))
    .digest("hex")
    .substr(0, CRYPTO_KEY_LENGTH);
}

function encrypt(salt, text, encoding = "base64") {
  try {
    let cipher;
    if (iv) {
      const key = generate_crypto_key(salt);
      cipher = crypto.createCipheriv(CRYPTO_ALGORITHM, key, iv);
    } else {
      cipher = crypto.createCipher(CRYPTO_ALGORITHM, salt);
    }

    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(text, "utf8")),
      cipher.final(),
    ]);

    return encrypted.toString(encoding);
  } catch (exception) {
    throw new Error(exception.message);
  }
}

function decrypt(salt, text, encoding = "base64") {
  try {
    let decipher;
    if (iv) {
      const key = generate_crypto_key(salt);
      decipher = crypto.createDecipheriv(CRYPTO_ALGORITHM, key, iv);
    } else {
      decipher = crypto.createDecipher(CRYPTO_ALGORITHM, salt);
    }

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(text, encoding)),
      decipher.final(),
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

function toBoolean(input) {
  //return !!(dataStr?.toLowerCase?.() === 'true' || dataStr === true || Number.parseInt(dataStr, 10) === 0);
  //return !!(dataStr?.toLowerCase?.() === 'true' || dataStr === true);
  
  if (typeof input == "undefined" || input === null) {
    return false;
  }
  
  if (typeof input == "boolean") {
    return input;
  }

  if (!isNaN(input)) {
    if (typeof input == "string") {
      input = parseFloat(input);
    }
    return Boolean(input);
  }

  if (typeof input == "string") {
    switch (input.toLocaleLowerCase()) {
      case "true":
        return true;
      case "false":
        return false;
      default:
        return Boolean(input);
    }
  }

  throw new Error("unable to determine boolean value");
}

function is_jwt(jwtString) {
  const re = new RegExp(
    /^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/
  );
  return re.test(jwtString);
}

function is_json_like(str) {
  if (typeof str !== "string") {
    return false;
  }

  const JSON_START = /^\[|^\{(?!\{)/;
  const JSON_ENDS = {
    "[": /]$/,
    "{": /}$/,
  };

  const jsonStart = str.match(JSON_START);
  if (!jsonStart) {
    return false;
  }

  return JSON_ENDS[jsonStart[0]].test(str);
}

function is_yaml_like(str) {
  if (typeof str !== "string") {
    return false;
  }

  if (str.startsWith("---")) {
    return true;
  }
  // TODO: fix this logic to be sane
  return true;
}

/**
 * ingress-nginx headers
 * - x-sent-from: nginx-ingress-controller
 * - x-auth-request-redirect:/anything?foo=bar
 * - x-original-method: GET
 * - x-original-url: <full url>
 *
 * @param {*} req
 */
function get_parent_request_info(req) {
  const info = {};
  info.uri = get_parent_request_uri(req);
  info.parsedUri = URI.parse(info.uri);
  info.parsedQuery = JSON.parse(
    JSON.stringify(queryString.parse(info.parsedUri.query))
  );
  // not used currently but could be used for verify process
  if (req.headers["x-forwarded-method"]) {
    info.method = req.headers["x-forwarded-method"];
  }

  // ingress-nginx
  if (!info.method && req.headers["x-original-method"]) {
    info.method = req.headers["x-original-method"];
  }

  return info;
}

function get_parent_request_uri(req) {
  let originalRequestURI = "";

  if (req.headers["x-eas-request-uri"]) {
    return req.headers["x-eas-request-uri"];
  }

  // ingress-nginx
  if (req.headers["x-original-url"]) {
    return req.headers["x-original-url"];
  }

  if (!("x-forwarded-proto" in req.headers)) {
    throw new Error(
      "missing x-forwarded-proto header, cannot determine parent request uri"
    );
  }

  if (!("x-forwarded-uri" in req.headers)) {
    throw new Error(
      "missing x-forwarded-uri header, cannot determine parent request uri"
    );
  }

  originalRequestURI += req.headers["x-forwarded-proto"] + "://";

  if (req.headers["x-forwarded-host"]) {
    originalRequestURI += req.headers["x-forwarded-host"];
  } else {
    originalRequestURI += req.headers["host"];
  }

  if (req.headers["x-replaced-path"]) {
    /*
      {
        "headers": {
          "x-forwarded-uri": "/test/api?var1=test",
          "x-replaced-path": "/demo/cjm/test/api"
        },
        "body": {}
      }
    */

    originalRequestURI += req.headers["x-replaced-path"];

    const parsedUri = URI.parse(req.headers["x-forwarded-uri"]);
    if (parsedUri.query) {
      originalRequestURI += "?" + parsedUri.query;
    }
  } else if (req.headers["x-forwarded-prefix"]) {
    /*
      {
        "headers": {
          "x-forwarded-prefix": "/demo/cjm/",
          "x-forwarded-uri": "/test/api?var1=test",
        },
        "body": {}
      }
    */

    originalRequestURI += req.headers["x-forwarded-prefix"];
    originalRequestURI = originalRequestURI.replace(/^(.+?)\/*?$/, "$1"); // remove all trailing slashes
    originalRequestURI += req.headers["x-forwarded-uri"];
  } else {
    originalRequestURI += req.headers["x-forwarded-uri"];
  }

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

/**
 * Takes the requested URI to the auth server and strips the initial parts of the url
 * /ambasador/verify/:verify_parms/...leave this...
 *
 * ie: remove the 'path_prefix' portion of the URL
 *
 * @param {*} req
 */
function get_envoy_forwarded_uri(req, leadingParts = 4) {
  // TODO: properly parse the whole URL and then reconstruct for saner handling
  const parts = req.url.split("/");
  parts.splice(0, leadingParts);

  return "/" + parts.join("/");
}

/**
 * Attempts to detect if a request is xhr or not
 *
 * @param {*} req
 */
function request_is_xhr(req) {
  if (req.headers.origin) {
    return true;
  }

  if (
    req.headers["x-requested-with"] &&
    req.headers["x-requested-with"].toLowerCase() == "xmlhttprequest"
  ) {
    return true;
  }

  return false;
}

function parse_basic_authorization_header(value) {
  let parts;
  const creds = {};
  parts = value.split(" ");

  creds.strategy = parts[0];

  parts = base64_decode(parts[1]);
  creds.username = parts.split(":")[0];
  creds.password = parts.split(":").slice(1).join(":");

  return creds;
}

function parse_bearer_authorization_header(value) {
  let parts;
  const creds = {};
  parts = value.split(" ");

  creds.scheme = parts[0];
  creds.token = parts.slice(1).join(" ");

  return creds;
}

function authorization_scheme_is(value, scheme) {
  const value_scheme = value.split(" ")[0];
  if (value_scheme.toLowerCase() == scheme.toLowerCase()) {
    return true;
  }

  return false;
}

function array_unique(a) {
  return a.filter(function (e, i, c) {
    return c.indexOf(e) === i;
  });
}

function array_intersect(a, b) {
  let t;
  if (b.length > a.length) (t = b), (b = a), (a = t); // indexOf to loop over shorter
  return a.filter(function (e) {
    return b.indexOf(e) > -1;
  });
}

async function js_query(query, data) {
  const func = new Function("data", query);
  return func(data);
}

async function jsonata_query(query, data) {
  return jsonata(query).evaluate(data);
}

async function jsonpath_query(query, data) {
  return jp.query(data, query);
}

async function jq_query(query, data) {
  const options = {
    input: "json",
    output: "json",
  };

  const values = await jq.run(query, data, options);
  return values;
}

async function json_query(query_engine, query, data) {
  let value;

  switch (query_engine) {
    case "js":
      if (process.env.EAS_ALLOW_EVAL) {
        value = await js_query(query, data);
      } else {
        throw new Error(
          "cannot use potentially unsafe query_engine 'js' unless env variable 'EAS_ALLOW_EVAL' is set"
        );
      }
      break;
    case "jsonata":
      value = await jsonata_query(query, data);
      break;
    case "jp":
      value = await jsonpath_query(query, data);
      break;
    case "jq":
      value = await jq_query(query, data);
      break;
    case "handlebars":
      const template = Handlebars.compile(query);
      value = template(data);
      break;
    default:
      throw new Error("invalid query engine: " + query_engine);
  }

  return value;
}

function redirect_http_code(req) {
  return req.query.redirect_http_code ? req.query.redirect_http_code : 302;
}

function lower_case_keys(obj) {
  let key,
    keys = Object.keys(obj);
  let n = keys.length;
  let newobj = {};
  while (n--) {
    key = keys[n];
    newobj[key.toLowerCase()] = obj[key];
  }

  return newobj;
}

function stringify(value) {
  const getCircularReplacer = () => {
    const seen = new WeakSet();
    return (key, value) => {
      if (typeof value === "object" && value !== null) {
        if (seen.has(value)) {
          return;
        }
        seen.add(value);
      }
      return value;
    };
  };

  return JSON.stringify(value, getCircularReplacer());
}

function validateConfigToken(configToken) {}

async function get_jwt_sign_secret(secret, kid) {
  // jwks uri
  if (
    typeof secret === "string" &&
    (secret.startsWith("http://") || secret.startsWith("https://"))
  ) {
    const client = jwksClient({
      jwksUri: secret,
    });

    const key = await client.getSigningKey(kid);
    if (key) {
      return key.getPublicKey();
    }
  } else {
    // jwks result
    if (typeof secret === "object" || Array.isArray(secret)) {
      if (!Array.isArray(secret)) {
        secret = secret.keys;
      }
      const keys = await retrieveSigningKeys(secret);
      function getSigningKey() {
        const kidDefined = kid !== undefined && kid !== null;
        if (!kidDefined && keys.length > 1) {
          throw new Error(
            "No KID specified and JWKS endpoint returned more than 1 key"
          );
        }

        const key = keys.find((k) => !kidDefined || k.kid === kid);
        if (key) {
          return key;
        } else {
          throw new Error(`Unable to find a signing key that matches '${kid}'`);
        }
      }
      const key = getSigningKey();
      if (key) {
        return key.getPublicKey();
      }
    }

    // shared secret
    return secret;
  }
}

module.exports = {
  exit_failure,
  encrypt,
  decrypt,
  md5,
  base64_encode,
  base64_decode,
  generate_session_id,
  generate_csrf_id,
  toBoolean,
  is_json_like,
  is_yaml_like,
  is_jwt,
  get_parent_request_uri,
  get_parent_request_info,
  get_envoy_forwarded_uri,
  request_is_xhr,
  validateConfigToken,
  parse_basic_authorization_header,
  parse_bearer_authorization_header,
  authorization_scheme_is,
  redirect_http_code,
  array_unique,
  array_intersect,
  lower_case_keys,
  json_query,
  stringify,
  get_jwt_sign_secret,
};
