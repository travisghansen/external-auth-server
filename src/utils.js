const crypto = require("crypto");
const queryString = require("query-string");
const URI = require("uri-js");
const uuidv4 = require("uuid/v4");
const jp = require("jsonpath");

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

function array_unique(a) {
  return a.filter(function(e, i, c) {
    return c.indexOf(e) === i;
  });
}

function array_intersect(a, b) {
  let t;
  if (b.length > a.length) (t = b), (b = a), (a = t); // indexOf to loop over shorter
  return a.filter(function(e) {
    return b.indexOf(e) > -1;
  });
}

function redirect_http_code(req) {
  return req.query.redirect_http_code ? req.query.redirect_http_code : 302;
}

function jsonpath_query(obj, path, singleValue = false) {
  const values = jp.query(obj, path);
  if (singleValue) {
    if (values.length > 1) {
      throw new Error("more than 1 value in jsonpath query result");
    }

    return values[0];
  }
  return values;
}

function assert(rule, value) {
  let test;

  //console.log("########## asserting the following rule: %j", rule);
  //console.log("########## asserting the following value: ", value);

  if (rule.case_insensitive) {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        value[i] = value[i].toString().toLowerCase();
      }
    } else {
      value = value.toString().toLowerCase();
    }

    if (Array.isArray(rule.value)) {
      for (let i = 0; i < rule.value.length; i++) {
        rule.value[i] = rule.value[i].toString().toLowerCase();
      }
    } else {
      rule.value = rule.value.toString().toLowerCase();
    }
  }

  let a, b, c;
  switch (rule.method) {
    case "contains":
      if (!Array.isArray(value)) {
        throw new Error("value must be an array for 'contains' method");
      }

      test = value.includes(rule.value);
      break;
    case "contains-any":
      if (!Array.isArray(value)) {
        throw new Error("value must be an array for 'contains-any' method");
      }

      if (!Array.isArray(rule.value)) {
        throw new Error(
          "rule.value must be an array for 'contains-any' method"
        );
      }

      a = array_unique(value);
      b = array_unique(rule.value);
      c = array_intersect(a, b);
      test = c.length > 0;
      break;
    case "contains-all":
      if (!Array.isArray(value)) {
        throw new Error("value must be an array for 'contains-all' method");
      }

      if (!Array.isArray(rule.value)) {
        throw new Error(
          "rule.value must be an array for 'contains-all' method"
        );
      }

      a = array_unique(value);
      b = array_unique(rule.value);
      c = array_intersect(a, b);
      test = b.length == c.length;
      break;
    case "eq":
      test = rule.value == value;
      break;
    case "in":
      if (!Array.isArray(rule.value)) {
        throw new Error("rule.value must be an array for 'in' method");
      }

      test = rule.value.includes(value);
      break;
    case "regex":
      /**
       * this splits the simple "/pattern/[flags]" syntaxt into something the
       * regex constructor understands
       */
      const parts = /\/(.*)\/(.*)/.exec(rule.value);
      const regex = new RegExp(parts[1], parts[2]);
      test = regex.test(value);
      break;
    default:
      throw new Error("unknown assert method: " + rule.method);
  }

  if (rule.negate) {
    return !!!test;
  }

  return test;
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
  redirect_http_code,
  jsonpath_query,
  assert,
  array_unique,
  array_intersect
};
