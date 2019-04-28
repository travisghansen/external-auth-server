const config = require("./config");
const crypto = require("crypto");
const { Issuer } = require("openid-client");
const jwt = require("jsonwebtoken");
const queryString = require("query-string");
const URI = require("uri-js");
const uuidv4 = require("uuid/v4");

const algorithm = "aes-256-cbc";

Issuer.useRequest();
Issuer.defaultHttpOptions = { timeout: 10000, headers: {} };

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

function encrypt(salt, text) {
  try {
    var cipher = crypto.createCipher(algorithm, salt);
    var encrypted = Buffer.concat([
      cipher.update(Buffer.from(text, "utf8")),
      cipher.final()
    ]);
    return encrypted.toString("base64");
  } catch (exception) {
    throw new Error(exception.message);
  }
}

function decrypt(salt, text) {
  try {
    var decipher = crypto.createDecipher(algorithm, salt);
    var decrypted = Buffer.concat([
      decipher.update(Buffer.from(text, "base64")),
      decipher.final()
    ]);
    return decrypted.toString("utf8");
  } catch (exception) {
    throw new Error(exception.message);
  }
}

function generate_session_id() {
  return uuidv4();
}

function generate_csrf_id() {
  return uuidv4();
}

function get_parent_request_info(configToken, req) {
  const info = {};
  info.uri = get_parent_request_uri(req);
  info.parsedUri = URI.parse(info.uri);
  info.parsedQuery = JSON.parse(
    JSON.stringify(queryString.parse(info.parsedUri.query))
  );
  // not used currently but could be used for verify process
  info.method = req.headers["x-forwarded-method"];
  info.authorization_redirect_uri = get_authorization_redirect_uri(
    configToken,
    info.uri
  );

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

function get_issuer(configToken) {
  const discover_url = configToken.oeas.issuer.discover_url;
  return new Promise((resolve, reject) => {
    if (discover_url) {
      Issuer.discover(discover_url)
        .then(issuer => {
          console
            .log
            //"newly discovered issuer %s %O",
            //issuer.issuer,
            //issuer.metadata
            ();
          //console.log(issuer);
          resolve(issuer);
        })
        .catch(e => {
          console.log(e);
          reject(e);
        });
    } else {
      const issuer = new Issuer(configToken.oeas.issuer);
      console.log("manual issuer %s %O", issuer.issuer, issuer.metadata);
      resolve(issuer);
    }
  });
}

function get_client(issuer, configToken) {
  console.log("client config %j", configToken);
  let client;
  return new Promise((resolve, reject) => {
    if (
      configToken.oeas.client.client_id &&
      configToken.oeas.client.client_secret
    ) {
      client = new issuer.Client({
        client_id: configToken.oeas.client.client_id,
        client_secret: configToken.oeas.client.client_secret
      });
      client.CLOCK_TOLERANCE = config.DEFAULT_CLIENT_CLOCK_TOLERANCE;

      resolve(client);
    } else if (
      configToken.oeas.client.registration_client_uri &&
      configToken.oeas.client.registration_access_token
    ) {
      issuer.Client.fromUri(
        configToken.oeas.issuer.registration_client_uri,
        configToken.oeas.issuer.registration_access_token
      )
        .then(function(client) {
          client.CLOCK_TOLERANCE = config.DEFAULT_CLIENT_CLOCK_TOLERANCE;
          resolve(client);
        })
        .catch(e => {
          reject(e);
        });
    } else {
      reject("invalid client configuration");
    }
  });
}

/**
 * Generate appropriate authorization redirect URI
 *
 * We redirect to the exact same URI as requested (ensures we land at the same
 * place) without the query original query params (prevents overwriting data).
 *
 * @param {*} uri
 */
function get_authorization_redirect_uri(configToken, uri) {
  const query = {};
  query[config.HANDLER_INDICATOR_PARAM_NAME] = "authorization_callback";

  console.log(config.HANDLER_INDICATOR_PARAM_NAME);

  if (configToken.oeas.redirect_uri) {
    uri = configToken.oeas.redirect_uri;
  }

  const parsedURI = URI.parse(uri);
  parsedURI.query = queryString.stringify(query);

  return URI.serialize(parsedURI);
}

function setConfigTokenDefaults(configToken) {
  const configAudMD5 = configToken.hasOwnProperty("aud")
    ? md5(JSON.stringify(configToken.aud))
    : md5(JSON.stringify(configToken));

  configToken.audMD5 = configAudMD5;

  if (!configToken.oeas.cookie) {
    configToken.oeas.cookie = {};
  }

  configToken.oeas.cookie.name = configToken.oeas.cookie.hasOwnProperty("name")
    ? configToken.oeas.cookie.name
    : config.DEFAULT_COOKIE_NAME;

  if (!configToken.oeas.cookie.hasOwnProperty("domain")) {
    configToken.oeas.cookie.domain = null;
  }

  if (!configToken.oeas.cookie.hasOwnProperty("path")) {
    configToken.oeas.cookie.path = "/";
  }

  if (!configToken.oeas.features) {
    configToken.oeas.features = {};
  }

  if (!configToken.oeas.assertions) {
    configToken.oeas.assertions = {};
  }

  if (!configToken.oeas.features.hasOwnProperty("set_cookie_expiry")) {
    configToken.oeas.features.set_cookie_expiry = false;
  }

  if (!configToken.oeas.features.hasOwnProperty("refresh_access_token")) {
    configToken.oeas.features.refresh_access_token = true;
  }

  if (!configToken.oeas.features.hasOwnProperty("fetch_userinfo")) {
    configToken.oeas.features.fetch_userinfo = true;
  }

  if (!configToken.oeas.features.hasOwnProperty("introspect_access_token")) {
    configToken.oeas.features.introspect_access_token = false;
  }

  if (!configToken.oeas.assertions.hasOwnProperty("exp")) {
    configToken.oeas.assertions.exp = true;
  }

  if (!configToken.oeas.assertions.hasOwnProperty("nbf")) {
    configToken.oeas.assertions.nbf = true;
  }

  if (!configToken.oeas.assertions.hasOwnProperty("iss")) {
    configToken.oeas.assertions.iss = true;
  }

  return configToken;
}

function validateConfigToken(configToken) {}

function prepare_token_headers(res, sessionData, configToken) {
  if (sessionData.tokenSet.id_token) {
    res.header("X-Id-Token", sessionData.tokenSet.id_token);
  }

  if (sessionData.userinfo) {
    res.header("X-Userinfo", JSON.stringify(sessionData.userinfo));
  }

  if (sessionData.tokenSet.access_token) {
    res.header("X-Access-Token", sessionData.tokenSet.access_token);
  }

  if (
    configToken.oeas.features.authorization_token &&
    ["id_token", "access_token", "refresh_token"].includes(
      configToken.oeas.features.authorization_token
    ) &&
    sessionData.tokenSet[configToken.oeas.features.authorization_token]
  ) {
    res.header(
      "Authorization",
      "Bearer " +
        sessionData.tokenSet[configToken.oeas.features.authorization_token]
    );
  }
}

function token_is_expired(token) {
  return !!(token.exp && token.exp < Date.now() / 1000);
}

function token_is_premature(token) {
  return !!(token.nbf && token.nbf < Date.now() / 1000);
}

function token_issuer_match(token, issuer) {
  return token.iss && token.iss == issuer;
}

function tokenset_is_expired(tokenSet) {
  if (tokenSet.expires_at) {
    return !!(tokenSet.expires_at < Date.now() / 1000);
  }

  if (tokenSet.id_token) {
    return token_is_expired(jwt.decode(tokenSet.id_token));
  }

  return false;
}

function tokenset_is_premature(tokenSet) {
  if (tokenSet.id_token) {
    return token_is_premature(jwt.decode(tokenSet.id_token));
  }

  return false;
}

function tokenset_issuer_match(tokenSet, issuer) {
  if (tokenSet.id_token) {
    return token_issuer_match(jwt.decode(tokenSet.id_token), issuer);
  }

  return true;
}

function tokenset_can_refresh(tokenSet) {
  if (!tokenSet.refresh_token) {
    return false;
  }

  let refreshToken;
  try {
    refreshToken = jwt.decode(tokenSet.refresh_token);
    return token_is_expired(refreshToken);
  } catch (e) {
    return true;
  }
}

module.exports = {
  exit_failure,
  encrypt,
  decrypt,
  md5,
  generate_session_id,
  generate_csrf_id,
  get_parent_request_uri,
  get_parent_request_info,
  get_authorization_redirect_uri,
  get_issuer,
  get_client,
  setConfigTokenDefaults,
  validateConfigToken,
  prepare_token_headers,
  token_is_expired,
  token_is_premature,
  token_issuer_match,
  tokenset_is_expired,
  tokenset_is_premature,
  tokenset_issuer_match,
  tokenset_can_refresh
};
