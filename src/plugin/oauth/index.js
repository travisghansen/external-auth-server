const { Assertion } = require("../../assertion");
const { BasePlugin } = require("../../plugin");
const Handlebars = require("handlebars");
const { Issuer, custom } = require("openid-client");
const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");
const queryString = require("query-string");
const request = require("request");
const URI = require("uri-js");

custom.setHttpOptionsDefaults({
  followRedirect: false,
  timeout: 10000,
  headers: {},
});

if (process.env.DEBUG_OIDC) {
  custom.setHttpOptionsDefaults({
    hooks: {
      beforeRequest: [
        (options) => {
          console.log(
            "--> %s %s",
            options.method.toUpperCase(),
            options.url.href
          );
          console.log("--> HEADERS %o", options.headers);
          if (options.body) {
            console.log("--> BODY %s", options.body);
          }
        },
      ],
      afterResponse: [
        (response) => {
          console.log(
            "<-- %i FROM %s %s",
            response.statusCode,
            response.request.options.method.toUpperCase(),
            response.request.options.url.href
          );
          console.log("<-- HEADERS %o", response.headers);
          if (response.body) {
            console.log("<-- BODY %s", response.body);
          }
          return response;
        },
      ],
    },
  });
}

const exit_failure = function (message = "", code = 1) {
  if (message) {
    console.log(message);
  }
  process.exit(code);
};

const issuer_encrypt_secret =
  process.env.EAS_ISSUER_ENCRYPT_SECRET ||
  exit_failure("missing EAS_ISSUER_ENCRYPT_SECRET env variable");
const issuer_sign_secret =
  process.env.EAS_ISSUER_SIGN_SECRET ||
  exit_failure("missing EAS_ISSUER_SIGN_SECRET env variable");

const SESSION_CACHE_PREFIX = "session:oauth:";
const INTROSPECTION_CACHE_PREFIX = "introspection:oauth:";
const DEFAULT_COOKIE_NAME = "_eas_oauth_session";

const HANDLER_INDICATOR_PARAM_NAME = "__eas_oauth_handler__";
const STATE_CSRF_COOKIE_NAME = "_eas_oauth_csrf";
const STATE_CSRF_COOKIE_EXPIRY = "43200"; //12 hours
const DEFAULT_CLIENT_CLOCK_TOLERANCE = 5;
const ISSUER_CACHE_DURATION = 43200 * 1000;
const CLIENT_CACHE_DURATION = 43200 * 1000;

const STATE_CACHE_PREFIX = "state:oauth:";
const STATE_CACHE_EXPIRY = "43200"; //12 hours

const BACKCHANNEL_LOGOUT_CACHE_PREFIX = "bachchannel_logout:oauth:";
const BACKCHANNEL_LOGOUT_DEFAULT_TTL = 2678400; //31 days

let initialized = false;

/**
 * Initialize common config options for oidc/oauth2 plugins
 *
 * @param {*} config
 */
function initialize_common_config_options(config) {
  config.custom_authorization_parameters =
    config.custom_authorization_parameters || {};

  config.custom_authorization_code_parameters =
    config.custom_authorization_code_parameters || {};

  config.custom_refresh_parameters = config.custom_refresh_parameters || {};

  config.custom_revoke_parameters = config.custom_revoke_parameters || {};

  if (!config.cookie) {
    config.cookie = {};
  }

  if (!config.csrf_cookie) {
    config.csrf_cookie = {};
  }

  if (!config.csrf_cookie.hasOwnProperty("enabled")) {
    config.csrf_cookie.enabled = true;
  }

  if (!config.csrf_cookie.hasOwnProperty("domain")) {
    config.csrf_cookie.domain = null;
  }

  if (!config.csrf_cookie.hasOwnProperty("path")) {
    config.csrf_cookie.path = "/";
  }

  if (!config.csrf_cookie.hasOwnProperty("secure")) {
    config.csrf_cookie.secure = false;
  }

  if (!config.csrf_cookie.hasOwnProperty("httpOnly")) {
    config.csrf_cookie.httpOnly = true;
  }

  if (!config.csrf_cookie.hasOwnProperty("sameSite")) {
    config.csrf_cookie.sameSite = "lax";
  }

  config.cookie.name = config.cookie.hasOwnProperty("name")
    ? config.cookie.name
    : DEFAULT_COOKIE_NAME;

  if (!config.cookie.hasOwnProperty("domain")) {
    config.cookie.domain = null;
  }

  if (!config.cookie.hasOwnProperty("path")) {
    config.cookie.path = "/";
  }

  if (!config.cookie.hasOwnProperty("secure")) {
    config.cookie.secure = false;
  }

  if (!config.cookie.hasOwnProperty("httpOnly")) {
    config.cookie.httpOnly = true;
  }

  if (!config.cookie.hasOwnProperty("sameSite")) {
    config.cookie.sameSite = "lax";
  }

  if (!config.features) {
    config.features = {};
  }

  if (!config.features.hasOwnProperty("filtered_service_headers")) {
    config.features.filtered_service_headers = [];
  }

  if (!config.features.logout) {
    config.features.logout = {};
  }

  if (!config.features.logout.end_provider_session) {
    config.features.logout.end_provider_session = {};
  }

  if (!config.features.logout.backchannel) {
    config.features.logout.backchannel = {};
  }

  if (!config.assertions) {
    config.assertions = {};
  }

  if (!config.features.hasOwnProperty("cookie_expiry")) {
    config.features.cookie_expiry = false;
  }

  if (!config.features.hasOwnProperty("userinfo_expiry")) {
    config.features.userinfo_expiry = true;
  }

  if (!config.features.hasOwnProperty("session_retain_id")) {
    config.features.session_retain_id = true;
  }

  if (!config.features.hasOwnProperty("session_expiry")) {
    config.features.session_expiry = true;
  }

  if (!config.features.hasOwnProperty("refresh_access_token")) {
    config.features.refresh_access_token = true;
  }

  if (!config.features.hasOwnProperty("fetch_userinfo")) {
    config.features.fetch_userinfo = true;
  }

  if (!config.xhr) {
    config.xhr = {};
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
    return !!!token_is_expired(refreshToken);
  } catch (e) {
    return true;
  }
}

function tokenset_refresh_can_expire(tokenSet) {
  if (!tokenSet.refresh_token) {
    return false;
  }

  if (tokenSet.refresh_expires_in) {
    return true;
  }

  try {
    refreshToken = jwt.decode(tokenSet.refresh_token);
    if (refreshToken.exp) {
      return true;
    }
  } catch (e) {}

  return false;
}

function tokenset_refresh_expire_at(tokenSet) {
  if (tokenset_refresh_can_expire(tokenSet)) {
    //TODO: implement this somehow
  }

  return null;
}

/**
 * Get issuer instance
 *
 * @param {*} options
 * @returns
 */
async function get_oauth_issuer(options) {
  const discover_url = options.discover_url;
  let issuer;

  if (discover_url) {
    issuer = await Issuer.discover(discover_url);
    return issuer;
  } else {
    issuer = new Issuer(options);
    return issuer;
  }
}

/**
 * Get client instance
 *
 * @param {*} options
 * @param {*} issuer
 * @returns
 */
async function get_oauth_client(options, issuer) {
  let client;

  if (options.client_id && options.client_secret) {
    client = new issuer.Client({
      client_id: options.client_id,
      client_secret: options.client_secret,
    });
    client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;
    return client;
  } else if (
    options.registration_client_uri &&
    options.registration_access_token
  ) {
    client = await issuer.Client.fromUri(
      options.registration_client_uri,
      options.registration_access_token
    );

    client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;
    return client;
  } else {
    throw new Error("invalid client configuration");
  }
}

/**
 * Retrieve backchannel_logout_data (if any) from the store
 *
 * @param {*} server
 * @param {*} key
 * @returns
 */
async function get_backchannel_logout_data(server, key) {
  const store = server.store;
  server.logger.verbose("retrieving backchannel_logout data: %s", key);

  let data = await store.get(BACKCHANNEL_LOGOUT_CACHE_PREFIX + key);

  server.logger.verbose(
    "retrieved encrypted backchannel_logout data: %s",
    data
  );

  if (!data) {
    return false;
  }

  data = server.utils.decrypt(server.secrets.session_encrypt_secret, data);

  if (!data) {
    server.logger.verbose("failed to decrypt backchannel_logout data");
    return false;
  }

  server.logger.debug("backchannel_logout data: %s", data);
  data = JSON.parse(data);

  return data;
}

/**
 * This should only ever get invoked directly by the backchannel endpoint
 * as updates need to be handled specially to not reset the ttl of the entry in
 * the store.
 *
 * @param {*} server
 * @param {*} key
 * @param {*} data
 * @param {*} ttl
 */
async function set_backchannel_logout_data(server, key, data, ttl = null) {
  data.authenticated_sessions = data.authenticated_sessions || [];
  await server.store.set(
    BACKCHANNEL_LOGOUT_CACHE_PREFIX + key,
    server.utils.encrypt(
      server.secrets.session_encrypt_secret,
      JSON.stringify(data)
    ),
    ttl
  );
}

/**
 * This function potentially has concurrency issues but the security risk
 * should be 0. If a 2nd request comes in the last man wins leaving the first
 * session in the dark needing to re-authenticate. The scope of concurrency
 * should only ever be per iss/aud/sub||sid so extremely small but possible.
 *
 * @param {*} server
 * @param {*} key
 * @param {*} session_id
 * @returns
 */
async function add_backchannel_logout_authenticated_session(
  server,
  key,
  session_id
) {
  let data = await get_backchannel_logout_data(server, key);

  // if no current logout data available move along
  if (!data) {
    return;
  }

  data.authenticated_sessions = data.authenticated_sessions || [];
  data.authenticated_sessions.push(session_id);

  let ttl = data.ttl;
  let iat = data.iat;

  if (ttl) {
    ttl = ttl - (Date.now() / 1000 - iat);
    if (ttl < 1) {
      await delete_backchannel_logout_data(server, key);
      return;
    }
  }

  await set_backchannel_logout_data(server, key, data, ttl);
}

/**
 * Unlikely to ever be used as the entry should have a ttl and delete itself.
 *
 * @param {*} server
 * @param {*} key
 */
async function delete_backchannel_logout_data(server, key) {
  if (key) {
    await server.store.del(BACKCHANNEL_LOGOUT_CACHE_PREFIX + key);
  }
}

/**
 * common method to ensure the same syntax for logout keys
 *
 * @param {*} server
 * @param {*} token
 * @returns
 */
async function generate_backchannel_logout_key(server, token) {
  /**
   * purposely not using specific logic for situations where both sid
   * and sub are present as sid already guarenteed to be unique
   */

  // https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions
  // the ordering here is incredibly important as the *exact* same logic
  // should be used/checked on the other side of the equation
  //let lock_key = { iss: token.iss, aud: token.aud };
  let lock_key = { iss: token.iss };
  if (token.hasOwnProperty("sid")) {
    // create a sid-based lock
    lock_key.sid = token.sid;
  } else if (token.hasOwnProperty("sub")) {
    // create a sub-based lock
    lock_key.sub = token.sub;
  } else {
    throw new Error("missing both sid and sub claims");
  }

  server.logger.verbose("backchannel_logout key object: %j", lock_key);
  lock_key = server.utils.md5(JSON.stringify(lock_key));
  server.logger.verbose("backchannel_logout key: %s", lock_key);

  return lock_key;
}

function handlebars_template_properties(src, data) {
  const ret = {};
  for (let property in src) {
    let value = src[property];
    const template = Handlebars.compile(value);

    ret[property] = template(data);
  }

  return ret;
}

class BaseOauthPlugin extends BasePlugin {
  static initialize(server) {
    if (!initialized) {
      server.WebServer.get("/oauth/callback", (req, res) => {
        server.logger.silly("%j", {
          headers: req.headers,
          body: req.body,
        });

        try {
          let state = server.utils.decrypt(
            issuer_encrypt_secret,
            req.query.state,
            "hex"
          );
          state = jwt.verify(state, issuer_sign_secret);
          const state_redirect_uri = state.request_uri;

          const parsedStateRedirectURI = URI.parse(state_redirect_uri);
          server.logger.verbose(
            "parsed state redirect uri: %j",
            parsedStateRedirectURI
          );

          const parsedRequestURI = URI.parse(req.url);
          server.logger.verbose("parsed request uri: %j", parsedRequestURI);

          const parsedRedirectURI = Object.assign({}, parsedStateRedirectURI);
          const parsedQuery = queryString.parse(parsedRequestURI.query);
          parsedQuery[HANDLER_INDICATOR_PARAM_NAME] = "authorization_callback";
          parsedRedirectURI.query = queryString.stringify(parsedQuery);
          server.logger.verbose("parsed redirect uri: %j", parsedRedirectURI);

          const redirect_uri = URI.serialize(parsedRedirectURI);
          server.logger.info("redirecting browser to: %j", redirect_uri);

          res.statusCode = 302;
          res.setHeader("Location", redirect_uri);
          res.end();
          return;
        } catch (e) {
          server.logger.error(e);
          res.statusCode = 503;
          res.end();
        }
      });

      server.WebServer.get("/oauth/end-session-redirect", (req, res) => {
        server.logger.silly("%j", {
          headers: req.headers,
          body: req.body,
        });

        try {
          let state = server.utils.decrypt(
            issuer_encrypt_secret,
            req.query.state,
            "hex"
          );
          state = jwt.verify(state, issuer_sign_secret);
          const redirect_uri = state.redirect_uri;
          server.logger.verbose("state redirect uri: %j", redirect_uri);

          res.statusCode = 302;
          res.setHeader("Location", redirect_uri);
          res.end();
          return;
        } catch (e) {
          server.logger.error(e);
          res.statusCode = 503;
          res.end();
        }
      });

      // https://openid.net/specs/openid-connect-backchannel-1_0.html
      server.WebServer.post("/oauth/backchannel-logout", async (req, res) => {
        server.logger.silly("%j", {
          headers: req.headers,
          body: req.body,
        });

        try {
          if (!req.query.backchannel_config_token) {
            throw new Error("missing backchannel_config_token");
          }

          let backchannel_config_token = server.utils.decrypt(
            server.secrets.config_token_encrypt_secret,
            req.query.backchannel_config_token
          );
          backchannel_config_token = jwt.verify(
            backchannel_config_token,
            server.secrets.config_token_sign_secret
          );

          server.logger.silly(
            "backchannel revoke using backchannel_config_token: %j",
            backchannel_config_token
          );

          const issuer = await get_oauth_issuer(
            backchannel_config_token.eas.issuer
          );
          let jwt_secret = issuer.jwks_uri;

          function getKey(header, callback) {
            let client;
            if (
              jwt_secret.startsWith("http://") ||
              jwt_secret.startsWith("https://")
            ) {
              client = jwksClient({
                jwksUri: jwt_secret,
              });

              client.getSigningKey(header.kid, function (err, key) {
                if (err) {
                  callback(err, null);
                } else {
                  const signingKey = key.publicKey || key.rsaPublicKey;
                  callback(null, signingKey);
                }
              });
            } else {
              callback(null, jwt_secret);
            }
          }

          /**
           * If the logout succeeded, the RP MUST respond with HTTP 200 OK. If
           * the logout request was invalid, the RP MUST respond with HTTP 400
           * Bad Request. If the logout failed, the RP MUST respond with 501
           * Not Implemented. If the local logout succeeded but some downstream
           * logouts have failed, the RP MUST respond with HTTP 504 Gateway
           * Timeout.
           *
           * The RP's response SHOULD include Cache-Control directives keeping
           * the response from being cached to prevent cached responses from
           * interfering with future logout requests. It is RECOMMENDED that
           * these directives be used:
           *
           * Cache-Control: no-cache, no-store
           * Pragma: no-cache
           */
          try {
            /**
             * Upon receiving a logout request at the back-channel logout URI, the RP MUST validate the Logout Token as follows:
             * If the Logout Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt ID Tokens. If ID Token encryption was negotiated with the OP at Registration time and the Logout Token is not encrypted, the RP SHOULD reject it.
             * Validate the Logout Token signature in the same way that an ID Token signature is validated, with the following refinements.
             * Validate the iss, aud, and iat Claims in the same way they are validated in ID Tokens.
             * Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
             * Verify that the Logout Token contains an events Claim whose value is JSON object containing the member name http://schemas.openid.net/event/backchannel-logout.
             * Verify that the Logout Token does not contain a nonce Claim.
             * Optionally verify that another Logout Token with the same jti value has not been recently received.
             * Optionally verify that the iss Logout Token Claim matches the iss Claim in an ID Token issued for the current session or a recent session of this RP with the OP.
             * Optionally verify that any sub Logout Token Claim matches the sub Claim in an ID Token issued for the current session or a recent session of this RP with the OP.
             * Optionally verify that any sid Logout Token Claim matches the sid Claim in an ID Token issued for the current session or a recent session of this RP with the OP.
             * If any of the validation steps fails, reject the Logout Token and return an HTTP 400 Bad Request error. Otherwise, proceed to perform the logout actions.
             */
            let logout_token = req.body.logout_token;

            //logout_token = jwt.decode(logout_token);
            // validate the logout_token as per spec
            logout_token = await new Promise((resolve, reject) => {
              jwt.verify(
                logout_token,
                getKey,
                {
                  audience: backchannel_config_token.eas.client.client_id,
                  issuer: issuer.issuer,
                },
                (err, decoded) => {
                  if (err) {
                    reject(err);
                  }
                  resolve(decoded);
                }
              );
            });

            server.logger.info(
              "backchannel revoke using logout_token: %j",
              logout_token
            );

            if (!logout_token.hasOwnProperty("iat")) {
              throw new Error("logout_token missing iat claim");
            }

            if (logout_token.iat > Date.now() / 1000) {
              throw new Error("logout_token issued in the future");
            }

            if (!logout_token.hasOwnProperty("events")) {
              throw new Error("logout_token missing events claim");
            }

            if (
              !logout_token.events.hasOwnProperty(
                "http://schemas.openid.net/event/backchannel-logout"
              )
            ) {
              throw new Error(
                'logout_token events claim missing "http://schemas.openid.net/event/backchannel-logout" property'
              );
            }

            if (logout_token.hasOwnProperty("nonce")) {
              throw new Error("logout_token contains nonce claim");
            }

            let backchannel_logout_key = await generate_backchannel_logout_key(
              server,
              logout_token
            );

            let ttl;
            let bc_config;
            if (process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG) {
              bc_config = JSON.parse(process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG);
            }

            // checked forced values
            if (
              typeof ttl === "undefined" &&
              process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG
            ) {
              if (
                bc_config.hasOwnProperty("ttl") &&
                bc_config.ttl.hasOwnProperty("issuers") &&
                bc_config.ttl.issuers.hasOwnProperty(`${issuer.issuer}`) &&
                bc_config.ttl.issuers[issuer.issuer].hasOwnProperty("forced")
              ) {
                ttl = bc_config.ttl.issuers[issuer.issuer].forced;
              }
            }

            if (
              typeof ttl === "undefined" &&
              process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG
            ) {
              if (
                bc_config.hasOwnProperty("ttl") &&
                bc_config.ttl.hasOwnProperty("_fallback") &&
                bc_config.ttl["_fallback"].hasOwnProperty("forced")
              ) {
                ttl = bc_config.ttl["_fallback"].forced;
              }
            }

            if (
              typeof ttl === "undefined" &&
              backchannel_config_token.eas.hasOwnProperty("ttl")
            ) {
              ttl = backchannel_config_token.eas.ttl;
            }

            // checked default values
            if (
              typeof ttl === "undefined" &&
              process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG
            ) {
              if (
                bc_config.hasOwnProperty("ttl") &&
                bc_config.ttl.hasOwnProperty("issuers") &&
                bc_config.ttl.issuers.hasOwnProperty(`${issuer.issuer}`) &&
                bc_config.ttl.issuers[issuer.issuer].hasOwnProperty("default")
              ) {
                ttl = bc_config.ttl.issuers[issuer.issuer].default;
              }

              if (
                bc_config.hasOwnProperty("ttl") &&
                bc_config.ttl.hasOwnProperty("_fallback") &&
                bc_config.ttl["_fallback"].hasOwnProperty("default")
              ) {
                ttl = bc_config.ttl["_fallback"].default;
              }
            }

            if (typeof ttl === "undefined") {
              ttl = BACKCHANNEL_LOGOUT_DEFAULT_TTL;
            }

            server.logger.debug("backchannel_logout ttl: %s", ttl);

            // create a lock entry in the store
            await set_backchannel_logout_data(
              server,
              backchannel_logout_key,
              { iat: Date.now() / 1000, ttl, logout_token },
              ttl
            );

            res.statusCode = 200;
            res.setHeader("Cache-Control", "no-cache, no-store");
            res.setHeader("Pragma", "no-cache");
            res.end();
            return;
          } catch (e) {
            server.logger.error(e);
            res.statusCode = 400;
            res.end();
          }
        } catch (e) {
          server.logger.error(e);
          res.statusCode = 503;
          res.end();
          return;
        }
      });

      initialized = true;
    }
  }

  /**
   * Verify the request
   *
   * @name verify
   * @param {*} configToken
   * @param {*} req
   */
  async verify(configToken, req, res) {
    const plugin = this;
    const store = plugin.server.store;
    const issuer = await plugin.get_issuer();
    const client = await plugin.get_client();
    const pluginStrategy =
      plugin.constructor.name == "OpenIdConnectPlugin" ? "oidc" : "oauth2";
    const PLUGIN_STRATEGY_OAUTH = "oauth";
    const PLUGIN_STRATEGY_OIDC = "oidc";

    /**
     * reconstruct original request info from headers etc
     */
    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    plugin.server.logger.verbose("parent request info: %j", parentReqInfo);

    const configAudMD5 = configToken.audMD5;
    plugin.server.logger.verbose("audMD5: %s", configAudMD5);

    const configCookieName = this.config.cookie.name;
    plugin.server.logger.verbose("cookie name: %s", configCookieName);

    let redirectHttpCode;
    if (!redirectHttpCode && req.query.redirect_http_code) {
      redirectHttpCode = req.query.redirect_http_code;
    }

    const request_is_xhr = plugin.server.utils.request_is_xhr(req);

    if (
      request_is_xhr &&
      !redirectHttpCode &&
      plugin.config.xhr.redirect_http_code
    ) {
      redirectHttpCode = plugin.config.xhr.redirect_http_code;
    }

    if (!redirectHttpCode) {
      redirectHttpCode = 302;
    }

    const authorization_redirect_uri = plugin.get_authorization_redirect_uri(
      parentReqInfo.uri
    );

    const respond_to_failed_authorization = async function () {
      plugin.server.logger.verbose(
        "redirect_uri: %s",
        authorization_redirect_uri
      );

      const payload = {
        request_uri: parentReqInfo.uri,
        aud: configAudMD5,
        csrf: plugin.server.utils.generate_csrf_id(),
        req: {
          headers: {
            referer: req.headers.referer,
          },
        },
        request_is_xhr,
      };
      const stateToken = jwt.sign(payload, issuer_sign_secret);
      const state = plugin.server.utils.encrypt(
        issuer_encrypt_secret,
        stateToken,
        "hex"
      );

      const url = await plugin.get_authorization_url(
        req,
        parentReqInfo,
        authorization_redirect_uri,
        state
      );

      plugin.server.logger.verbose("callback redirect_uri: %s", url);

      switch (redirectHttpCode) {
        case 401:
          res.setHeader(
            "WWW-Authenticate",
            'Bearer realm="' +
              url +
              ', scope="' +
              plugin.config.scopes.join(" ") +
              '"'
          );
        default:
          if (plugin.config.csrf_cookie.enabled) {
            res.cookie(
              STATE_CSRF_COOKIE_NAME,
              plugin.server.utils.encrypt(
                plugin.server.secrets.cookie_encrypt_secret,
                payload.csrf
              ),
              {
                /**
                 * if omitted will be a 'session' cookie
                 */
                expires: new Date(Date.now() + STATE_CSRF_COOKIE_EXPIRY * 1000),

                domain: plugin.config.csrf_cookie.domain,
                path: plugin.config.csrf_cookie.path,
                httpOnly: plugin.config.csrf_cookie.httpOnly, //kills js access
                secure: plugin.config.csrf_cookie.secure,

                /**
                 * None: what Chrome defaults to today without a SameSite value set
                 * Lax: some limits on sending cookies on a cross-origin request
                 * Strict: tight limits on sending cookies on a cross-origin request
                 */
                sameSite: plugin.config.csrf_cookie.sameSite,
                signed: true,
              }
            );
          }

          res.statusCode = redirectHttpCode;
          res.setHeader("Location", url);
          return res;
      }
    };

    /**
     * state should be the decrypted and decoded state token
     *
     *
     * @param {*} req
     * @param {*} res
     * @param {*} state
     */
    const handle_logout_callback_request = async function (
      req,
      res,
      parentReqInfo
    ) {
      const redirectHttpCode = req.query.redirect_http_code
        ? req.query.redirect_http_code
        : 302;

      const configCookieName = plugin.config.cookie.name;
      plugin.server.logger.verbose("cookie name: %s", configCookieName);

      const session_id = req.signedCookies[configCookieName];
      let redirect_uri = parentReqInfo.parsedQuery.redirect_uri || "";
      if (session_id) {
        let sessionPayload = await plugin.get_session_data(session_id);

        if (
          plugin.config.features.logout.revoke_tokens_on_logout &&
          plugin.config.features.logout.revoke_tokens_on_logout.length > 0
        ) {
          try {
            if (!sessionPayload) {
              plugin.server.logger.verbose("failed to retrieve session");
            } else {
              plugin.server.logger.info(
                "attempt to revoke token with authentication service"
              );

              for (const token_type of plugin.config.features.logout
                .revoke_tokens_on_logout) {
                try {
                  if (!sessionPayload.tokenSet[token_type]) {
                    return;
                  }

                  await client.revoke(
                    sessionPayload.tokenSet[token_type],
                    token_type,
                    {
                      revokeBody: {
                        ...handlebars_template_properties(
                          plugin.config.custom_revoke_parameters,
                          { parentReqInfo, req }
                        ),
                      },
                    }
                  );
                } catch (e) {
                  plugin.server.logger.debug(
                    `failed to revoke token ${token_type} with authentication service: ` +
                      e.message
                  );
                }
              }
            }
          } catch (e) {
            plugin.server.logger.debug(
              `failed to revoke tokens with authentication service: ` +
                e.message
            );
          }
        }

        // support oidc end provider session param
        if (
          pluginStrategy == PLUGIN_STRATEGY_OIDC &&
          plugin.config.features.logout.end_provider_session.enabled &&
          sessionPayload.tokenSet &&
          sessionPayload.tokenSet.id_token
        ) {
          let idToken = jwt.decode(sessionPayload.tokenSet.id_token);
          // TODO: this check may not be entirely needed/wanted
          if (idToken.session_state) {
            const payload = {
              redirect_uri: redirect_uri,
              aud: configAudMD5,
              req: {
                headers: {
                  referer: req.headers.referer,
                },
              },
              request_is_xhr,
            };
            const stateToken = jwt.sign(payload, issuer_sign_secret);
            const state = plugin.server.utils.encrypt(
              issuer_encrypt_secret,
              stateToken,
              "hex"
            );

            redirect_uri = await client.endSessionUrl({
              id_token_hint: sessionPayload.tokenSet.id_token,
              post_logout_redirect_uri:
                plugin.config.features.logout.end_provider_session
                  .post_logout_redirect_uri,
              state,
            });
          }
        }

        plugin.server.logger.info("deleting session: %s", session_id);
        await plugin.delete_session(session_id);

        //res.clearCookie(configCookieName);
      } else {
        plugin.server.logger.verbose("no session to delete, moving on");
      }

      plugin.server.logger.info(
        "redirecting after logout to redirect_uri: %s",
        redirect_uri
      );

      res.statusCode = redirectHttpCode;
      res.setHeader("Location", redirect_uri);
      return res;
    };

    /**
     * state should be the decrypted and decoded state token
     *
     *
     * @param {*} req
     * @param {*} res
     * @param {*} state
     */
    const handle_auth_callback_request = async function (
      configToken,
      req,
      res,
      state,
      parentReqInfo
    ) {
      const redirectHttpCode = req.query.redirect_http_code
        ? req.query.redirect_http_code
        : 302;
      plugin.server.logger.verbose("decoded state: %j", state);

      const configAudMD5 = configToken.audMD5;
      plugin.server.logger.verbose("audMD5: %s", configAudMD5);

      const configCookieName = plugin.config.cookie.name;
      plugin.server.logger.verbose("cookie name: %s", configCookieName);

      if (plugin.config.csrf_cookie.enabled) {
        /**
         * check for csrf cookie presense
         */
        if (!req.signedCookies[STATE_CSRF_COOKIE_NAME]) {
          plugin.server.logger.verbose("missing csrf token");
          res.statusCode = 503;
          return res;
        }

        /**
         * validate csrf token
         */
        if (
          state.csrf !=
          plugin.server.utils.decrypt(
            plugin.server.secrets.cookie_encrypt_secret,
            req.signedCookies[STATE_CSRF_COOKIE_NAME]
          )
        ) {
          plugin.server.logger.verbose("mismatched csrf values");
          res.statusCode = 503;
          return res;
        }
      }

      plugin.server.logger.verbose("begin token fetch with authorization code");

      const compare_redirect_uri = plugin.get_authorization_redirect_uri(
        state.request_uri
      );
      plugin.server.logger.verbose(
        "compare_redirect_uri: %s",
        compare_redirect_uri
      );

      let realRedirectUri;
      if (
        plugin.config.xhr.use_referer_as_redirect_uri &&
        state.request_is_xhr &&
        state.req.headers.referer
      ) {
        realRedirectUri = state.req.headers.referer;
      } else {
        realRedirectUri = state.request_uri;
      }

      let tokenSet;
      try {
        tokenSet = await plugin.authorization_code_callback(
          req,
          parentReqInfo,
          compare_redirect_uri
        );
      } catch (e) {
        plugin.server.logger.verbose("failed to retrieve tokens");
        plugin.server.logger.error(e);
        if (plugin.is_redirectable_error(e)) {
          res.statusCode = redirectHttpCode;
          res.setHeader("Location", realRedirectUri);
          return res;
        }

        if (plugin.is_unauthorized_error(e)) {
          res.statusCode = 403;
          return res;
        }

        res.statusCode = 503;
        return res;
      }

      plugin.server.logger.verbose("received and validated tokens");
      plugin.log_token_set(tokenSet);

      const tokenSetValid = await plugin.token_set_assertions(tokenSet);
      if (!tokenSetValid) {
        res.statusCode = 403;
        return res;
      }

      /**
       * only id_token is guaranteed to be a jwt
       */
      let idToken;

      if (tokenSet.id_token) {
        idToken = jwt.decode(tokenSet.id_token);
      }

      //TODO: see if expires_at is access_token or refresh_token, adjust logic accordingly
      let cookieExpiresAt, sessionExpiresAt, tokenExpiresAt;
      if (tokenSet.expires_at) {
        tokenExpiresAt = tokenSet.expires_at * 1000;
      } else if (idToken) {
        if (idToken.exp) {
          tokenExpiresAt = idToken.exp * 1000;
        }
      }

      if (plugin.config.features.cookie_expiry === false) {
        cookieExpiresAt = null;
      } else if (
        plugin.config.features.cookie_expiry !== true &&
        plugin.config.features.cookie_expiry > 0
      ) {
        cookieExpiresAt =
          Date.now() / 1000 + plugin.config.features.cookie_expiry;
        cookieExpiresAt = cookieExpiresAt * 1000;
      } else {
        cookieExpiresAt = tokenExpiresAt;
      }

      if (plugin.config.features.session_expiry === false) {
        sessionExpiresAt = null;
      } else if (
        plugin.config.features.session_expiry !== true &&
        plugin.config.features.session_expiry > 0
      ) {
        sessionExpiresAt =
          Date.now() / 1000 + plugin.config.features.session_expiry;
        sessionExpiresAt = sessionExpiresAt * 1000;
      } else {
        sessionExpiresAt = tokenExpiresAt;
      }

      let sessionPayload = {
        iat: Math.floor(Date.now() / 1000),
        tokenSet,
        aud: configAudMD5,
      };

      let userinfo;
      if (plugin.config.features.fetch_userinfo) {
        userinfo = await plugin.get_userinfo(tokenSet);
        plugin.server.logger.verbose("userinfo %j", userinfo);
        if (userinfo && userinfo.data) {
          sessionPayload.userinfo = userinfo;
        }
      }

      if (plugin.config.assertions.userinfo) {
        const userinfoValid = await plugin.userinfo_assertions(
          sessionPayload.userinfo.data
        );
        if (!userinfoValid) {
          res.statusCode = 403;
          return res;
        }
      }

      let session_id;
      if (
        plugin.config.features.session_retain_id === true &&
        req.signedCookies[configCookieName]
      ) {
        session_id = req.signedCookies[configCookieName];
        plugin.server.logger.verbose("re-creating session: %s", session_id);
      } else {
        session_id = plugin.server.utils.generate_session_id();
        plugin.server.logger.verbose("creating new session: %s", session_id);
      }

      /**
       * backchannel_logout logic
       */
      if (
        pluginStrategy == PLUGIN_STRATEGY_OIDC &&
        (await plugin.get_backchannel_enabled())
      ) {
        let backchannel_logout_key = await generate_backchannel_logout_key(
          plugin.server,
          idToken
        );
        await add_backchannel_logout_authenticated_session(
          plugin.server,
          backchannel_logout_key,
          session_id
        );
      }

      let ttl = null;
      if (sessionExpiresAt) {
        sessionPayload.exp = Math.floor(sessionExpiresAt / 1000);
        ttl = (sessionExpiresAt - Date.now()) / 1000;
      }
      await plugin.save_session(session_id, sessionPayload, ttl);

      res.cookie(configCookieName, session_id, {
        domain: plugin.config.cookie.domain,
        path: plugin.config.cookie.path,
        /**
         * if omitted will be a 'session' cookie
         */
        expires: cookieExpiresAt ? new Date(cookieExpiresAt) : null,
        httpOnly: plugin.config.cookie.httpOnly, //kills js access
        secure: plugin.config.cookie.secure,

        /**
         * None: what Chrome defaults to today without a SameSite value set
         * Lax: some limits on sending cookies on a cross-origin request
         * Strict: tight limits on sending cookies on a cross-origin request
         */
        sameSite: plugin.config.cookie.sameSite,
        signed: true,
      });

      /**
       * remove the csrf cookie
       * NOTE: some servers do not appropriately send the response to the client
       * when multiple Set-Cookie response headers are sent. For example nginx
       * only forwards the first instance and envoy seems to send the last.
       *
       * Commenting out for now as whenever the value is required a new value should
       * be sent by the server anyhow.
       */
      //res.clearCookie(STATE_CSRF_COOKIE_NAME);

      plugin.server.logger.info(
        "redirecting to original resource: %s",
        realRedirectUri
      );

      res.statusCode = redirectHttpCode;
      res.setHeader("Location", realRedirectUri);
      return res;
    };

    /**
     * This handles callback scenarios from the provider (ie: auth succeeded or failed)
     * authenticates provider
     * gathers tokens
     * sends token(s) as encrypted cookie(s)
     * redirects to original requested URI
     *
     */
    switch (parentReqInfo.parsedQuery[HANDLER_INDICATOR_PARAM_NAME]) {
      case "logout":
        return handle_logout_callback_request(req, res, parentReqInfo);
      case "authorization_callback":
        const state = plugin.server.utils.decrypt(
          issuer_encrypt_secret,
          parentReqInfo.parsedQuery.state,
          "hex"
        );
        const decodedState = jwt.verify(state, issuer_sign_secret);
        return handle_auth_callback_request(
          configToken,
          req,
          res,
          decodedState,
          parentReqInfo
        );

      case "verify":
      default:
        /**
         * This should handle 2 broad scenarios:
         *  1. cookie is present and needs to be authenticated (ie: user has already been authed)
         *  2. cookie is not present and user agent needs to be redirected to provider
         */
        const session_id = req.signedCookies[configCookieName];
        if (session_id) {
          plugin.server.logger.verbose("retrieving session: %s", session_id);

          let sessionPayload = await plugin.get_session_data(session_id);
          if (!sessionPayload) {
            plugin.server.logger.verbose("failed to retrieve session");
            return respond_to_failed_authorization();
          }
          let tokenSet = sessionPayload.tokenSet;

          plugin.log_token_set(tokenSet);

          plugin.server.logger.verbose(
            "comparing audience values: session=%s config=%s",
            sessionPayload.aud,
            configAudMD5
          );

          /**
           * assures the session was created by the appropriate configToken
           *
           * TODO: should this be 503 or 401?
           * TODO: clear the cookie?
           */
          if (sessionPayload.aud != configAudMD5) {
            plugin.server.logger.verbose("non-matching audience");
            return respond_to_failed_authorization();
          }

          /**
           * backchannel_logout logic
           */
          if (
            pluginStrategy == PLUGIN_STRATEGY_OIDC &&
            (await plugin.get_backchannel_enabled())
          ) {
            /**
             * only id_token is guaranteed to be a jwt
             */
            const idToken = jwt.decode(tokenSet.id_token);

            let backchannel_logout_key = await generate_backchannel_logout_key(
              plugin.server,
              idToken
            );
            let backchannel_logout_data = await get_backchannel_logout_data(
              plugin.server,
              backchannel_logout_key
            );

            if (
              backchannel_logout_data &&
              !backchannel_logout_data.authenticated_sessions.includes(
                session_id
              )
            ) {
              /**
               * revoke keys (dealing with offline_access logic)
               *
               * Refresh tokens issued without the offline_access property to a
               * session being logged out SHOULD be revoked. Refresh tokens
               * issued with the offline_access property normally SHOULD NOT be
               * revoked. NOTE: An open issue for the specification is whether
               * to define an additional optional parameter in the logout
               * token, probably as a value in the event-specific parameters
               * JSON object, that explicitly signals that offline_access
               * refresh tokens are also to be revoked.
               */
              for (const token_type of [
                "access_token",
                "refresh_token",
                "id_token",
              ]) {
                try {
                  if (!sessionPayload.tokenSet[token_type]) {
                    return;
                  }

                  if (token_type == "refresh_token") {
                    let introspection = await client.introspect(
                      tokenSet[token_type],
                      token_type
                    );

                    if (
                      introspection.scope
                        .split(" ")
                        .includes("offline_access") ||
                      introspection.offline_access == true
                    ) {
                      continue;
                    }
                  }

                  await client.revoke(
                    sessionPayload.tokenSet[token_type],
                    token_type,
                    {
                      revokeBody: {
                        ...handlebars_template_properties(
                          plugin.config.custom_revoke_parameters,
                          { parentReqInfo, req }
                        ),
                      },
                    }
                  );
                } catch (e) {
                  plugin.server.logger.debug(
                    `failed to revoke token ${token_type} with authentication service: ` +
                      e.message
                  );
                }
              }

              // destroy the session
              plugin.server.logger.info("deleting session: %s", session_id);
              await plugin.delete_session(session_id);

              return respond_to_failed_authorization();
            }
          }

          if (
            sessionPayload.exp > 0 &&
            Date.now() / 1000 > sessionPayload.exp
          ) {
            plugin.server.logger.verbose("session has expired");
            store.del(SESSION_CACHE_PREFIX + session_id);
            return respond_to_failed_authorization();
          }

          /**
           * refresh tokenSet
           * NOTE: this process could be getting invoked by several requests resulting
           * in concurrency issues where the refresh_token is no longer valid after the
           * tokenSet has been refreshed by the first one through.  This is alleviated
           * by doing generating an md5 of the session payload before attempting to refresh.
           * If the process fails fresh session data is reloaded and compared against the
           * original md5.  If the values have changed it's assumed another request attempted
           * a refresh and succeeded.
           */
          if (
            tokenset_is_expired(tokenSet) &&
            plugin.config.features.refresh_access_token &&
            tokenset_can_refresh(tokenSet)
          ) {
            /**
             * store md5 *before* attempting refresh to test if failure due to concurrency
             */
            const preSaveSessionMD5 = plugin.server.utils.md5(
              JSON.stringify(sessionPayload)
            );
            try {
              plugin.server.logger.verbose("refreshing tokenSet");
              const originalTokenSet = tokenSet;
              tokenSet = await plugin.refresh_token(
                req,
                parentReqInfo,
                tokenSet
              );
              // If the refreshed tokenset doesn't contain a new refresh token then assume the
              // original one can still be used.
              if (tokenSet.refresh_token === undefined) {
                tokenSet.refresh_token = originalTokenSet.refresh_token;
              }
              sessionPayload.tokenSet = tokenSet;

              let userinfo;
              if (
                plugin.config.features.fetch_userinfo &&
                plugin.config.features.userinfo_expiry === true
              ) {
                plugin.server.logger.verbose("refreshing userinfo");
                userinfo = await plugin.get_userinfo(tokenSet);
                plugin.server.logger.verbose("userinfo %j", userinfo);
                sessionPayload.userinfo = userinfo;
              }

              if (plugin.config.assertions.userinfo) {
                const userinfoValid = await plugin.userinfo_assertions(
                  sessionPayload.userinfo.data
                );
                if (!userinfoValid) {
                  return respond_to_failed_authorization();
                }
              }
              await plugin.update_session(session_id, sessionPayload);
            } catch (e) {
              //TODO: better logic here to detect invalid_grant, etc
              const snooze = (ms) =>
                new Promise((resolve) => setTimeout(resolve, ms));
              await snooze(500);
              sessionPayload = await plugin.get_session_data(session_id);
              tokenSet = sessionPayload.tokenSet;
              const postSaveSessionMD5 = plugin.server.utils.md5(
                JSON.stringify(sessionPayload)
              );
              /**
               * if data is same before *and* after
               */
              if (preSaveSessionMD5 == postSaveSessionMD5) {
                plugin.server.logger.warn("tokenSet not refreshed externally");
                plugin.server.logger.error(e);
                if (plugin.is_redirectable_error(e)) {
                  return respond_to_failed_authorization();
                } else {
                  throw e;
                }
              } else {
                plugin.server.logger.verbose("tokenSet refreshed externally");
              }
            }
          }

          // run tokenSet assertions (including id_token assertions)
          let tokenSetValid;
          tokenSetValid = await plugin.token_set_assertions(
            tokenSet,
            session_id
          );
          if (!tokenSetValid) {
            plugin.server.logger.verbose("tokenSet failed assertions");
            return respond_to_failed_authorization();
          }

          // refresh userinfo if necessary
          if (
            plugin.config.features.fetch_userinfo &&
            plugin.config.features.userinfo_expiry !== true &&
            plugin.config.features.userinfo_expiry > 0 &&
            Date.now() / 1000 >
              sessionPayload.userinfo.iat +
                plugin.config.features.userinfo_expiry
          ) {
            plugin.server.logger.verbose("refreshing expired userinfo");
            let userinfo;
            try {
              userinfo = await plugin.get_userinfo(tokenSet);
              plugin.server.logger.verbose("userinfo %j", userinfo);
              sessionPayload.userinfo = userinfo;

              await plugin.update_session(session_id, sessionPayload);
            } catch (e) {
              plugin.server.logger.warn("failed to retrieve userinfo");
              plugin.server.logger.error(e);
              if (plugin.is_redirectable_error(e)) {
                return respond_to_failed_authorization();
              } else {
                throw e;
              }
            }
          }

          // run assertions on userinfo
          if (plugin.config.assertions.userinfo) {
            const userinfoValid = await plugin.userinfo_assertions(
              sessionPayload.userinfo.data
            );
            if (!userinfoValid) {
              plugin.server.logger.verbose("userinfo failed assertions");
              return respond_to_failed_authorization();
            }
          }

          let now = Date.now() / 1000;
          if (
            plugin.config.features.session_expiry !== true &&
            plugin.config.features.session_expiry > 0 &&
            sessionPayload.exp &&
            plugin.config.features.session_expiry_refresh_window &&
            now >=
              plugin.config.features.session_expiry_refresh_window +
                sessionPayload.exp
          ) {
            await plugin.update_session(session_id, sessionPayload);
          }

          await plugin.prepare_token_headers(res, sessionPayload);
          await plugin.prepare_authentication_data(res, sessionPayload);
          res.statusCode = 200;
          return res;
        } else {
          /**
           * cookie not present, redirect to oidc provider
           */
          return respond_to_failed_authorization();
        }
        break;
    }
  }

  async get_backchannel_enabled() {
    const plugin = this;
    const issuer = await plugin.get_issuer();

    /**
     * https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions
     * the above metions the action should be for the iss and not iss/aud
     * combination, which makes the global config extremely relevant
     */

    let bc_config;
    if (process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG) {
      bc_config = JSON.parse(process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG);
    }

    // checked forced values
    if (process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG) {
      if (
        bc_config.hasOwnProperty("enabled") &&
        bc_config.enabled.hasOwnProperty("issuers") &&
        bc_config.enabled.issuers.hasOwnProperty(`${issuer.issuer}`) &&
        bc_config.enabled.issuers[issuer.issuer].hasOwnProperty("forced")
      ) {
        return Boolean(bc_config.enabled.issuers[issuer.issuer].forced);
      }

      if (
        bc_config.hasOwnProperty("enabled") &&
        bc_config.enabled.hasOwnProperty("_fallback") &&
        bc_config.enabled["_fallback"].hasOwnProperty("forced")
      ) {
        return Boolean(bc_config.enabled["_fallback"].forced);
      }
    }

    // use token value if present
    if (plugin.config.features.logout.backchannel.hasOwnProperty("enabled")) {
      return Boolean(plugin.config.features.logout.backchannel.enabled);
    }

    // checked default values
    if (process.env.EAS_BACKCHANNEL_LOGOUT_CONFIG) {
      if (
        bc_config.hasOwnProperty("enabled") &&
        bc_config.enabled.hasOwnProperty("issuers") &&
        bc_config.enabled.issuers.hasOwnProperty(`${issuer.issuer}`) &&
        bc_config.enabled.issuers[issuer.issuer].hasOwnProperty("default")
      ) {
        return Boolean(bc_config.enabled.issuers[issuer.issuer].default);
      }

      if (
        bc_config.hasOwnProperty("enabled") &&
        bc_config.enabled.hasOwnProperty("_fallback") &&
        bc_config.enabled["_fallback"].hasOwnProperty("default")
      ) {
        return Boolean(bc_config.enabled["_fallback"].default);
      }
    }

    return false;
  }

  async get_session_data(session_id) {
    const plugin = this;
    const store = plugin.server.store;
    plugin.server.logger.verbose("retrieving session: %s", session_id);

    const encryptedSession = await store.get(SESSION_CACHE_PREFIX + session_id);

    plugin.server.logger.verbose(
      "retrieved encrypted session content: %s",
      encryptedSession
    );

    if (!encryptedSession) {
      plugin.server.logger.verbose("failed to decrypt session");
      return false;
    }

    let sessionPayload = plugin.server.utils.decrypt(
      plugin.server.secrets.session_encrypt_secret,
      encryptedSession
    );
    plugin.server.logger.debug("session data: %s", sessionPayload);
    sessionPayload = JSON.parse(sessionPayload);

    return sessionPayload;
  }

  async save_session(session_id, sessionPayload, ttl = null) {
    const plugin = this;
    const store = plugin.server.store;

    await store.set(
      SESSION_CACHE_PREFIX + session_id,
      plugin.server.utils.encrypt(
        plugin.server.secrets.session_encrypt_secret,
        JSON.stringify(sessionPayload)
      ),
      ttl
    );
  }

  async delete_session(session_id) {
    const plugin = this;
    const store = plugin.server.store;
    if (session_id) {
      await store.del(SESSION_CACHE_PREFIX + session_id);
    }
  }

  async update_session(session_id, sessionPayload) {
    const plugin = this;
    const store = plugin.server.store;

    let ttl;
    if (
      plugin.config.features.session_expiry !== true &&
      plugin.config.features.session_expiry > 0
    ) {
      let sessionExpiresAt =
        Date.now() / 1000 + plugin.config.features.session_expiry;
      sessionExpiresAt = sessionExpiresAt * 1000;

      if (sessionExpiresAt) {
        sessionPayload.exp = Math.floor(sessionExpiresAt / 1000);
        ttl = (sessionExpiresAt - Date.now()) / 1000;
      }
      plugin.server.logger.verbose("session TTL: %s", ttl);
    }

    await store.set(
      SESSION_CACHE_PREFIX + session_id,
      plugin.server.utils.encrypt(
        plugin.server.secrets.session_encrypt_secret,
        JSON.stringify(sessionPayload)
      ),
      ttl
    );
  }

  async set_introspection_cache(session_id, introspectionPayload) {
    const plugin = this;
    const store = plugin.server.store;

    if (!session_id) {
      return;
    }

    if (plugin.config.features.introspect_expiry > 0) {
      let ttl = plugin.config.features.introspect_expiry;
      plugin.server.logger.verbose(
        "setting introspection cache with TTL: %s",
        ttl
      );

      await store.set(
        INTROSPECTION_CACHE_PREFIX + session_id,
        plugin.server.utils.encrypt(
          plugin.server.secrets.session_encrypt_secret,
          JSON.stringify(introspectionPayload)
        ),
        ttl
      );
    }
  }

  async get_introspection_cache(session_id) {
    const plugin = this;
    const store = plugin.server.store;

    if (!session_id) {
      return false;
    }

    plugin.server.logger.verbose(
      "retrieving introspection cache: %s",
      session_id
    );

    const encryptedIntrospection = await store.get(
      INTROSPECTION_CACHE_PREFIX + session_id
    );

    plugin.server.logger.verbose(
      "retrieved encrypted introspection content: %s",
      encryptedIntrospection
    );

    if (!encryptedIntrospection) {
      plugin.server.logger.verbose("failed to decrypt introspection");
      return false;
    }

    let introspectionPayload = plugin.server.utils.decrypt(
      plugin.server.secrets.session_encrypt_secret,
      encryptedIntrospection
    );
    plugin.server.logger.debug("introspection data: %s", introspectionPayload);
    introspectionPayload = JSON.parse(introspectionPayload);

    return introspectionPayload;
  }

  async get_state(state_id) {
    const plugin = this;
    const store = plugin.server.store;
    plugin.server.logger.verbose("retrieving state: %s", state_id);

    const encryptedState = await store.get(STATE_CACHE_PREFIX + state_id);

    plugin.server.logger.verbose(
      "retrieved encrypted state content: %s",
      encryptedState
    );

    if (!encryptedState) {
      plugin.server.logger.verbose("failed to decrypt state");
      return false;
    }

    let statePayload = plugin.server.utils.decrypt(
      plugin.server.secrets.session_encrypt_secret,
      encryptedState
    );
    plugin.server.logger.debug("state data: %s", statePayload);
    statePayload = JSON.parse(statePayload);

    return statePayload;
  }

  async save_state(state_id, payload, ttl = null) {
    const plugin = this;
    const store = plugin.server.store;

    await store.set(
      STATE_CACHE_PREFIX + state_id,
      plugin.server.utils.encrypt(
        plugin.server.secrets.session_encrypt_secret,
        JSON.stringify(payload)
      ),
      ttl
    );
  }

  async delete_state(state_id) {
    const plugin = this;
    const store = plugin.server.store;
    if (state_id) {
      await store.del(STATE_CACHE_PREFIX + state_id);
    }
  }

  /**
   * Generate appropriate authorization redirect URI
   *
   * We redirect to the exact same URI as requested (ensures we land at the same
   * place) without the query original query params (prevents overwriting data).
   *
   * @param {*} uri
   */
  get_authorization_redirect_uri(uri) {
    const plugin = this;
    const query = {};

    if (plugin.config.redirect_uri) {
      uri = plugin.config.redirect_uri;
    } else {
      // set this in the /oauth/callback endpoint manually to avoid sending non-standard params to providers
      // ie: okta pukes when it sees this
      query[HANDLER_INDICATOR_PARAM_NAME] = "authorization_callback";
    }

    const parsedURI = URI.parse(uri);
    if (Object.keys(query).length) {
      parsedURI.query = queryString.stringify(query);
    }

    return URI.serialize(parsedURI);
  }

  async prepare_token_headers(res, sessionData) {
    const plugin = this;
    let filtered_service_headers =
      plugin.config.features.filtered_service_headers || [];
    filtered_service_headers = filtered_service_headers.map((value) => {
      return value.toLowerCase();
    });

    if (
      sessionData.tokenSet.id_token &&
      !filtered_service_headers.includes("x-id-token")
    ) {
      res.setHeader("X-Id-Token", sessionData.tokenSet.id_token);
    }

    if (
      sessionData.userinfo &&
      sessionData.userinfo.data &&
      !filtered_service_headers.includes("x-userinfo")
    ) {
      res.setHeader("X-Userinfo", JSON.stringify(sessionData.userinfo.data));
    }

    if (
      sessionData.tokenSet.access_token &&
      !filtered_service_headers.includes("x-access-token")
    ) {
      res.setHeader("X-Access-Token", sessionData.tokenSet.access_token);
    }

    if (
      plugin.config.features.authorization_token &&
      ["id_token", "access_token", "refresh_token"].includes(
        plugin.config.features.authorization_token
      ) &&
      sessionData.tokenSet[plugin.config.features.authorization_token]
    ) {
      res.setHeader(
        "Authorization",
        "Bearer " +
          sessionData.tokenSet[plugin.config.features.authorization_token]
      );
    }
  }

  async prepare_authentication_data(res, sessionData) {
    res.setAuthenticationData({
      userinfo:
        sessionData.userinfo && sessionData.userinfo.data
          ? sessionData.userinfo.data
          : undefined,
      id_token: sessionData.tokenSet.id_token,
      access_token: sessionData.tokenSet.access_token,
      refresh_token: sessionData.tokenSet.refresh_token,
      token_set: sessionData.tokenSet,
    });
  }

  is_redirectable_error(e) {
    if (
      e.error ||
      (e.data && e.data.isResponseError) ||
      (e.name && e.name == "OpenIdConnectError")
    ) {
      if (e.data && e.data.isResponseError) {
        e = e.data.payload;
      }
      switch (e.error) {
        case "invalid_grant":
        case "bad_verification_code":
          return true;
        case "incorrect_client_credentials":
        case "redirect_uri_mismatch":
        default:
          return false;
      }
    }

    return false;
  }

  is_unauthorized_error(e) {
    if (
      e.error ||
      (e.data && e.data.isResponseError) ||
      (e.name && e.name == "OpenIdConnectError")
    ) {
      if (e.data && e.data.isResponseError) {
        e = e.data.payload;
      }
      switch (e.error) {
        case "unauthorized":
        case "access_denied":
          return true;
        default:
          return false;
      }
    }

    return false;
  }

  async access_token_assertions(access_token) {
    const plugin = this;

    return await Assertion.assertSet(
      access_token,
      plugin.config.assertions.access_token
    );
  }

  async id_token_assertions(id_token) {
    const plugin = this;

    return await Assertion.assertSet(
      id_token,
      plugin.config.assertions.id_token
    );
  }

  async userinfo_assertions(userinfo) {
    const plugin = this;

    return await Assertion.assertSet(
      userinfo,
      plugin.config.assertions.userinfo
    );
  }

  async token_set_assertions(tokenSet, session_id = null) {
    const plugin = this;
    const issuer = await plugin.get_issuer();
    const client = await plugin.get_client();

    const pluginStrategy =
      plugin.constructor.name == "OpenIdConnectPlugin" ? "oidc" : "oauth2";
    const PLUGIN_STRATEGY_OAUTH = "oauth";
    const PLUGIN_STRATEGY_OIDC = "oidc";

    /**
     * token aud is the client_id
     */
    if (
      pluginStrategy == PLUGIN_STRATEGY_OIDC &&
      plugin.config.assertions.aud &&
      idToken.aud != plugin.config.client.client_id
    ) {
      return false;
    }

    /**
     * access token is expired and refresh tokens are disabled
     */
    if (
      plugin.config.assertions.exp &&
      tokenset_is_expired(tokenSet) &&
      !(
        plugin.config.features.refresh_access_token &&
        tokenset_can_refresh(tokenSet)
      )
    ) {
      plugin.server.logger.verbose(
        "tokenSet is expired and refresh tokens disabled"
      );
      return false;
    }

    /**
     * both access and refresh tokens are expired and refresh is enabled
     */
    if (
      plugin.config.assertions.exp &&
      tokenset_is_expired(tokenSet) &&
      plugin.config.features.refresh_access_token &&
      !tokenset_can_refresh(tokenSet)
    ) {
      plugin.server.logger.verbose(
        "tokenSet expired and refresh no longer available"
      );
      return false;
    }

    if (
      pluginStrategy == PLUGIN_STRATEGY_OIDC &&
      plugin.config.assertions.nbf &&
      tokenset_is_premature(tokenSet)
    ) {
      plugin.server.logger.verbose("tokenSet is premature");
      return false;
    }

    if (
      pluginStrategy == PLUGIN_STRATEGY_OIDC &&
      plugin.config.assertions.iss
    ) {
      if (!tokenset_issuer_match(tokenSet, issuer.issuer)) {
        plugin.server.logger.verbose("tokenSet has a mismatch issuer");
        return false;
      }
    }

    if (
      pluginStrategy == PLUGIN_STRATEGY_OIDC &&
      plugin.config.features.introspect_access_token &&
      tokenSet.access_token
    ) {
      if (!issuer.introspection_endpoint) {
        plugin.server.logger.error("issuer does not support introspection");
        throw new Error("issuer does not support introspection");
      }

      let response;
      let cacheHit = false;
      if (session_id && plugin.config.features.introspect_expiry > 0) {
        response = await plugin.get_introspection_cache(session_id);
        cacheHit = Boolean(response);
      }

      if (!response) {
        response = await client.introspect(tokenSet.access_token);
      }

      plugin.server.logger.verbose("token introspect details %j", response);
      if (response.active === false) {
        plugin.server.logger.verbose("token no longer active!!!");
        return false;
      }

      if (
        !cacheHit &&
        session_id &&
        plugin.config.features.introspect_expiry > 0
      ) {
        await plugin.set_introspection_cache(session_id, response);
      }
    }

    if (
      pluginStrategy == PLUGIN_STRATEGY_OIDC &&
      plugin.config.assertions.id_token
    ) {
      let idToken;
      idToken = jwt.decode(tokenSet.id_token);
      let idTokenValid = await plugin.id_token_assertions(idToken);
      if (!idTokenValid) {
        return false;
      }
    }

    if (
      pluginStrategy == PLUGIN_STRATEGY_OIDC &&
      plugin.config.assertions.access_token
    ) {
      let accessToken;
      accessToken = jwt.decode(tokenSet.access_token);
      let accessTokenValid = await plugin.access_token_assertions(accessToken);
      if (!accessTokenValid) {
        return false;
      }
    }

    return true;
  }

  log_userinfo(userinfo) {
    const plugin = this;
    plugin.server.logger.verbose("userinfo %j", userinfo);
  }

  log_token_set(tokenSet) {
    const plugin = this;
    if (tokenSet.refresh_token) {
      plugin.server.logger.debug("refresh_token %j", tokenSet.refresh_token);
      try {
        plugin.server.logger.debug(
          "refresh_token decoded %j",
          jwt.decode(tokenSet.refresh_token)
        );
      } catch (e) {}
    }

    if (tokenSet.access_token) {
      plugin.server.logger.debug("access_token %j", tokenSet.access_token);
      try {
        plugin.server.logger.debug(
          "access_token decoded %j",
          jwt.decode(tokenSet.access_token)
        );
      } catch (e) {}
    }

    if (tokenSet.id_token) {
      plugin.server.logger.debug("id_token %j", tokenSet.id_token);
      const idToken = jwt.decode(tokenSet.id_token);
      plugin.server.logger.debug("id_token decoded %j", idToken);
    }
  }

  // #################### common client/issuer methods ####################

  async get_issuer() {
    const plugin = this;
    const cache = plugin.server.cache;

    let issuer;
    let cache_key;

    const discover_url = plugin.config.issuer.discover_url;
    if (discover_url) {
      cache_key = "issuer:" + plugin.server.utils.md5(discover_url);
    } else {
      cache_key =
        "issuer:" +
        plugin.server.utils.md5(JSON.stringify(plugin.config.issuer));
    }

    issuer = cache.get(cache_key);
    if (issuer !== undefined) {
      return issuer;
    }
    issuer = await get_oauth_issuer(plugin.config.issuer);
    await cache.set(cache_key, issuer, ISSUER_CACHE_DURATION);
    return issuer;
  }

  async get_client() {
    const plugin = this;
    const cache = plugin.server.cache;
    const cache_key =
      "client:" + plugin.server.utils.md5(JSON.stringify(plugin.config));
    let client;
    const issuer = await plugin.get_issuer();

    client = cache.get(cache_key);
    if (client !== undefined) {
      return client;
    }

    client = await get_oauth_client(plugin.config.client, issuer);
    client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;

    await cache.set(cache_key, client, CLIENT_CACHE_DURATION);
    return client;
  }

  async get_authorization_url(
    req,
    parentReqInfo,
    authorization_redirect_uri,
    state
  ) {
    const plugin = this;
    const client = await plugin.get_client();

    const url = client.authorizationUrl({
      ...handlebars_template_properties(
        plugin.config.custom_authorization_parameters,
        { parentReqInfo, req }
      ),
      redirect_uri: authorization_redirect_uri,
      scope: plugin.config.scopes.join(" "),
      state: state,
    });

    return url;
  }

  async refresh_token(req, parentReqInfo, tokenSet) {
    const plugin = this;
    const client = await plugin.get_client();

    return client.refresh(tokenSet.refresh_token, {
      exchangeBody: {
        ...handlebars_template_properties(
          plugin.config.custom_refresh_parameters,
          { parentReqInfo, req }
        ),
      },
    });
  }
}

/**
 * https://github.com/lelylan/simple-oauth2
 */
class OauthPlugin extends BaseOauthPlugin {
  /**
   * Create new instance
   *
   * @name constructor
   * @param {*} server
   * @param {*} config
   */
  constructor(server, config) {
    initialize_common_config_options(config);
    super(...arguments);
  }

  async authorization_code_callback(req, parentReqInfo, authorization_redirect_uri) {
    const plugin = this;
    const client = await plugin.get_client();
    const response_type = "code";

    return client.oauthCallback(
      authorization_redirect_uri,
      parentReqInfo.parsedQuery,
      {
        state: parentReqInfo.parsedQuery.state,
        nonce: null,
        response_type,
      },
      {
        exchangeBody: {
          ...handlebars_template_properties(
            plugin.config.custom_authorization_code_parameters,
            { parentReqInfo, req }
          ),
        },
      }
    );
  }

  async get_userinfo(tokenSet) {
    const plugin = this;
    const userinfoConfig = plugin.config.features.userinfo;
    userinfoConfig.config = userinfoConfig.config || {};
    plugin.server.logger.debug("get userinfo with tokenSet: %j", tokenSet);
    let userinfo;

    switch (userinfoConfig.provider) {
      /**
       * `user` scope adds more info
       * `user:email` allows to hit the `GET /user/emails` endpoint and `GET /user/public_emails` endpoint
       *
       * List all of the teams across all of the organizations to which the authenticated user belongs. This method requires user, repo, or read:org scope when authenticating via OAuth.
       * GET /user/teams
       */
      case "github":
        const GITHUB_API_URI = "https://api.github.com";
        const promises = [];
        const results = {};
        let promise;

        const log_repsonse = function (error, response, body) {
          plugin.server.logger.debug("GITHUB ERROR: " + error);
          plugin.server.logger.debug("GITHUB STATUS: " + response.statusCode);
          plugin.server.logger.debug(
            "GITHUB HEADERS: " + JSON.stringify(response.headers)
          );
          plugin.server.logger.debug("GITHUB BODY: " + JSON.stringify(body));
        };

        promise = new Promise(async (resolve) => {
          await new Promise((resolve, reject) => {
            const options = {
              method: "GET",
              url: GITHUB_API_URI + "/user",
              headers: {
                Authorization: "token " + tokenSet.access_token,
                Accept: "application/vnd.github.v3+json",
                "User-Agent": "external-auth-server",
              },
            };
            request(options, function (error, response, body) {
              log_repsonse(...arguments);
              if (response.statusCode == 200) {
                results.userinfo = JSON.parse(body);
                resolve();
              } else {
                reject(body);
              }
            });
          });

          if (userinfoConfig.config.fetch_organizations) {
            await new Promise((resolve, reject) => {
              const options = {
                method: "GET",
                url: results.userinfo.organizations_url,
                headers: {
                  Authorization: "token " + tokenSet.access_token,
                  Accept: "application/vnd.github.v3+json",
                  "User-Agent": "external-auth-server",
                },
              };
              request(options, function (error, response, body) {
                log_repsonse(...arguments);
                if (response.statusCode == 200) {
                  results.organizations = JSON.parse(body);
                  resolve();
                } else {
                  reject(body);
                }
              });
            });
          }

          resolve();
        });
        promises.push(promise);

        if (userinfoConfig.config.fetch_teams) {
          promise = new Promise((resolve, reject) => {
            /**
             * https://developer.github.com/v3/teams/#list-user-teams
             */
            const options = {
              method: "GET",
              url: "https://api.github.com/user/teams",
              headers: {
                Authorization: "token " + tokenSet.access_token,
                Accept: "application/vnd.github.v3+json",
                "User-Agent": "external-auth-server",
              },
            };
            request(options, function (error, response, body) {
              log_repsonse(...arguments);
              if (response.statusCode == 200) {
                results.teams = JSON.parse(body);
                resolve();
              } else {
                reject(body);
              }
            });
          });
          promises.push(promise);
        }

        if (userinfoConfig.config.fetch_emails) {
          promise = new Promise((resolve, reject) => {
            /**
             * https://developer.github.com/v3/users/emails/
             */
            const options = {
              method: "GET",
              url: "https://api.github.com/user/emails",
              headers: {
                Authorization: "token " + tokenSet.access_token,
                Accept: "application/vnd.github.v3+json",
                "User-Agent": "external-auth-server",
              },
            };
            request(options, function (error, response, body) {
              log_repsonse(...arguments);
              if (response.statusCode == 200) {
                results.emails = JSON.parse(body);
                resolve();
              } else {
                reject(body);
              }
            });
          });
          promises.push(promise);
        }

        await Promise.all(promises);

        userinfo = results.userinfo;

        if (results.organizations) {
          userinfo.organizations = results.organizations;
        }

        if (results.teams) {
          userinfo.teams = results.teams;
        }

        if (results.emails) {
          userinfo.emails = results.emails;
        }

        break;
      default:
        return;
    }

    return { iat: Math.floor(Date.now() / 1000), data: userinfo };
  }
}

class OpenIdConnectPlugin extends BaseOauthPlugin {
  /**
   * Create new instance
   *
   * @name constructor
   * @param {*} config
   */
  constructor(server, config) {
    initialize_common_config_options(config);

    if (!config.features.hasOwnProperty("introspect_access_token")) {
      config.features.introspect_access_token = false;
    }

    if (!config.assertions.hasOwnProperty("exp")) {
      config.assertions.exp = true;
    }

    if (!config.assertions.hasOwnProperty("nbf")) {
      config.assertions.nbf = true;
    }

    if (!config.assertions.hasOwnProperty("iss")) {
      config.assertions.iss = true;
    }

    super(...arguments);
  }

  async authorization_code_callback(req, parentReqInfo, authorization_redirect_uri) {
    const plugin = this;
    const client = await plugin.get_client();
    const response_type = "code";

    return client.callback(
      authorization_redirect_uri,
      parentReqInfo.parsedQuery,
      {
        state: parentReqInfo.parsedQuery.state,
        nonce: null,
        response_type,
      },
      {
        exchangeBody: {
          ...handlebars_template_properties(
            plugin.config.custom_authorization_code_parameters,
            { parentReqInfo, req }
          ),
        },
      }
    );
  }

  async get_userinfo(tokenSet) {
    const plugin = this;
    plugin.server.logger.debug("get userinfo with tokenSet: %j", tokenSet);

    const client = await plugin.get_client();
    const userinfo = await client.userinfo(tokenSet.access_token);
    return { iat: Math.floor(Date.now() / 1000), data: userinfo };
  }
}

module.exports = {
  OauthPlugin,
  OpenIdConnectPlugin,
};
