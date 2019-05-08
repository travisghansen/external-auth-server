const { BasePlugin } = require("../../plugin");
const { Issuer } = require("openid-client");
const jwt = require("jsonwebtoken");
const oauth2 = require("simple-oauth2");
const queryString = require("query-string");
const URI = require("uri-js");

Issuer.useRequest();
Issuer.defaultHttpOptions = { timeout: 10000, headers: {} };

const exit_failure = function(message = "", code = 1) {
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
const DEFAULT_COOKIE_NAME = "_eas_oauth_session";

const HANDLER_INDICATOR_PARAM_NAME = "__eas_oauth_handler__";
const STATE_CSRF_COOKIE_NAME = "_eas_oauth_csrf";
const STATE_CSRF_COOKIE_EXPIRY = "43200"; //12 hours
const DEFAULT_CLIENT_CLOCK_TOLERANCE = 5;
const ISSUER_CACHE_DURATION = 43200 * 1000;
const CLIENT_CACHE_DURATION = 43200 * 1000;

let initialized = false;

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

class BaseOauthPlugin extends BasePlugin {
  static initialize(server) {
    if (!initialized) {
      server.WebServer.get("/oauth/callback", (req, res) => {
        //console.log(req);

        try {
          let state = server.utils.decrypt(
            issuer_encrypt_secret,
            req.query.state,
            "hex"
          );
          state = jwt.verify(state, issuer_sign_secret);
          const state_redirect_uri = state.request_uri;

          const parsedStateRedirectURI = URI.parse(state_redirect_uri);
          console.log("parsed state redirect uri: %j", parsedStateRedirectURI);

          const parsedRequestURI = URI.parse(req.url);
          console.log("parsed request uri: %j", parsedRequestURI);

          const parsedRedirectURI = Object.assign({}, parsedStateRedirectURI);
          parsedRedirectURI.query = parsedRequestURI.query;
          console.log("parsed redirect uri: %j", parsedRedirectURI);

          const redirect_uri = URI.serialize(parsedRedirectURI);
          console.log("redirecting browser to: %j", redirect_uri);

          res.statusCode = 302;
          res.setHeader("Location", redirect_uri);
          res.end();
          return;
        } catch (e) {
          console.log("/oauth/callback error: ", e);
          res.statusCode = 503;
          res.end();
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
    const client = await plugin.get_client();
    const pluginStrategy =
      plugin.constructor.name == "OpenIdPlugin" ? "oidc" : "oauth2";
    const PLUGIN_STRATEGY_OAUTH = "oauth";
    const PLUGIN_STRATEGY_OIDC = "oidc";

    /**
     * reconstruct original request info from headers etc
     */
    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    console.log("parent request info: %j", parentReqInfo);

    const configAudMD5 = configToken.audMD5;
    console.log("audMD5: %s", configAudMD5);

    const configCookieName = this.config.cookie.name;
    console.log("cooking name: %s", configCookieName);

    const redirectHttpCode = req.query.redirect_http_code
      ? req.query.redirect_http_code
      : 302;

    const authorization_redirect_uri = plugin.get_authorization_redirect_uri(
      parentReqInfo.uri
    );

    const respond_to_failed_authorization = async function() {
      console.log("redirect_uri: %s", authorization_redirect_uri);
      const payload = {
        request_uri: parentReqInfo.uri,
        aud: configAudMD5,
        csrf: plugin.server.utils.generate_csrf_id()
      };
      const stateToken = jwt.sign(payload, issuer_sign_secret);
      const state = plugin.server.utils.encrypt(
        issuer_encrypt_secret,
        stateToken,
        "hex"
      );

      const url = await plugin.get_authorization_url(
        authorization_redirect_uri,
        state
      );

      console.log("callback redirect_uri: %s", url);

      switch (redirectHttpCode) {
        case 401:
          res.setHeader(
            "WWW-Authenticate",
            'Bearer realm="' +
              authorization_redirect_uri +
              ', scope="' +
              plugin.config.scopes.join(" ") +
              '"'
          );
        default:
          res.cookie(
            STATE_CSRF_COOKIE_NAME,
            plugin.server.utils.encrypt(
              plugin.server.secrets.cookie_encrypt_secret,
              payload.csrf
            ),
            {
              expires: new Date(Date.now() + STATE_CSRF_COOKIE_EXPIRY * 1000),
              httpOnly: true, //kills js access
              signed: true
            }
          );
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
    const handle_auth_callback_request = async function(
      configToken,
      req,
      res,
      state,
      parentReqInfo
    ) {
      const redirectHttpCode = req.query.redirect_http_code
        ? req.query.redirect_http_code
        : 302;
      console.log("decoded state: %j", state);

      const configAudMD5 = configToken.audMD5;
      console.log("audMD5: %s", configAudMD5);

      const configCookieName = plugin.config.cookie.name;
      console.log("cooking name: %s", configCookieName);

      /**
       * check for csrf cookie presense
       */
      if (!req.signedCookies[STATE_CSRF_COOKIE_NAME]) {
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
        res.statusCode = 503;
        return res;
      }

      console.log("begin token fetch with authorization code");

      const compare_redirect_uri = plugin.get_authorization_redirect_uri(
        state.request_uri
      );
      console.log("compare_redirect_uri: %s", compare_redirect_uri);
      let tokenSet;
      try {
        tokenSet = await plugin.authorization_code_callback(
          parentReqInfo,
          compare_redirect_uri
        );
      } catch (e) {
        console.log(e);
        if (e.data.isResponseError) {
          e = e.data.payload;
          switch (e.error) {
            case "invalid_grant":
            case "bad_verification_code":
              res.statusCode = redirectHttpCode;
              res.setHeader("Location", state.request_uri);
              return res;
            case "incorrect_client_credentials":
            case "redirect_uri_mismatch":
            default:
              res.statusCode = 503;
              return res;
          }
        }

        if (e.name) {
          switch (e.name) {
            case "OpenIdConnectError":
              switch (e.error) {
                case "invalid_grant":
                  res.statusCode = redirectHttpCode;
                  res.setHeader("Location", state.request_uri);
                  return res;
              }
              break;
          }

          res.statusCode = 503;
          res.statusMessage = e.error_description;
          return res;
        }

        res.statusCode = 503;
        return res;
      }

      const session_id = plugin.server.utils.generate_session_id();
      console.log("creating new session: %s", session_id);
      console.log("received and validated tokens %j", tokenSet);
      console.log("validated id_token claims %j", tokenSet.claims);

      /**
       * only id_token is guaranteed to be a jwt
       */
      let idToken;
      if (tokenSet.refresh_token) {
        console.log("refresh_token %j", tokenSet.refresh_token);
      }

      if (tokenSet.access_token) {
        console.log("access_token %j", tokenSet.access_token);
      }

      if (tokenSet.id_token) {
        idToken = jwt.decode(tokenSet.id_token);
        console.log("id_token %j", idToken);
      }

      let tokenExpiresAt, cookieExpiresAt;
      if (tokenSet.expires_at) {
        tokenExpiresAt = tokenSet.expires_at * 1000;
      } else if (idToken) {
        if (idToken.exp) {
          tokenExpiresAt = idToken.exp * 1000;
        }
      }

      let promise;
      let sessionPayload = {
        tokenSet,
        aud: configAudMD5
      };

      const promises = [];

      if (
        pluginStrategy == PLUGIN_STRATEGY_OIDC &&
        plugin.config.features.fetch_userinfo
      ) {
        promise = client
          .userinfo(tokenSet)
          .then(userinfo => {
            console.log("userinfo %j", userinfo);
            sessionPayload.userinfo = userinfo;
          })
          .catch(e => {
            console.log(e);
            res.statusCode = 503;
          });

        promises.push(promise);
      }

      return Promise.all(promises)
        .then(() => {
          /**
           * seconds to keep backend cache
           */
          const ttl = (tokenExpiresAt - Date.now()) / 1000;
          return store.set(
            SESSION_CACHE_PREFIX + session_id,
            plugin.server.utils.encrypt(
              plugin.server.secrets.session_encrypt_secret,
              JSON.stringify(sessionPayload)
            ),
            ttl
          );
        })
        .then(() => {
          /**
           * set expiry if enabled
           */
          if (plugin.config.features.set_cookie_expiry) {
            cookieExpiresAt = tokenExpiresAt;
          } else {
            cookieExpiresAt = null;
          }

          res.cookie(configCookieName, session_id, {
            domain: plugin.config.cookie.domain,
            path: plugin.config.cookie.path,
            /**
             * if omitted will be a 'session' cookie
             */
            expires: cookieExpiresAt ? new Date(cookieExpiresAt) : null,
            httpOnly: true, //kills js access
            signed: true
          });

          /**
           * remove the csrf cookie
           */
          res.clearCookie(STATE_CSRF_COOKIE_NAME);

          console.log(
            "redirecting to original resource: %s",
            state.request_uri
          );

          res.statusCode = redirectHttpCode;
          res.setHeader("Location", state.request_uri);
          return res;
        })
        .catch(e => {
          console.log(e);
          res.statusCode = 503;
          return res;
        });
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
          console.log("retrieving session: %s", session_id);

          const encryptedSession = await store.get(
            SESSION_CACHE_PREFIX + session_id
          );

          console.log(
            "retrieved encrypted session content: %s",
            encryptedSession
          );

          if (!encryptedSession) {
            return respond_to_failed_authorization();
          }

          let sessionPayload = plugin.server.utils.decrypt(
            plugin.server.secrets.session_encrypt_secret,
            encryptedSession
          );
          console.log("session data: %s", sessionPayload);
          sessionPayload = JSON.parse(sessionPayload);
          const tokenSet = sessionPayload.tokenSet;

          /**
           * only id_token is guaranteed to be a jwt
           */
          let idToken;
          if (tokenSet.refresh_token) {
            console.log("refresh_token %j", tokenSet.refresh_token);
          }

          if (tokenSet.access_token) {
            console.log("access_token %j", tokenSet.access_token);
          }

          if (tokenSet.id_token) {
            idToken = jwt.decode(tokenSet.id_token);
            console.log("id_token %j", idToken);
          }

          console.log(
            "comparing audience values: session=%s config=%s",
            sessionPayload.aud,
            configAudMD5
          );

          //console.log('tokenSet#expired()', tokenSet.expired());
          //console.log('tokenSet#claims', tokenSet.claims);

          /**
           * assures the session was created by the appropriate configToken
           *
           * TODO: should this be 503 or 401?
           * TODO: clear the cookie?
           */
          if (sessionPayload.aud != configAudMD5) {
            return respond_to_failed_authorization();
          }

          /**
           * token aud is the client_id
           */
          if (
            pluginStrategy == PLUGIN_STRATEGY_OIDC &&
            plugin.config.assertions.aud &&
            idToken.aud != plugin.config.client.client_id
          ) {
            return respond_to_failed_authorization();
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
            console.log("tokenSet is expired and refresh tokens disabled");
            return respond_to_failed_authorization();
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
            console.log("tokenSet expired and refresh no longer available");
            return respond_to_failed_authorization();
          }

          if (
            pluginStrategy == PLUGIN_STRATEGY_OIDC &&
            plugin.config.assertions.nbf &&
            tokenset_is_premature(tokenSet)
          ) {
            console.log("tokenSet is premature");
            return respond_to_failed_authorization();
          }

          const promises = [];
          let promise;

          if (
            pluginStrategy == PLUGIN_STRATEGY_OIDC &&
            plugin.config.assertions.iss
          ) {
            promise = new Promise((resolve, reject) => {
              plugin
                .get_issuer()
                .then(issuer => {
                  if (tokenset_issuer_match(tokenSet, issuer.issuer)) {
                    resolve();
                  } else {
                    console.log("tokenSet issuer mismatch");
                    reject("issuer mismatch");
                  }
                })
                .catch(e => {
                  reject(e);
                });
            });
            promises.push(promise);
          }

          if (
            pluginStrategy == PLUGIN_STRATEGY_OIDC &&
            plugin.config.features.introspect_access_token &&
            tokenSet.access_token
          ) {
            promise = new Promise((resolve, reject) => {
              plugin
                .get_issuer()
                .then(issuer => {
                  if (!issuer.metadata.token_introspection_endpoint) {
                    reject("issuer does not support introspection");
                  }

                  return client.introspect(
                    sessionPayload.tokenSet.access_token
                  );
                })
                .then(response => {
                  console.log("token introspect details %j", response);
                  if (response.active === false) {
                    console.log("token no longer active!!!");
                    reject();
                  }
                  resolve();
                })
                .catch(e => {
                  reject(e);
                });
            });
            promises.push(promise);
          }

          if (
            tokenset_is_expired(tokenSet) &&
            plugin.config.features.refresh_access_token &&
            tokenset_can_refresh(tokenSet)
          ) {
            promise = new Promise((resolve, reject) => {
              plugin
                .refresh_token(tokenSet)
                .then(tokenSet => {
                  sessionPayload.tokenSet = tokenSet;
                  if (
                    pluginStrategy == PLUGIN_STRATEGY_OIDC &&
                    plugin.config.features.fetch_userinfo
                  ) {
                    client.userinfo(tokenSet).then(userinfo => {
                      console.log("userinfo %j", userinfo);
                      sessionPayload.userinfo = userinfo;
                      resolve();
                    });
                  } else {
                    resolve();
                  }
                })
                .catch(e => {
                  reject(e);
                });
            })
              .then(() => {
                return new Promise(resolve => {
                  store
                    .set(
                      SESSION_CACHE_PREFIX + session_id,
                      plugin.server.utils.encrypt(
                        plugin.server.secrets.session_encrypt_secret,
                        JSON.stringify(sessionPayload)
                      )
                    )
                    .then(() => {
                      resolve();
                    })
                    .catch(e => {
                      console.log(e);
                      res.statusCode = 503;
                    });
                });
              })
              .catch(e => {
                console.log(e);
                res.statusCode = 503;
              });

            promises.push(promise);
          }

          return Promise.all(promises).then(() => {
            plugin.prepare_token_headers(res, sessionPayload);
            res.statusCode = 200;
            return res;
          });
        } else {
          /**
           * cookie not present, redirect to oidc provider
           */
          return respond_to_failed_authorization();
        }
        break;
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
    query[HANDLER_INDICATOR_PARAM_NAME] = "authorization_callback";

    console.log(HANDLER_INDICATOR_PARAM_NAME);

    if (plugin.config.redirect_uri) {
      uri = plugin.config.redirect_uri;
    }

    const parsedURI = URI.parse(uri);
    parsedURI.query = queryString.stringify(query);

    return URI.serialize(parsedURI);
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
   * @param {*} config
   */
  constructor(server, config) {
    if (!config.cookie) {
      config.cookie = {};
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

    if (!config.features) {
      config.features = {};
    }

    if (!config.assertions) {
      config.assertions = {};
    }

    if (!config.features.hasOwnProperty("set_cookie_expiry")) {
      config.features.set_cookie_expiry = false;
    }

    if (!config.features.hasOwnProperty("refresh_access_token")) {
      config.features.refresh_access_token = true;
    }

    //config.scopes = [];

    super(...arguments);
  }

  prepare_token_headers(res, sessionData) {
    const plugin = this;
    if (sessionData.tokenSet.access_token) {
      res.setHeader("X-Access-Token", sessionData.tokenSet.access_token);
    }

    if (
      plugin.config.features.authorization_token &&
      ["access_token", "refresh_token"].includes(
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

  async get_client() {
    const plugin = this;
    console.log("client config %j", plugin.config);

    const credentials = {
      client: {
        id: plugin.config.client.client_id,
        secret: plugin.config.client.client_secret
      },
      auth: {}
    };

    let tokenHost, tokenPath, authorizeHost, authorizePath;
    if (plugin.config.issuer.token_endpoint) {
      let parsedTokenURI = URI.parse(plugin.config.issuer.token_endpoint);
      tokenHost = URI.serialize({
        scheme: parsedTokenURI.scheme,
        host: parsedTokenURI.host,
        port: parsedTokenURI.port
      }).replace(/\/$/, "");
      tokenPath = parsedTokenURI.path;
    }

    if (plugin.config.issuer.authorization_endpoint) {
      let parsedAuthorizeURI = URI.parse(
        plugin.config.issuer.authorization_endpoint
      );
      authorizeHost = URI.serialize({
        scheme: parsedAuthorizeURI.scheme,
        host: parsedAuthorizeURI.host,
        port: parsedAuthorizeURI.port
      }).replace(/\/$/, "");
      authorizePath = parsedAuthorizeURI.path;
    }

    credentials.auth.tokenHost = tokenHost;
    credentials.auth.tokenPath = tokenPath;
    credentials.auth.authorizeHost = authorizeHost;
    credentials.auth.authorizePath = authorizePath;

    return oauth2.create(credentials);
  }

  async get_authorization_url(authorization_redirect_uri, state) {
    const plugin = this;
    const client = await plugin.get_client();
    const url = client.authorizationCode.authorizeURL({
      redirect_uri: authorization_redirect_uri,
      scope: plugin.config.scopes.join(" "),
      state: state
    });

    return url;
  }

  async refresh_token(tokenSet) {
    const plugin = this;
    const client = await plugin.get_client();
    let accessToken = client.accessToken.create(tokenSet);

    return accessToken.refresh();
  }

  async authorization_code_callback(parentReqInfo, authorization_redirect_uri) {
    const plugin = this;
    const client = await plugin.get_client();
    const tokenConfig = {
      code: parentReqInfo.parsedQuery.code,
      redirect_uri: authorization_redirect_uri,
      scope: plugin.config.scopes.join(" ")
    };

    console.log("tokenConfig: %j", tokenConfig);

    const result = await client.authorizationCode.getToken(tokenConfig);
    console.log("oauth code result: %j", result);
    if (result.error) {
      throw result;
    }
    const accessToken = client.accessToken.create(result);
    return accessToken.token;
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
    if (!config.cookie) {
      config.cookie = {};
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

    if (!config.features) {
      config.features = {};
    }

    if (!config.assertions) {
      config.assertions = {};
    }

    if (!config.features.hasOwnProperty("set_cookie_expiry")) {
      config.features.set_cookie_expiry = false;
    }

    if (!config.features.hasOwnProperty("refresh_access_token")) {
      config.features.refresh_access_token = true;
    }

    if (!config.features.hasOwnProperty("fetch_userinfo")) {
      config.features.fetch_userinfo = true;
    }

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

  prepare_token_headers(res, sessionData) {
    const plugin = this;
    if (sessionData.tokenSet.id_token) {
      res.setHeader("X-Id-Token", sessionData.tokenSet.id_token);
    }

    if (sessionData.userinfo) {
      res.setHeader("X-Userinfo", JSON.stringify(sessionData.userinfo));
    }

    if (sessionData.tokenSet.access_token) {
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

  async get_issuer() {
    const plugin = this;
    const cache = plugin.server.cache;
    const discover_url = plugin.config.issuer.discover_url;
    const cache_key = "issuer:" + plugin.server.utils.md5(discover_url);
    let issuer;
    issuer = cache.get(cache_key);
    if (issuer !== undefined) {
      return issuer;
    }

    if (discover_url) {
      issuer = await Issuer.discover(discover_url);
      cache.set(cache_key, issuer, ISSUER_CACHE_DURATION);
      return issuer;
    } else {
      issuer = new Issuer(plugin.config.issuer);
      console.log("manual issuer %s %O", issuer.issuer, issuer.metadata);
      cache.set(cache_key, issuer, ISSUER_CACHE_DURATION);
      return issuer;
    }
  }

  async get_client() {
    const plugin = this;
    const cache = plugin.server.cache;
    console.log("client config %j", plugin.config);
    const cache_key =
      "client:" + plugin.server.utils.md5(JSON.stringify(plugin.config));
    let client;
    const issuer = await plugin.get_issuer();

    client = cache.get(cache_key);
    if (client !== undefined) {
      return client;
    }

    if (plugin.config.client.client_id && plugin.config.client.client_secret) {
      client = new issuer.Client({
        client_id: plugin.config.client.client_id,
        client_secret: plugin.config.client.client_secret
      });
      client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;

      cache.set(cache_key, client, CLIENT_CACHE_DURATION);
      return client;
    } else if (
      plugin.config.client.registration_client_uri &&
      plugin.config.client.registration_access_token
    ) {
      client = await issuer.Client.fromUri(
        plugin.config.issuer.registration_client_uri,
        plugin.config.issuer.registration_access_token
      );

      client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;
      cache.set(cache_key, client, CLIENT_CACHE_DURATION);
      return client;
    } else {
      throw new Error("invalid client configuration");
    }
  }

  async get_authorization_url(authorization_redirect_uri, state) {
    const plugin = this;
    const client = await plugin.get_client();

    const url = client.authorizationUrl({
      redirect_uri: authorization_redirect_uri,
      scope: plugin.config.scopes.join(" "),
      state: state
    });

    return url;
  }

  async refresh_token(tokenSet) {
    const plugin = this;
    const client = await plugin.get_client();

    return client.refresh(tokenSet.refresh_token);
  }

  async authorization_code_callback(parentReqInfo, authorization_redirect_uri) {
    const plugin = this;
    const client = await plugin.get_client();
    const response_type = "code";

    return client.authorizationCallback(
      authorization_redirect_uri,
      parentReqInfo.parsedQuery,
      {
        state: parentReqInfo.parsedQuery.state,
        response_type
      }
    );
  }
}

module.exports = {
  OauthPlugin,
  OpenIdConnectPlugin
};
