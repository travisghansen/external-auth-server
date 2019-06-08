const { Assertion } = require("../../assertion");
const { BasePlugin } = require("../../plugin");
const { Issuer } = require("openid-client");
const jwt = require("jsonwebtoken");
const oauth2 = require("simple-oauth2");
const queryString = require("query-string");
const request = require("request");
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

class BaseOauthPlugin extends BasePlugin {
  static initialize(server) {
    if (!initialized) {
      server.WebServer.get("/oauth/callback", (req, res) => {
        server.logger.silly("%j", {
          headers: req.headers,
          body: req.body
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
          parsedRedirectURI.query = parsedRequestURI.query;
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
    plugin.server.logger.verbose("cooking name: %s", configCookieName);

    const redirectHttpCode = req.query.redirect_http_code
      ? req.query.redirect_http_code
      : 302;

    const authorization_redirect_uri = plugin.get_authorization_redirect_uri(
      parentReqInfo.uri
    );

    const respond_to_failed_authorization = async function() {
      plugin.server.logger.verbose(
        "redirect_uri: %s",
        authorization_redirect_uri
      );
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

      plugin.server.logger.verbose("callback redirect_uri: %s", url);

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
      plugin.server.logger.verbose("decoded state: %j", state);

      const configAudMD5 = configToken.audMD5;
      plugin.server.logger.verbose("audMD5: %s", configAudMD5);

      const configCookieName = plugin.config.cookie.name;
      plugin.server.logger.verbose("cooking name: %s", configCookieName);

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

      plugin.server.logger.verbose("begin token fetch with authorization code");

      const compare_redirect_uri = plugin.get_authorization_redirect_uri(
        state.request_uri
      );
      plugin.server.logger.verbose(
        "compare_redirect_uri: %s",
        compare_redirect_uri
      );
      let tokenSet;
      try {
        tokenSet = await plugin.authorization_code_callback(
          parentReqInfo,
          compare_redirect_uri
        );
      } catch (e) {
        plugin.server.logger.error(e);
        if (plugin.is_redirectable_error(e)) {
          res.statusCode = redirectHttpCode;
          res.setHeader("Location", state.request_uri);
          return res;
        }

        res.statusCode = 503;
        return res;
      }

      plugin.server.logger.verbose("received and validated tokens");
      plugin.log_token_set(tokenSet);

      const tokenSetValid = await plugin.token_set_asertions(tokenSet);
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
          Date.now() / 1000 + plugin.config.features.session_expiry;
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
        aud: configAudMD5
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
        httpOnly: true, //kills js access
        signed: true
      });

      /**
       * remove the csrf cookie
       */
      res.clearCookie(STATE_CSRF_COOKIE_NAME);

      plugin.server.logger.info(
        "redirecting to original resource: %s",
        state.request_uri
      );

      res.statusCode = redirectHttpCode;
      res.setHeader("Location", state.request_uri);
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
              tokenSet = await plugin.refresh_token(tokenSet);
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
              const snooze = ms =>
                new Promise(resolve => setTimeout(resolve, ms));
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
          tokenSetValid = await plugin.token_set_asertions(tokenSet);
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

    if (plugin.config.redirect_uri) {
      uri = plugin.config.redirect_uri;
    }

    const parsedURI = URI.parse(uri);
    parsedURI.query = queryString.stringify(query);

    return URI.serialize(parsedURI);
  }

  async prepare_token_headers(res, sessionData) {
    const plugin = this;

    if (sessionData.tokenSet.id_token) {
      res.setHeader("X-Id-Token", sessionData.tokenSet.id_token);
    }

    if (sessionData.userinfo.data) {
      res.setHeader("X-Userinfo", JSON.stringify(sessionData.userinfo.data));
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

  async prepare_authentication_data(res, sessionData) {
    res.setAuthenticationData({
      userinfo: sessionData.userinfo.data,
      id_token: sessionData.tokenSet.id_token,
      access_token: sessionData.tokenSet.access_token,
      refresh_token: sessionData.tokenSet.refresh_token
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

  async token_set_asertions(tokenSet) {
    const plugin = this;
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
      const issuer = await plugin.get_issuer();
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
      const issuer = await plugin.get_issuer();

      if (!issuer.metadata.token_introspection_endpoint) {
        plugin.server.logger.error("issuer does not support introspection");
        throw new Error("issuer does not support introspection");
      }

      const response = await client.introspect(tokenSet.access_token);

      plugin.server.logger.verbose("token introspect details %j", response);
      if (response.active === false) {
        plugin.server.logger.verbose("token no longer active!!!");
        return false;
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
      const idToken = jwt.decode(tokenSet.id_token);
      plugin.server.logger.debug("id_token %j", idToken);
    }
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

    //config.scopes = [];

    super(...arguments);
  }

  async get_client() {
    const plugin = this;

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

        const log_repsonse = function(error, response, body) {
          plugin.server.logger.debug("GITHUB ERROR: " + error);
          plugin.server.logger.debug("GITHUB STATUS: " + response.statusCode);
          plugin.server.logger.debug(
            "GITHUB HEADERS: " + JSON.stringify(response.headers)
          );
          plugin.server.logger.debug("GITHUB BODY: " + JSON.stringify(body));
        };

        promise = new Promise(async resolve => {
          await new Promise((resolve, reject) => {
            const options = {
              method: "GET",
              url: GITHUB_API_URI + "/user",
              headers: {
                Authorization: "token " + tokenSet.access_token,
                Accept: "application/vnd.github.v3+json",
                "User-Agent": "external-auth-server"
              }
            };
            request(options, function(error, response, body) {
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
                  "User-Agent": "external-auth-server"
                }
              };
              request(options, function(error, response, body) {
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
                "User-Agent": "external-auth-server"
              }
            };
            request(options, function(error, response, body) {
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
                "User-Agent": "external-auth-server"
              }
            };
            request(options, function(error, response, body) {
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

  async authorization_code_callback(parentReqInfo, authorization_redirect_uri) {
    const plugin = this;
    const client = await plugin.get_client();
    const tokenConfig = {
      code: parentReqInfo.parsedQuery.code,
      redirect_uri: authorization_redirect_uri,
      scope: plugin.config.scopes.join(" ")
    };

    plugin.server.logger.verbose("tokenConfig: %j", tokenConfig);

    const result = await client.authorizationCode.getToken(tokenConfig);
    plugin.server.logger.debug("oauth code result: %j", result);
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

    if (!config.features.hasOwnProperty("cookie_expiry")) {
      config.features.cookie_expiry = false;
    }

    if (!config.features.hasOwnProperty("userinfo_expiry")) {
      config.features.userinfo_expiry = true;
    }

    if (!config.features.hasOwnProperty("session_expiry")) {
      config.features.session_expiry = true;
    }

    if (!config.features.hasOwnProperty("session_retain_id")) {
      config.features.session_retain_id = true;
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
      plugin.server.logger.verbose(
        "manual issuer %s %O",
        issuer.issuer,
        issuer.metadata
      );
      cache.set(cache_key, issuer, ISSUER_CACHE_DURATION);
      return issuer;
    }
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
  OpenIdConnectPlugin
};
