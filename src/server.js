const express = require("express");
const bodyParser = require("body-parser");
const config = require("./config");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const store = require("./store");
const { TokenSet } = require("openid-client");
const utils = require("./utils");

const jwt_sign_secret =
  process.env.OEAS_JWT_SIGN_SECRET ||
  utils.exit_failure("missing OEAS_JWT_SIGN_SECRET env variable");
const proxy_encrypt_secret =
  process.env.OEAS_PROXY_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_PROXY_ENCRYPT_SECRET env variable");
const issuer_encrypt_secret =
  process.env.OEAS_ISSUER_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_ISSUER_ENCRYPT_SECRET env variable");
const session_encrypt_secret =
  process.env.OEAS_SESSION_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_SESSION_ENCRYPT_SECRET env variable");
const cookie_sign_secret =
  process.env.OEAS_COOKIE_SIGN_SECRET ||
  utils.exit_failure("missing OEAS_COOKIE_SIGN_SECRET env variable");
const cookie_encrypt_secret =
  process.env.OEAS_COOKIE_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_COOKIE_ENCRYPT_SECRET env variable");

//Issuer.defaultHttpOptions = { timeout: 2500, headers: { 'X-Your-Header': '<whatever>' } };

const app = express();

/**
 * register middleware
 */
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser(cookie_sign_secret));

/**
 * authenticates the proxy
 * authenticates the request (should check access_token, should validated thing token/aud against config aud)
 * returns 200 if good
 * if not redirects to provider
 *
 * TODO: discovery cache/ttl
 * TODO: refresh token window
 * TODO: userinfo refresh window
 *
 * TODO: various validations on claims (ie: groups, iss, etc)
 *
 * decrypt token
 * verify token
 * refresh if necessary?
 * get redirect_uri
 *
 * To update cookie/token redirect back to original URI sending updated cookie
 *
 * HTTP 403 Forbidden
 * HTTP 403 is a standard HTTP status code communicated to clients by an HTTP
 * server to indicate that the server understood the request, but will not
 * fulfill it for some reason related to authorization. There are a number of
 * sub-status error codes that provide a more specific reason for responding
 * with the 403 status code.
 *
 * HTTP 401 Unauthorized
 * Similar to 403 Forbidden, but specifically for use when authentication is
 * possible but has failed or not yet been provided. The response must
 * include a WWW-Authenticate header field containing a challenge applicable to
 * the requested resource. See Basic access authentication and Digest access
 * authentication.
 */
app.get("/oauth/verify", (req, res) => {
  //console.log(req);

  /**
   * pull the config token
   */
  let configToken;
  try {
    configToken = utils.decrypt(proxy_encrypt_secret, req.query.config_token);
    configToken = jwt.verify(configToken, jwt_sign_secret);
    configToken = utils.setConfigTokenDefaults(configToken);
    console.log("config token: %j", configToken);
  } catch (e) {
    console.log(e);
    res.statusCode = 503;
    res.end();
    return;
  }

  /**
   * reconstruct original request info from headers etc
   */
  const parentReqInfo = utils.get_parent_request_info(configToken, req);
  console.log("parent request info: %j", parentReqInfo);

  const configAudMD5 = configToken.audMD5;
  console.log("audMD5: %s", configAudMD5);

  const configCookieName = configToken.oeas.cookie.name;
  console.log("cooking name: %s", configCookieName);

  const redirectHttpCode = req.query.redirect_http_code
    ? req.query.redirect_http_code
    : 302;

  const respond_to_failed_authorization = function() {
    utils
      .get_issuer(configToken)
      .then(issuer => {
        console.log(
          "redirect_uri: %s",
          parentReqInfo.authorization_redirect_uri
        );

        utils
          .get_client(issuer, configToken)
          .then(client => {
            const payload = {
              request_uri: parentReqInfo.uri,
              aud: configAudMD5,
              csrf: utils.generate_csrf_id()
            };
            const stateToken = jwt.sign(payload, jwt_sign_secret);
            const state = utils.encrypt(issuer_encrypt_secret, stateToken);

            const url = client.authorizationUrl({
              redirect_uri: parentReqInfo.authorization_redirect_uri,
              scope: configToken.oeas.scopes.join(" "),
              state: state
            });
            console.log("callback redirect_uri: %s", url);

            switch (redirectHttpCode) {
              case 401:
                res.setHeader(
                  "WWW-Authenticate",
                  'Bearer realm="foo.bar.com", scope="openid profile email"'
                );
              default:
                res.cookie(
                  config.STATE_CSRF_COOKIE_NAME,
                  utils.encrypt(cookie_encrypt_secret, payload.csrf),
                  {
                    expires: new Date(
                      Date.now() + config.STATE_CSRF_COOKIE_EXPIRY * 1000
                    ),
                    httpOnly: true, //kills js access
                    signed: true
                  }
                );
                res.statusCode = redirectHttpCode;
                res.setHeader("Location", url);
                res.end();
                break;
            }
          })
          .catch(e => {
            console.log(e);
            res.statusCode = 503;
            res.end();
          });
      })
      .catch(e => {
        console.log(e);
        res.statusCode = 503;
        res.end();
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
  switch (parentReqInfo.parsedQuery[config.HANDLER_INDICATOR_PARAM_NAME]) {
    case "authorization_callback":
      const state = utils.decrypt(
        issuer_encrypt_secret,
        parentReqInfo.parsedQuery.state
      );
      const decodedState = jwt.verify(state, jwt_sign_secret);
      console.log("decoded state: %j", decodedState);

      /**
       * check for csrf cookie presense
       */
      if (!req.signedCookies[config.STATE_CSRF_COOKIE_NAME]) {
        res.statusCode = 503;
        res.end();
        return;
      }

      /**
       * validate csrf token
       */
      if (
        decodedState.csrf !=
        utils.decrypt(
          cookie_encrypt_secret,
          req.signedCookies[config.STATE_CSRF_COOKIE_NAME]
        )
      ) {
        res.statusCode = 503;
        res.end();
        return;
      }

      console.log("begin token fetch with authorization code");

      utils
        .get_issuer(configToken)
        .then(issuer => {
          //console.log("Discovered issuer %s %O", issuer.issuer, issuer.metadata);

          utils
            .get_client(issuer, configToken)
            .then(client => {
              const response_type = "code";
              const compare_redirect_uri = utils.get_authorization_redirect_uri(
                configToken,
                decodedState.request_uri
              );

              console.log("compare_redirect_uri: %s", compare_redirect_uri);
              client
                .authorizationCallback(
                  compare_redirect_uri,
                  parentReqInfo.parsedQuery,
                  {
                    state: parentReqInfo.parsedQuery.state,
                    response_type
                  }
                )
                .then(tokenSet => {
                  const session_id = utils.generate_session_id();
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

                  if (configToken.oeas.features.fetch_userinfo) {
                    promise = client
                      .userinfo(tokenSet)
                      .then(userInfo => {
                        console.log("userinfo %j", userInfo);
                        sessionPayload.userInfo = userInfo;
                      })
                      .catch(e => {
                        console.log(e);
                        res.statusCode = 503;
                        res.end();
                      });

                    promises.push(promise);
                  }

                  Promise.all(promises)
                    .then(() => {
                      /**
                       * seconds to keep backend cache
                       */
                      const ttl = (tokenExpiresAt - Date.now()) / 1000;
                      return store.set(
                        config.SESSION_CACHE_PREFIX + session_id,
                        utils.encrypt(
                          session_encrypt_secret,
                          JSON.stringify(sessionPayload)
                        ),
                        ttl
                      );
                    })
                    .then(() => {
                      /**
                       * set expiry if enabled
                       */
                      if (configToken.oeas.features.set_cookie_expiry) {
                        cookieExpiresAt = tokenExpiresAt;
                      } else {
                        cookieExpiresAt = null;
                      }

                      res.cookie(configCookieName, session_id, {
                        domain: configToken.oeas.cookie.domain,
                        path: configToken.oeas.cookie.path,
                        /**
                         * if omitted will be a 'session' cookie
                         */
                        expires: cookieExpiresAt
                          ? new Date(cookieExpiresAt)
                          : null,
                        httpOnly: true, //kills js access
                        signed: true
                      });

                      /**
                       * remove the csrf cookie
                       */
                      res.clearCookie(config.STATE_CSRF_COOKIE_NAME);

                      console.log(
                        "redirecting to original resource: %s",
                        decodedState.request_uri
                      );

                      res.statusCode = redirectHttpCode;
                      res.setHeader("Location", decodedState.request_uri);
                      res.end();
                    })
                    .catch(e => {
                      console.log(e);
                      res.statusCode = 503;
                      res.end();
                    });
                })
                .catch(e => {
                  console.log(e);
                  console.log(e.name);
                  if (e.name) {
                    switch (e.name) {
                      case "OpenIdConnectError":
                        console.log(`${e.error} (${e.error_description})`);
                        switch (e.error) {
                          case "invalid_grant":
                            res.statusCode = redirectHttpCode;
                            res.setHeader("Location", decodedState.request_uri);
                            res.end();
                            return;
                            break;
                        }
                        break;
                    }

                    res.statusCode = 503;
                    res.statusMessage = e.error_description;
                    res.end();
                    return;
                  }

                  res.statusCode = 503;
                  res.end();
                });
            })
            .catch(e => {
              console.log(e);
              res.statusCode = 503;
              res.end();
            });
        })
        .catch(e => {
          console.log(e);
          res.statusCode = 503;
          res.end();
        });
      break;

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

        store
          .get(config.SESSION_CACHE_PREFIX + session_id)
          .then(result => {
            if (!result) {
              respond_to_failed_authorization();
              return;
            }
            console.log("retrieved encrypted session content: %s", result);
            let sessionPayload = utils.decrypt(session_encrypt_secret, result);
            console.log("session data: %s", sessionPayload);
            sessionPayload = JSON.parse(sessionPayload);
            const tokenSet = new TokenSet(sessionPayload.tokenSet);

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
              respond_to_failed_authorization();
              return;
            }

            /**
             * token aud is the client_id
             */
            if (
              configToken.oeas.assertions.aud &&
              idToken.aud != configToken.oeas.client.client_id
            ) {
              respond_to_failed_authorization();
              return;
            }

            /**
             * access token is expired and refresh tokens are disabled
             */
            if (
              configToken.oeas.assertions.exp &&
              utils.tokenset_is_expired(tokenSet) &&
              !(
                configToken.oeas.features.refresh_access_token &&
                utils.tokenset_can_refresh(tokenSet)
              )
            ) {
              console.log("tokenSet is expired and refresh tokens disabled");
              respond_to_failed_authorization();
              return;
            }

            /**
             * both access and refresh tokens are expired and refresh is enabled
             */
            if (
              configToken.oeas.assertions.exp &&
              utils.tokenset_is_expired(tokenSet) &&
              configToken.oeas.features.refresh_access_token &&
              !utils.tokenset_can_refresh(tokenSet)
            ) {
              console.log("tokenSet expired and refresh no longer available");
              respond_to_failed_authorization();
              return;
            }

            if (
              configToken.oeas.assertions.nbf &&
              utils.tokenset_is_premature(tokenSet)
            ) {
              console.log("tokenSet is premature");
              respond_to_failed_authorization();
              return;
            }

            const promises = [];
            let promise;

            if (configToken.oeas.assertions.iss) {
              promise = new Promise((resolve, reject) => {
                utils
                  .get_issuer(configToken)
                  .then(issuer => {
                    if (utils.tokenset_issuer_match(tokenSet, issuer.issuer)) {
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
              configToken.oeas.features.introspect_access_token &&
              tokenSet.access_token
            ) {
              promise = new Promise((resolve, reject) => {
                utils
                  .get_issuer(configToken)
                  .then(issuer => {
                    if (!issuer.metadata.token_introspection_endpoint) {
                      reject("issuer does not support introspection");
                    }
                    return utils.get_client(issuer, configToken);
                  })
                  .then(client => {
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
              utils.tokenset_is_expired(tokenSet) &&
              configToken.oeas.features.refresh_access_token &&
              utils.tokenset_can_refresh(tokenSet)
            ) {
              promise = new Promise((resolve, reject) => {
                utils
                  .get_issuer(configToken)
                  .then(issuer => {
                    return utils.get_client(issuer, configToken);
                  })
                  .then(client => {
                    return new Promise(resolve => {
                      client
                        .refresh(sessionPayload.tokenSet.refresh_token)
                        .then(tokenSet => {
                          sessionPayload.tokenSet = tokenSet;
                          if (configToken.oeas.features.fetch_userinfo) {
                            client.userinfo(tokenSet).then(userInfo => {
                              console.log("userinfo %j", userInfo);

                              sessionPayload.userInfo = userInfo;

                              resolve();
                            });
                          } else {
                            resolve();
                          }
                        })
                        .catch(e => {
                          reject(e);
                        });
                    });
                  })
                  .then(() => {
                    store
                      .set(
                        config.SESSION_CACHE_PREFIX + session_id,
                        utils.encrypt(
                          session_encrypt_secret,
                          JSON.stringify(sessionPayload)
                        )
                      )
                      .then(() => {
                        resolve();
                      })
                      .catch(e => {
                        console.log(e);
                        res.statusCode = 503;
                        res.end();
                      });
                  })
                  .catch(e => {
                    console.log(e);
                    res.statusCode = 503;
                    res.end();
                  });
              });
              promises.push(promise);
            }

            Promise.all(promises)
              .then(() => {
                utils.prepare_token_headers(res, sessionPayload);
                res.statusCode = 200;
                res.end();
              })
              .catch(e => {
                console.log(e);
                res.statusCode = 503;
                res.end();
              });
          })
          .catch(e => {
            console.log(e);
            res.statusCode = 503;
            res.end();
          });
      } else {
        /**
         * cookie not present, redirect to oidc provider
         */
        respond_to_failed_authorization();
        return;
      }
      break;
  }
});

const port = process.env.OEAS_PORT || 8080;
console.log("starting server on port %s", port);
app.listen(port);
