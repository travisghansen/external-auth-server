const config = require("./config");
const jwt = require("jsonwebtoken");
const secrets = require("./secrets");
const store = require("./store");
const utils = require("./utils");

/**
 * state should be the decrypted state token
 *
 *
 * @param {*} req
 * @param {*} res
 * @param {*} state
 */
function handle_auth_callback_request(
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

  const configCookieName = configToken.oeas.cookie.name;
  console.log("cooking name: %s", configCookieName);

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
    state.csrf !=
    utils.decrypt(
      secrets.cookie_encrypt_secret,
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
            state.request_uri
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
                  .then(userinfo => {
                    console.log("userinfo %j", userinfo);
                    sessionPayload.userinfo = userinfo;
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
                      secrets.session_encrypt_secret,
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
                    expires: cookieExpiresAt ? new Date(cookieExpiresAt) : null,
                    httpOnly: true, //kills js access
                    signed: true
                  });

                  /**
                   * remove the csrf cookie
                   */
                  res.clearCookie(config.STATE_CSRF_COOKIE_NAME);

                  console.log(
                    "redirecting to original resource: %s",
                    state.request_uri
                  );

                  res.statusCode = redirectHttpCode;
                  res.setHeader("Location", state.request_uri);
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
                        res.setHeader("Location", state.request_uri);
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
}

module.exports = {
  handle_auth_callback_request
};
