# Introduction

`eas` is designed to make it easy to integrate various authentication schemes
leveraging the _forward_ or _external_ authentication feature of several
reverse proxies.

The general idea is to deploy the service once and subsequently embed all
unique configurations in the `config_token` parameter of the authentication
URL.

Various authentication plugins can be included in each `config_token` creating
a pipeline of authentication mechanisms for each request. The first to
authenticate successfully allows the request and remaining plugins will **not**
be attempted. If **all** the plugins fail authentication, then the result from
the _last_ plugin is returned by default. However, this behavior can be
adjusted with the `fallback_plugin` query param in the authentication URL. It's
value is the 0-indexed value of which plugin from the list should be returned
in the case of complete failure.

# Setup

An example of running the service in kubernetes with `traefik` as an `Ingress`
controller follows. Other setups are completely valid and only change the
semantics.

## Deploy the service

Using helm you can deploy the service to your cluster. First clone the repo.

```
helm upgrade \
--install \
--namespace=kube-system \
--set configTokenSignSecret=<secret> \
--set configTokenEncryptSecret=<secret> \
--set issuerSignSecret=<secret> \
--set issuerEncryptSecret=<secret> \
--set cookieSignSecret=<secret> \
--set cookieEncryptSecret=<secret> \
--set sessionEncryptSecret=<secret> \
--set logLevel="info" \
--set storeOpts.store="redis" \
--set storeOpts.host="redis.lan" \
--set storeOpts.prefix="eas:" \
--set ingress.enabled=true \
--set ingress.hosts[0]=eas.example.com \
--set ingress.paths[0]=/ \
eas ./chart/
```

Be sure to pick **different** `secrets` for each of the options. Make note of
the `configTokenSignSecret` and `configTokenEncryptSecret` as we'll need them
shortly. If you do not have `redis` available simply omit the `storeOpts`
settings but make sure you only have 1 instance of the service running.

Technically `redis` is only required for multiple instances if you intend on
using the `oauth2` or `oidc` plugins.

## Generage `config_token`

Next let's generate our first `config_token` to use with a (or several)
services. Edit the `bin/generate-config-token.js` file to your needs.

Refer to [PLUGINS.md](PLUGINS.md) for more detail on each parameter.

This example is for `github`. You will at a minimum need to set the appropriate
values for `client_id`, `client_secret`, `redirect_uri`, and `cookie.domain`.

```
const jwt = require("jsonwebtoken");
const utils = require("../src/utils");

const config_token_sign_secret =
  process.env.EAS_CONFIG_TOKEN_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_SIGN_SECRET env variable");
const config_token_encrypt_secret =
  process.env.EAS_CONFIG_TOKEN_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ENCRYPT_SECRET env variable");

let config_token = {
  /**
   * future feature: allow blocking certain token IDs
   */
  //jti: <some known value>

  /**
   * using the same aud for multiple tokens allows sso for all services sharing the aud
   */
  //aud: "some application id", //should be unique to prevent cookie/session hijacking, defaults to a hash unique to the whole config
  eas: {
    // list of plugin definitions, refer to PLUGINS.md for details
    plugins: [
      {
        type: "oauth2",
        issuer: {
          authorization_endpoint: "https://github.com/login/oauth/authorize",
          token_endpoint: "https://github.com/login/oauth/access_token"
        },
        client: {
          client_id: "",
          client_secret: ""
        },
        scopes: ["user"],
        /**
         * static redirect URI
         * if your oauth provider does not support wildcards place the URL configured in the provider (that will return to this proper service) here
         */
        redirect_uri: "https://eas.example.com/oauth/callback",
        features: {
          /**
           * if false cookies will be 'session' cookies
           * if true and cookies expire will expire with tokens
           */
          cookie_expiry: false,

          userinfo_expiry: 86400, // 24 hours

          /**
           * sessions become a floating window *if* tokens are being refreshed or userinfo being refreshed
           */
          session_expiry: 604800, // 7 days

          /**
           * if session_expiry is a number and this is set then sessions become a 'floating window'
           * if activity is triggered in this amount of time *before* preceeding the end of the
           * session then the expiration time is extended + session_expiry
           */
          session_expiry_refresh_window: 86400, // 24 hours

          /**
           * will re-use the same id (ie: same cookie) for a particular client if a session has expired
           */
          session_retain_id: true,

          /**
           * if the access token is expired and a refresh token is available, refresh
           */
          refresh_access_token: true,

          /**
           * fetch userinfo and include as X-Userinfo header to backing service
           */
          fetch_userinfo: true,

          userinfo: {
            provider: "github",
            config: {
              fetch_teams: true,
              fetch_organizations: true,
              fetch_emails: true
            }
          },

          /**
           * which token (if any) to send back to the proxy as the Authorization Bearer value
           * note the proxy must allow the token to be passed to the backend if desired
           *
           * possible values are access_token, or refresh_token
           */
          //authorization_token: "access_token"
        },
        assertions: {
          /**
           * assert the token(s) has not expired
           */
          exp: true
        },
        cookie: {
          name: "_eas_github_session_", //default is _oeas_oauth_session
          domain: "example.com" //defaults to request domain, could do sso with more generic domain
          //path: "/",
        }
      }
    ]
  }
};

config_token = jwt.sign(config_token, config_token_sign_secret);
const conifg_token_encrypted = utils.encrypt(
  config_token_encrypt_secret,
  config_token
);

//console.log("token: %s", config_token);
//console.log("");

//console.log("encrypted token: %s", conifg_token_encrypted);
//console.log("");

console.log(
  "URL safe config_token: %s",
  encodeURIComponent(conifg_token_encrypted)
);
console.log("");
```

Generate the token. Be sure to use the values specified when deploying the
service as the `EAS_CONFIG_TOKEN_SIGN_SECRET` and
`EAS_CONFIG_TOKEN_ENCRYPT_SECRET`.

```
EAS_CONFIG_TOKEN_SIGN_SECRET=foo EAS_CONFIG_TOKEN_ENCRYPT_SECRET=bar node bin/generate-config-token.js
```

Copy the value from the console after `URL safe config_token`. This is your
first `config_token` to used when protecting services.

## Configure traefik

Now that we have deployed the service and generated a `config_token` it's time
to configure the reverse proxy.

Edit the `Ingress` resource of the service you want to secure. Be sure to
use the proper URL by replacing `example.com` with your domain.

```
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  namespace: monitoring
  name: kibana
  annotations:
    kubernetes.io/ingress.class: traefik
    ingress.kubernetes.io/auth-response-headers: X-Userinfo, X-Id-Token, X-Access-Token, Authorization
    ingress.kubernetes.io/auth-type: forward
    ingress.kubernetes.io/auth-url: https://eas.example.com/verify?fallback_plugin=0&config_token=PLACE_CONFIG_TOKEN_OUTPUT_HERE
...
```

## Enjoy

Your service is now secured. Assuming you set a `cookie.domain` value
appropriately any `Ingress` which is a sub-domain of the `cookie.domain` value
can be secured with the exact same configuration.

Need different settings for a different `Ingress`? Simply generate a new
`config_token` with the appropriate values and use it in the `auth-url`.