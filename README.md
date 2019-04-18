# `oauth-external-auth-server`

`oeas` (pronounced oh-eez) is primarily focused on lowering the barrier to
using `OpenID Connect` in a kubernetes environment (but it works with any
reverse proxy supporting external/forward auth). `oeas` can be deployed once
and protect many services. The goal is to make enabling authentication as easy
as

1. generating a new `config_token` (see below)
1. adding an `annotation` to an `Ingress` with the `config_token`
1. benefit

# Features

- works with any proxy server (traefik, nginx, ambassador, etc) that supports
  forward/external auth
- works with any `OpenID Connect` provider (tested predominantly with
  `keycloak` but it should be agnostic)
- only requires 1 installation to service any number of
  providers/configurations/vhosts/domains
- passes tokens to the backing service via headers
- automatically refreshes tokens

# Usage

Configuring your `OIDC Provider` is presumed to be understood and accomplished
_before_ configuring `oeas`. `oeas` currently implements the
`Authorization Code Flow`, as such you will need a `client_id` and
`client_secret` from your `OIDC Provider`.

## Prerequisites

- `oeas` must be able to access `OIDC Provider`

- `OIDC Provider` should support callbacks using wildcards (`*`) (otherwise
  `oeas` will be of limited use)

- `user-agent` must be able to access `OIDC Provider`
- `user-agent` must be able to access `proxy`

- `proxy` must be able to access `oeas`
- `proxy` must send `X-Forwarded-Host` (localhost:8000) to `oeas` in sub-request
- `proxy` must send `X-Forwarded-Uri` (/anything/foo/bar?test=foo) to `oeas` in
  sub-request
- `proxy` must send `X-Forwarded-Proto` (http) to `oeas` in sub-request
- `proxy` should send `X-Forwarded-Method` (GET) to `oeas` in sub-request
- `proxy` must return non `2XX` responses from `oeas` to browser
- `proxy` should forward `2XX` auth header `X-Id-Token` to backing service
- `proxy` should forward `2XX` auth header `X-Userinfo` to backing service
- `proxy` should forward `2XX` auth header `X-Access-Token` to backing service

If running multiple instances (HA) you will need a shared cache/store (see
redis below).

## Launch the server

If running with docker (`docker pull travisghansen/oauth-external-auth-server`)
just launch the container with the appropraite env variables.

```
OEAS_JWT_SIGN_SECRET="foo" \
OEAS_PROXY_ENCRYPT_SECRET="bar" \
OEAS_ISSUER_ENCRYPT_SECRET="blah" \
OEAS_SESSION_ENCRYPT_SECRET="baz" \
OEAS_COOKIE_SIGN_SECRET="hello world" \
OEAS_COOKIE_ENCRYPT_SECRET="something" \
OEAS_PORT=8080 \
node src/server.js
```

## Generate a token

```
# please edit the values in bin/generate-config-token.js to your situation
# ie: issuer disovery URL, client_id, client_secret, etc
# also make sure to use the same secrets used when launching the server
OEAS_JWT_SIGN_SECRET="foo" \
OEAS_PROXY_ENCRYPT_SECRET="bar" \
node bin/generate-config-token.js
```

## Configure your reverse proxy

```
# See full examples in the ./examples/ directory
# particularly nginx has some particular requirements
# NOTE: run over https in production

# traefik
address = http://<oeas server ip>:8080/oauth/verify?config_token=<token output from above>

# nginx
proxy_pass "http://<oeas server ip>:8080/oauth/verify?redirect_http_code=401&config_token=<token output from above>";
```

## Endpoint

Configure the external auth URL to point to the services `/oauth/verify`
endpoint. The URL supports the following query params:

- `config_token=the encrypted configuration token`
- `redirect_http_code=code` (to overcome nginx external auth module limitations
  and should be set to `401`, otherwise omitted)

## redis

No support for sentinel currently, see `bin/generate-cache-opts.js` with further options.

- https://www.npmjs.com/package/redis#options-object-properties

```
OEAS_CACHE_OPTS='{"store":"redis","host":"localhost"}'
```

# Design

Really tring to alleviate the following primary challenges:

- needing to deploy an additional `proxy` (`oauth2_proxy`,
  `keycloak-gatekeeper`, etc)
- static configurations
- issuer/provider specific implementations
- reverse proxy specific implementations
- inability to make complex assertions on the claims/tokens

Development goals:

- maintain original host/port/path for _all_ callbacks to ensure return to the
  proper location (callbacks detected by setting GET param on original URI with
  query stripped)
- signed: ensures only trusted apps/proxies can use the service
- encrypted: allows for identity operators to hide client\_{id,secret} (and
  other configuration options) from reverse proxy operators
- config aud: ensures users cannot use token (cookie) from one
  configuration/site and use it with another

# Challenges

## kong-oidc

- not cache'ing the discovery docs
- does not allow for deeper validation on iss/groups/other attrs/etc
- `redirect_uri` when set on multiple hosts/routes becomes difficult
  (https://github.com/nokia/kong-oidc/issues/118)

## oauth2_proxy

- cumbersome to deploy and intrusive to the overall process (sidecars in
  kubernetes, etc)
- must be deployed unique to each service (ie, new deployment of the proxy for
  each `client_id` and `client_secret` etc)

# TODO

## 0.2.0

- cache jwks keys?
- support better logic for original URI detection `Forwarded` header and `X-Forwarded-For`, etc
- ensure sessions (guid) does not already exist however unlikely
- implement logout (both local and with provider)
- configuration for custom assertions (lodash?)
- allow for built-in assertions (`config_token`)
- allow for run-time (ie: URL params) assertions
- configuration for turning on/off redirects (probably a query param like `redirect_http_code`)
- nonce?
- config_token revocation (blacklist specific jti's)
- support for verifying Bearer requests/tokens
- support RSA signing in addition to signing key
- appropriately handle invalid/changed secrets for signing/encryption
- implement proper logger solution
- support self-signed certs
- document proper annotations for common ingress controllers (traefik, nginx, ambassador, etc)

## 0.1.0

- ~~cache discovery/issuer details~~ (this is automatically handled by the client lib)
- ~~support custom issuer endpoints~~
- ~~use key prefix for discovery and sessions~~
- ~~support manual issuer configuration~~
- ~~support client registration~~
- ~~refresh access token~~
- ~~checks to see if refresh token is present or not~~
- ~~configuration to enable refreshing access token~~
- ~~configuration to enable userInfo~~
- ~~configuration to enable refreshing userInfo~~
- ~~configuration for cookie domain~~
- ~~configuration for cookie path~~
- ~~configuration for scopes~~
- ~~proper ttl for cached sessions~~
- ~~state csrf cookie check~~
- ~~support redis configuration~~
- build docker images and publish to docker hub

- fixup refresh_access_token config option name
- fixup introspect access_token config option name?
- figure out why discovery requests are not being cached by the client
- figure out refresh token when URL has changed
- implement verify_strategy (cookie_only, bearer, cookie+token(s), etc)

# Links

- https://www.keycloak.org/docs/latest/securing_apps/index.html#_keycloak_generic_adapter
- https://docs.traefik.io/configuration/entrypoints/#forward-authentication
- https://www.getambassador.io/reference/services/auth-service/
- https://github.com/ajmyyra/ambassador-auth-oidc/blob/master/README.md
- https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-openid-connect-code
- https://bl.duesterhus.eu/20180119/

- https://github.com/oktadeveloper/okta-kong-origin-example
- https://connect2id.com/learn/openid-connect
- https://www.jerney.io/secure-apis-kong-keycloak-1/amp/

- https://redbyte.eu/en/blog/using-the-nginx-auth-request-module/
- https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
- https://github.com/openresty/lua-nginx-module#readme
- https://nginx.org/en/docs/varindex.html
- https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/
- https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/
- https://forum.nginx.org/read.php?29,222609,222652
- https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#external-authentication

- https://tools.ietf.org/html/rfc6750#section-3

- https://developer.okta.com/blog/2017/07/25/oidc-primer-part-1
- https://developer.okta.com/blog/2017/07/25/oidc-primer-part-2
- https://developer.okta.com/blog/2017/08/01/oidc-primer-part-3

- https://blog.runscope.com/posts/understanding-oauth-2-and-openid-connect

- https://developers.google.com/identity/protocols/OpenIDConnect

- https://tools.ietf.org/html/rfc6265#section-4.1.1
- Servers SHOULD NOT include more than one Set-Cookie header field in the same response with the same cookie-name.
- ^ why we do not allow setting the cookie on multiple domains

- https://github.com/keycloak/keycloak-gatekeeper
- https://github.com/pusher/oauth2_proxy
