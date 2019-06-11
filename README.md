# `external-auth-server`

`eas` (pronounced `eez`) is primarily focused on lowering the barrier to
using various authentication schemes in a kubernetes environment (but it works
with any reverse proxy supporting external/forward auth). `eas` can be
deployed once and protect many services using disperse authentication methods
and providers. The goal is to make enabling authentication as easy as:

1. generating a new `config_token` (see below)
1. configuring the reverse proxy to use the service for external authentication
1. benefit

# Authentication Plugins

Various [authentication plugins](PLUGINS.md) are supported. Within a single
`config_token` you can enable as many as you would like which results in a
pipeline of authentication mechanisms being invoked. The first plugin to result
in a `2XX` response code will allow the request to be serviced. If **all**
plugins fail, then by default the result from the final plugin defined in the
`config_token` will be returned to the client. You can however alter that on
a service-by-service basis by setting the `fallback_plugin=plugin index` (0
indexed) parameter on the authentication URL.

- htpasswd
- LDAP
- OpenID Connect
- oauth2
- request param
- request header
- jwt
- firebase jwt

# Features

- works with any proxy server (traefik, nginx, ambassador, etc) that supports
  forward/external auth
- works with any `OpenID Connect`/`oauth2` provider (tested predominantly with
  `keycloak` but it should be agnostic)
- only requires 1 installation to service any number of
  providers/configurations/vhosts/domains
- passes tokens to the backing service via headers
- automatically refreshes tokens
- server-side `config_token`s [CONFIG_TOKENS](CONFIG_TOKENS.md)

# Usage

If running multiple instances (HA) you will need a shared cache/store (see
redis below).

Refer to the [HOWTO](HOWTO.md) for a more detailed overview.

## Prerequisites

### `oauth2` and `oidc`

- `eas` must be able to access `OIDC Provider`

- `user-agent` must be able to access `OIDC Provider`
- `user-agent` must be able to access `proxy`
- `user-agent` must be able to access `eas` (if `redirect_uri` is directly
  pointing to `eas` service `/oauth/callback` endpoint)

- `proxy` must be able to access `eas`
- `proxy` must send `X-Forwarded-Host` (localhost:8000) to `eas` in sub-request
- `proxy` must send `X-Forwarded-Uri` (/anything/foo/bar?test=foo) to `eas` in
  sub-request
- `proxy` must send `X-Forwarded-Proto` (http) to `eas` in sub-request
- `proxy` should send `X-Forwarded-Method` (GET) to `eas` in sub-request
- `proxy` must return non `2XX` responses from `eas` to browser
- `proxy` may forward `2XX` auth header `X-Id-Token` to backing service
- `proxy` may forward `2XX` auth header `X-Userinfo` to backing service
- `proxy` may forward `2XX` auth header `X-Access-Token` to backing service
- `proxy` may forward `2XX` auth header `Authorization` to backing service

## Launch the server

### source

```
EAS_CONFIG_TOKEN_SIGN_SECRET="foo" \
EAS_CONFIG_TOKEN_ENCRYPT_SECRET="bar" \
EAS_ISSUER_SIGN_SECRET="super secret" \
EAS_ISSUER_ENCRYPT_SECRET="blah" \
EAS_COOKIE_SIGN_SECRET="hello world" \
EAS_COOKIE_ENCRYPT_SECRET="something" \
EAS_SESSION_ENCRYPT_SECRET="baz" \
EAS_CONFIG_TOKEN_STORES='{}' \
EAS_LOG_LEVEL="info" \
EAS_PORT=8080 \
node src/server.js
```

### docker

```
docker run -d --name eas -p 8080:8080 \
-e EAS_CONFIG_TOKEN_SIGN_SECRET="foo" \
-e EAS_CONFIG_TOKEN_ENCRYPT_SECRET="bar" \
-e EAS_ISSUER_SIGN_SECRET="super secret" \
-e EAS_ISSUER_ENCRYPT_SECRET="blah" \
-e EAS_COOKIE_SIGN_SECRET="hello world" \
-e EAS_COOKIE_ENCRYPT_SECRET="something" \
-e EAS_SESSION_ENCRYPT_SECRET="baz" \
-e EAS_CONFIG_TOKEN_STORES='{}' \
-e EAS_LOG_LEVEL="info" \
-e EAS_PORT=8080 \
travisghansen/external-auth-server
```

### Kubernetes

A `helm` chart is supplied in the repo directly.

```
helm upgrade \
--install \
--namespace=kube-system \
--set configTokenSignSecret=<random> \
--set configTokenEncryptSecret=<random> \
--set issuerSignSecret=<random> \
--set issuerEncryptSecret=<random> \
--set cookieSignSecret=<random> \
--set cookieEncryptSecret=<random> \
--set sessionEncryptSecret=<random> \
--set logLevel="info" \
--set storeOpts.store="redis" \
--set storeOpts.host="redis.lan" \
--set storeOpts.prefix="eas:" \
--set ingress.enabled=true \
--set ingress.hosts[0]=eas.example.com \
--set ingress.paths[0]=/ \
eas ./chart/
```

## Generate a token

```
# please edit the values in bin/generate-config-token.js to your situation
# ie: issuer disovery URL, client_id, client_secret, etc
# also make sure to use the same secrets used when launching the server
EAS_CONFIG_TOKEN_SIGN_SECRET="foo" \
EAS_CONFIG_TOKEN_ENCRYPT_SECRET="bar" \
node bin/generate-config-token.js
```

## Configure your reverse proxy

```
# See full examples in the ./examples/ directory
# particularly nginx has some particular requirements
# NOTE: run over https in production

# traefik
address = http://<oeas server ip>:8080/verify?config_token=<token output from above>

# nginx
proxy_pass "http://<oeas server ip>:8080/verify?redirect_http_code=401&config_token=<token output from above>";

# traefik ingress
ingress.kubernetes.io/auth-type: forward
ingress.kubernetes.io/auth-url: "https://eas.example.com/verify?config_token=CONFIG_TOKEN_HERE"
ingress.kubernetes.io/auth-response-headers: X-Userinfo, X-Id-Token, X-Access-Token, Authorization

```

## Endpoints

Configure the external auth URL to point to the services `/verify`
endpoint. The URL supports the following query params:

- `config_token=the encrypted configuration token`
- `redirect_http_code=code` (only use with nginx to overcome external auth
  module limitations (should be set to `401`), otherwise omitted)
- `fallback_plugin=plugin index` if all plugins fail authentication which
  plugin response should be returned to the client

If your provider does not support wildcards you may expose `eas` directly and
set the `config_token` `redirect_uri` to the `eas` service at the
`/oauth/callback` path.

## redis

No support for sentinel currently, see `bin/generate-store-opts.js` with further options.

- https://www.npmjs.com/package/redis#options-object-properties

```
EAS_STORE_OPTS='{"store":"redis","host":"localhost"}'
```
