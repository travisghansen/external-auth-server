![Image](https://img.shields.io/docker/pulls/travisghansen/external-auth-server.svg)
![Image](https://img.shields.io/github/workflow/status/travisghansen/external-auth-server/CI?style=flat-square)

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
- request js
- jwt
- firebase jwt

# Features

- works with any proxy server (traefik, nginx, ambassador, istio, envoy, etc)
  that supports forward/external auth
- works with any `OpenID Connect`/`oauth2` provider (tested predominantly with
  `keycloak` but it should be agnostic)
- only requires 1 installation to service any number of
  providers/configurations/vhosts/domains
- passes tokens to the backing service via headers
- automatically refreshes tokens
- server-side `config_token`s [CONFIG_TOKENS](CONFIG_TOKENS.md)

# Usage

If running multiple instances (HA) you will need a shared cache/store (see
redis below). You only **really** need redis if:

1. You are running HA
1. You are using the `oidc` or `oauth2` plugins

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

A `helm` chart is supplied in the repo directly. Reviewing
[values.yaml](charts/external-auth-server/values.yaml) is **highly**
recommended as examples are provided for common use-cases.

```
helm repo add eas https://travisghansen.github.io/external-auth-server
helm repo update
helm upgrade \
--install \
--namespace=external-auth-server \
\
--set configTokenSignSecret=<random> \
--set configTokenEncryptSecret=<random> \
--set issuerSignSecret=<random> \
--set issuerEncryptSecret=<random> \
--set cookieSignSecret=<random> \
--set cookieEncryptSecret=<random> \
--set sessionEncryptSecret=<random> \
--set logLevel="info" \
\
--set redis-ha.enabled=true \
--set redis-ha.auth=true \
--set redis-ha.redisPassword=53c237 \
\
--set storeOpts.store=ioredis \
--set storeOpts.password=53c237 \
--set storeOpts.name=mymaster \
--set storeOpts.sentinels[0].host=eas-redis-ha-announce-0 \
--set storeOpts.sentinels[0].port=26379 \
--set storeOpts.sentinels[1].host=eas-redis-ha-announce-1 \
--set storeOpts.sentinels[1].port=26379 \
--set storeOpts.sentinels[2].host=eas-redis-ha-announce-2 \
--set storeOpts.sentinels[2].port=26379 \
--set storeOpts.keyPrefix="eas:" \
\
--set ingress.enabled=true \
--set ingress.hosts[0]=eas.example.com \
--set ingress.paths[0]=/ \
eas eas/external-auth-server
```

## Generate a token

```
# please edit the values in bin/generate-config-token.js to your situation
# ie: issuer disovery URL, client_id, client_secret, etc
# also make sure to use the same secrets used when launching the server
EAS_CONFIG_TOKEN_SIGN_SECRET="foo" \
EAS_CONFIG_TOKEN_ENCRYPT_SECRET="bar" \
node bin/generate-config-token.js

# alternatively you may use the following to create tokens
# files can be either json or yaml
cat config-token.json | docker run --rm -i -e EAS_CONFIG_TOKEN_SIGN_SECRET=foo -e EAS_CONFIG_TOKEN_ENCRYPT_SECRET=bar travisghansen/external-auth-server generate-config-token
cat config-token.json | EAS_CONFIG_TOKEN_SIGN_SECRET=foo EAS_CONFIG_TOKEN_ENCRYPT_SECRET=bar npm run generate-config-token
```

## Configure your reverse proxy

```
# See full examples in the ./examples/ directory
# particularly nginx has some particular requirements
# NOTE: run over https in production
# NOTE: take care to NOT authenticate `eas` with itself (this is particularly
# possible to happen in service mesh scenarios), whatever tool you use should
# ensure access to the `eas` service bypasses authentication thereby avoiding
# recursive behavior

# traefik
address = http://<eas server ip>:8080/verify?config_token=<token output from above>

# nginx (see examples/nginx.conf)
proxy_pass "http://<eas server ip>:8080/verify?redirect_http_code=401&config_token=<token output from above>";

# ingress-nginx (see examples/ingress-nginx.yaml)

# nginx-ingress-controller (see examples/nginx-ingress-controller.yaml)

# traefik ingress
ingress.kubernetes.io/auth-type: forward
ingress.kubernetes.io/auth-url: "https://eas.example.com/verify?config_token=CONFIG_TOKEN_HERE"
ingress.kubernetes.io/auth-response-headers: X-Userinfo, X-Id-Token, X-Access-Token, Authorization

# ambassador (see file in examples directory)

# istio (see file in examples directory)

# haproxy-ingress (see file in examples directory)

# contour (see file in examples directory)

# envoy (see file in examples directory)

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

## Additional ENV vars

- `EAS_SSL_CERT` path to ssl cert file to enable https
- `EAS_SSL_KEY` path to ssl key file to enable https
- `EAS_GRPC_ADDRESS` the address to start the grpc server on (default is
  `0.0.0.0`)
- `EAS_GRPC_PORT` port the grpc server is bound to (default is `50051`)
- `EAS_GRPC_SSL_CERT` path to ssl cert file to enable https
- `EAS_GRPC_SSL_KEY` path to ssl key file to enable https

## redis

### `ioredis` cache adapter

Support for sentinel, see `bin/generate-store-opts.js` with further options.

- https://github.com/luin/ioredis/blob/master/API.md#new-redisport-host-options

```
EAS_STORE_OPTS='{"store":"ioredis","host":"localhost"}'
```

### `redis` cache adapter

No support for sentinel currently, see `bin/generate-store-opts.js` with further options.

- https://www.npmjs.com/package/redis#options-object-properties

```
EAS_STORE_OPTS='{"store":"redis","host":"localhost"}'
```
