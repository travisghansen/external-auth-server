# 1.0.0

- align/generic all features/documentation
- prometheus
- refactor naming of store/cache/etc
- force `EAS_ENCRYPT_IV_SECRET` parameter and document (`FLUSHDB` in redis to clear all old sessions)
- Add `EAS_ONE_POINT_ZERO` env var to ensure users have dealt with deprecated features

# 0.99.0

- helm repo analogy for server-side config tokens store IDs

- explore client-side `config_token` encryption (ie: pki encryption of `config_tokens`)
- look into support multiple `config_token` keys (ie: run external server as a service style setup)
- look into 'proper' `config_token` jwt encryption

- explore setting required scopes on a per-endpoint/verb basis (outside the
  backing service) and allowing the auth service to conditionally assert based on
  scopes in the jwt token

* support better logic for original URI detection `Forwarded` header and `X-Forwarded-For`, etc
* ensure sessions (guid) does not already exist however unlikely
* implement logout (both local and with provider)

* allow for run-time (ie: URL params) assertions
* configuration for turning on/off redirects (probably a query param like `redirect_http_code`) (this may simply be a verify_strategy)
* nonce?

* document proper annotations for common ingress controllers (traefik, nginx, ambassador, etc)

* support for encyprted cookie
* cookie as struct {id: foo, storage_type: cookie|backend}?
* update to 3.x `openid-client`
* replace `jsonwebtoken` with `@panva/jose`

* ensure empty body in responses

* email link plugin
* email code plugin

* support for POST callback providers (can accept post requests on the `/oauth/callback` route and translate to `GET` params)
* oauth2 providers

  - Google default
  - Azure
  - Facebook
  - ~~GitHub~~
  - GitLab
  - LinkedIn

* required plugins (ie: support multi-success pipepline)

* update docker hub description/details/homepage/etc
* note about contributing to the project
* link to examples (config store/auth plugin) with simple explanation about requirements

* redis config_token store
* try/catch in invalid responseCode getting sent by a plugin

* introduce options for csrf handling in `oauth2`/`oidc` plugins? currently disabling csrf deletion due to bad nginx/envoy behavior

* endpoint where config data can be sent and the backend will sign/encrypt and respond with newly minted `config_token` (need to consider security implications etc of this)

* give a nice overview of architecture with a pretty graphic to give newcomers a easier overview

* allow specifying a redirect URL for error response codes (ie: 404 -> some self hosted location, 503 -> some location with a pretty space etc)

* https://www.npmjs.com/package/jq.node (new query engine for better performance than jq)

* generic structure for various things
* request data
* auth data
* config data

* opa plugin
* opa assertions

* NODE_JQ_SKIP_INSTALL_BINARY=true
* pass previous response to subsequent plugins' verify method

- further data available to header injection (`req` and `parentRequestInfo`)
- update header injection to use generic query function
- only get parentRequestInfo once in server.js and more performance enhancements
- store `state` server-side in `oauth2`/`oidc` plugins

# 0.11.0

Released 2021-07-29

- support for `envoy` (contour, etc) grpc external auth
- support for running the http and grpc servers with native ssl
- support `handlebars` syntax for the various `custom_foo_parameters` in `oauth2`/`oidc`
- support `handlebars` as a new `query_engine`
- bump various deps
- minor bug fixes

# 0.10.2

Released 2021-04-04

- fix scenario where `scope` property is not present in `tokenSet` #107

# 0.10.1

Released 2021-04-03

- support `filtered_service_headers` to remove some hard-coded default response headers

# 0.10.0

Released 2021-04-03

- support `custom_authorization_code_parameters` in `oauth2`/`oidc`
- support `custom_refresh_parameters` in `oauth2`/`oidc`
- support `custom_revoke_parameters` in `oauth2`/`oidc`
- support `oauth2`/`oidc` single logout (SLO)
  - revoke tokens when logout initiated within `eas`
  - end the session with the provider when logout initiated within `eas`
  - `backchannel_logout` support for logouts triggered at the provider
- use multistage docker build process to shrink image size
- support `oidc` logic in the `jwt` plugin
- bump dependencies

# 0.9.1

Released 2020-08-17

- ~~fix issue with oidc introspection (see #84)~~
- ~~dependency updates~~

# 0.9.0

Released 2020-04-16

- ~~update all dependencies~~
- ~~use the same library for `oauth2`/`oidc` plugins~~
- ~~introduce `EAS_ENCRYPT_IV_SECRET` environment variable to address `crypto.createCipher is deprecated.`~~
- ~~update to node 12~~
- ~~assertions on `oidc` `access_token`~~
- ~~support token generation using docker~~

# 0.8.0

Released 2020-03-06

- ~~implement `use_referer_as_redirect_uri` for `oidc`/`oauth2` `xhr` scenarios~~
- ~~better support ingress-nginx~~
- ~~document nginx-ingress-controller and ingress-nginx~~

# 0.7.0

Released 2020-02-29

- ~~support server-side tokens being stored decrypted~~
- ~~support setting the `httpOnly`, `secure`, and `sameSite` flags on `oauth2`/`oidc` session/csrf cookies~~
- ~~allow for disabling the `csrf` cookie on `oauth2`/`oidc`~~
- ~~support custom authorization URL parameters for `oauth2`/`oidc`~~
- ~~support new endpoint to destroy `oidc`/`oauth2` sessions with `eas`~~
- ~~multi-arch docker images~~
- ~~support custom_error_headers~~
- ~~support for custom redirect code for xhr requests in `oidc`/`oauth2`~~

# 0.6.0

Released 2019-10-29

- ~~support dynamic server-side token/store id generation~~
- ~~introduce 2 new `query_engine`s - `js` and `jsonata`~~
- ~~introduce `request_js` as new plugin~~
- ~~ensure helm chart only mounts specific file in /tmp leaving it writable (currently the node ca certs are being mounted and rendering it ro)~~
- ~~new env variable `EAS_ALLOW_EVAL` which enables the usage of `request_js` plugin and/or the `js` `query_engine`~~

# 0.5.0

Released 2019-08-19

- ~~support jwks for `jwt` plugin~~
- ~~cache jwks keys~~
- ~~deprecate the `/ambasador/*` endpoints and replace with `/envoy/*`~~
- ~~document warnings about exposing the service in service meshes where the service itself becomes fronted with authentication by itself~~
- ~~support specifying server-side tokens with URL params in addition to 'pointer' token~~

# 0.4.0

Released 2019-07-02

- ~~various ldap improvements~~
- ~~ldap userinfo assertions~~
- ~~support annotations for helm service~~
- ~~initial support for ambassador configuration~~
- ~~update HOWTO helm example~~

# 0.3.2

Released 2019-06-26

- ~~fix ldap success response not setting http code properly~~

# 0.3.1

Released 2019-06-18

- ~~better helm example incorportating `redis-ha`~~
- ~~explicitly disable `nonce` checking for `oidc`~~
- ~~better parent request URI reconstruction for traefik edge-cases (prefix replacement, regex alterations)~~
- ~~better documentation around `oidc` and `oauth2` sessions~~

# 0.3.0

Released 2019-06-15

- ~~support self-signed certs~~
- ~~redis integration into helm chart~~
- ~~noop plugin to support simply doing header injection~~
- ~~config_token revocation (revoke specific jti's)~~

# 0.2.0

Released 2019-06-11

- ~~custom service headers~~
- ~~server-side `config_token`(s) to overcome URL length limits and centrally manage/update~~
- ~~firebase_jwt plugin~~
- ~~prometheus stats~~
- ~~support for arbitrary header names for the `jwt` plugin (ie: non Authorization headers)~~

# 0.1.0

Released 2019-05-21

- ~~plugin pipeline~~
- ~~multiple authentication plugins~~
- ~~cache discovery/issuer details~~ (this is automatically handled by the client lib)
- ~~support custom issuer endpoints~~
- ~~use key prefix for discovery and sessions~~
- ~~support manual issuer configuration~~
- ~~support client registration~~
- ~~refresh access token~~
- ~~checks to see if refresh token is present or not~~
- ~~configuration to enable refreshing access token~~
- ~~configuration to enable userinfo~~
- ~~configuration to enable refreshing userInfo~~
- ~~configuration for cookie domain~~
- ~~configuration for cookie path~~
- ~~configuration for scopes~~
- ~~proper ttl for cached sessions~~
- ~~state csrf cookie check~~
- ~~support redis configuration~~
- ~~build docker images and publish to docker hub~~
- ~~support static `redirect_uri` for providers that do not support wildcards~~
- ~~support `/oauth/callback` handler for the static `redirect_uri`~~
- ~~fixup refresh_access_token config option name~~
- ~~fixup introspect access_token config option name?~~
- ~~figure out why discovery requests are not being cached by the client~~
- ~~cache issuer and client objects~~
- ~~figure out refresh token when URL has changed~~
- ~~support `userinfo` for various `oauth2` providers using some kind of plugin system~~
- ~~allow for built-in assertions (`config_token`, `userinfo`)~~
- ~~configuration for custom assertions~~
- ~~implement proper logger solution~~
- ~~Authorization header with id_token for kube-dashboard~~
- ~~support static redirect URI (https://gitlab.com/gitlab-org/gitlab-ce/issues/48707)~~
- ~~support RSA signing in addition to signing key~~
- ~~appropriately handle invalid/changed secrets for signing/encryption~~
- ~~session expiry (true/false/seconds)~~
- ~~userinfo expiry (true/false/seconds)~~
- ~~cookie expiry (true/false/seconds)~~
- ~~ldap plugin~~
- ~~htpasswd plugin~~
- ~~request param/header plugins~~
- ~~jwt plugin~~
- ~~ensure all features are documented~~
- ~~document limitations when service provier only allows 1 active token per client_id~~
- ~~activity based session expiry (floating window sessions)~~
- ~~jwt assertions~~
- ~~forward auth plugin~~
- ~~assertion query engines~~
- ~~pipeline circuit breakers (`pcb`)~~
