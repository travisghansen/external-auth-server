# 0.2.0

- cache jwks keys?
- support better logic for original URI detection `Forwarded` header and `X-Forwarded-For`, etc
- ensure sessions (guid) does not already exist however unlikely
- implement logout (both local and with provider)

- allow for run-time (ie: URL params) assertions
- configuration for turning on/off redirects (probably a query param like `redirect_http_code`) (this may simply be a verify_strategy)
- nonce?
- config_token revocation (blacklist specific jti's)

- support self-signed certs
- document proper annotations for common ingress controllers (traefik, nginx, ambassador, etc)

- support for encyprted cookie
- cookie as struct {id: foo, storage_type: cookie|backend}?
- update to 3.x `openid-client`
- replace `jsonwebtoken` with `@panva/jose`

- ensure empty body in responses
- server-side `config_token`(s) to overcome URL length limits and centrally manage (provide a `config_token_id` instead)
- redis integration into helm chart

- email link plugin
- email code plugin

* support for POST callback providers (can accept post requests on the `/oauth/callback` route and translate to `GET` params)
* oauth2 providers
* Google default
* Azure
* Facebook
* ~~GitHub~~
* GitLab
* LinkedIn

# 0.1.0

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
- jwt plugin
- ensure all features are documented
- document limitations when service provier only allows 1 active token per client_id
- ~~activity based session expiry (floating window sessions)~~