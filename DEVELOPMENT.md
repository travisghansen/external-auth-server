# Plugins

Creating new plugins requires minimal effort. See the
[example](src/plugin/example/index.js) for details.

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

https://medium.com/hal24k-techblog/multitenancy-on-kubernetes-with-istio-external-authentication-server-and-openid-connect-33e02544e0db

# Challenges

## kong-oidc

- not cache'ing the discovery docs
- does not allow for deeper validation on iss/groups/other attrs/etc
- `redirect_uri` when set on multiple hosts/routes becomes difficult
  (https://github.com/nokia/kong-oidc/issues/118)
- not generic to work with all proxies

## oauth2_proxy

- cumbersome to deploy and intrusive to the overall process (sidecars in
  kubernetes, etc)
- must be deployed unique to each service (ie, new deployment of the proxy for
  each `client_id` and `client_secret` etc)

# Ideas

- allow per-path and/or per-method checks
  (https://www.keycloak.org/docs/latest/securing_apps/index.html#_keycloak_generic_adapter)

# Links

- https://www.keycloak.org/docs/latest/securing_apps/index.html#_keycloak_generic_adapter
- https://docs.traefik.io/configuration/entrypoints/#forward-authentication
- https://www.getambassador.io/reference/services/auth-service/
- https://github.com/ajmyyra/ambassador-auth-oidc/blob/master/README.md
- https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-openid-connect-code
- https://bl.duesterhus.eu/20180119/
- https://itnext.io/protect-kubernetes-dashboard-with-openid-connect-104b9e75e39c

- https://developer.okta.com/authentication-guide/auth-overview/#authentication-api-vs-oauth-2-0-vs-openid-connect
- https://developer.okta.com/authentication-guide/implementing-authentication/auth-code/

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

- https://devforum.okta.com/t/oauth-2-0-authentication-and-redirect-uri-wildcards/1015/2

- https://github.com/keycloak/keycloak-gatekeeper
- https://github.com/pusher/oauth2_proxy

- https://github.com/ory/oathkeeper
- https://www.express-gateway.io/
- https://github.com/buzzfeed/sso
- https://github.com/pomerium/pomerium
- https://www.pomerium.io/
- https://www.ory.sh/kratos/

- https://www.troyhunt.com/promiscuous-cookies-and-their-impending-death-via-the-samesite-policy/
- https://web.dev/samesite-cookies-explained/

## contour

- https://github.com/heptio/contour/issues/986
- https://github.com/heptio/contour/issues/432
- https://github.com/heptio/contour/issues/68

## ambassador

- https://github.com/datawire/ambassador/issues/216
- https://www.getambassador.io/reference/services/auth-service/
- https://www.getambassador.io/reference/host/
- https://www.getambassador.io/reference/add_request_headers/

## ingress-nginx

- https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/
- https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/
- https://github.com/kubernetes/ingress-nginx

## nginx-ingress-controller

- https://github.com/nginxinc/kubernetes-ingress/tree/master/deployments/helm-chart
- https://docs.nginx.com/nginx-ingress-controller/overview/
