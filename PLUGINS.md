# Plugins

Plugins defined in a list forming a pipeline of authentication schemes.

The first plugin to result in a `2XX` response code will allow the request to
be serviced. If **all** plugins fail, then by default the result from the
final plugin defined in the `config_token` will be returned to the client. You
can however alter that on a service-by-service basis by setting the
`fallback_plugin=plugin index` (0 indexed) parameter on the authentication URL.

In addition, there are various `pcb` (plugin/pipeline circuit breakers) to do 2
distinct things:

1. `skip` plugin execution based on the nature of the request
1. `stop` pipeline execution based on the nature of the request or the plugin
   response

An example `config_token`:

```
    ...
    plugins: [
      {
        type: "jwt",
        config: {
          secret: "foo"
        },
        pcb: {
          skip: [
            {
              query_engine: "jp",
              query: "$.req.headers.authorization",
              rule: {
                method: "regex",
                value: "/^bearer/i",
                negate: true
              }
            }
          ],
          stop: [
            {
              query_engine: "jp",
              query: "$.req.headers.authorization",
              rule: {
                method: "regex",
                value: "/^bearer/i",
              }
            }
          ]
        }
      },
      {
        type: "htpasswd",
        htpasswd: "...",
        pcb: {
          skip: [
            {
              query_engine: "jp",
              query: "$.req.headers.authorization",
              rule: {
                method: "regex",
                value: "/^basic/i",
                negate: true
              }
            }
          ],
          stop: [
            {
              query_engine: "jp",
              query: "$.req.headers.authorization",
              rule: {
                method: "regex",
                value: "/^basic/i",
              }
            }
          ]
        }
      },
    ]
    ...
```

The effect of the example is:

- the `jwt` plugin will be skipped if the `authorization` header does not start with `bearer`
- if the `authorization` does start with `bearer` it will be the last plugin to execute
- ditto for the `htpasswd` plugin except with `basic` instead of `bearer`

## `htpasswd`

Performs `Basic` authentiaction using a standard `htpasswd` file.

```
{
    type: "htpasswd",
    realm: "my realm", // optional
    htpasswd: "<password file data>" // ie: "foo:$apr1$P6l79L2I$yXjFNHLV.ZPiV86bZ73GI." be sure to properly escape for json if necessary

}
```

## `ldap`

Performs `Basic` authentication using `ldap` lookups.

```
{
    type: "ldap",
    realm: "my realm", // optional
    session_cache_ttl: 900, // seconds to cache successful logins
    connection: {
        url: "...",
        log: false, // special handling to integrate with eas logging, simply set to true to turn on
        ...
        see details here: https://github.com/vesse/node-ldapauth-fork#ldapauth-config-options
        filter syntax here: https://github.com/ldapjs/node-ldapjs/blob/v1.0.1/docs/client.md#filter-strings
    },
    assertions: {
        /**
        * custom userinfo assertions
        */
        userinfo: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ]
    }
}
```

### `connection` parameter details

- `searchFilter`: be careful with whitespace between filters (ie: GOOD `()()`
  BAD `() ()`)
- `searchAttributes`: only determines what returned, any field can be used in
  the `searchFilter` regardless of this setting, also note that computed fields
  like `memberOf` are not selected with the default "all" configuration
- `groupSearchBase`: example `ou=Groups,dc=example,dc=com`
- `groupSearchFilter`: can be used to limit which groups will be available in
  the `_groups` attribute
  - `(cn=*)` - include all groups in the `_groups` userinfo property
  - `(member={{dn}})` include only groups the user is a member of

## `jwt`

Verifies a `jwt` token sent as a `Bearer` token in the `Authorization` header.

```
{
    type: "jwt",
    realm: "my realm", // optional
    header_name: "Authorization", // optional
    scheme: "Bearer", // optional, if using a custom header_name without a scheme leave it blank
    config: {
        secret: "", // either the secret or full public key PEM data or jwks URL or empty if oidc features are enabled and jwks is available
        options: {
            ...
            see details here: https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
        }
    },
    oidc: {
      /**
      * enable oidc based features
      * enabling this assumes your oidc provider issues access_tokens as jwts (not required in the spec)
      * and that you want to leverage introspection and/or userinfo features
      */
      enabled: false,
      issuer: {
          /**
          * via discovery (takes preference)
          */
          //discover_url: "https://<provider>/.well-known/openid-configuration",

          /**
          * via manual definition
          */
          //issuer: 'https://accounts.google.com',
          //authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
          //token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
          //userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
          //jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      },
      client: {
          /**
          * manually defined (preferred)
          */
          client_id: "...",
          client_secret: "..."

          /**
          * via client registration
          */
          //registration_client_uri: "",
          //registration_access_token: "",
      },
      features: {
        /**
        * check token validity with provider during assertion process
        */
        introspect_access_token: false,

        /**
        * if introspect_access_token is true, how long in seconds to cache the result
        * if not a number greater than 0, the introspection endpoint will be requested *every* verify request
        */
        introspect_expiry: 0,

        /**
        * fetch userinfo and include as X-Userinfo header to backing service
        */
        fetch_userinfo: true,

        /**
        * how frequently to refresh userinfo data
        * true = expire when the token expires
        * false = always refresh (ie: do NOT cache)
        * num seconds = expire after given number of seconds
        */
        userinfo_expiry: 30,

        /**
        * by default, X-Userinfo, and X-Access-Token are
        * returned to the proxy, you can suppress that behavior by adding
        * the headers you do **NOT** want here.
        */
        filtered_service_headers: [],
      }
    },
    assertions: {
        /**
        * custom id_token assertions
        */
        id_token: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ],

        /**
        * custom userinfo assertions (only when oidc is enabled with fetch_userinfo)
        */
        userinfo: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ]
    }
}
```

## `firebase_jwt`

Verifies a firebase `idToken`.

```
{
    type: "firebase_jwt",
    realm: "my realm", // optional
    header_name: "Authorization", // optional
    scheme: "Bearer", // optional, if using a custom header_name without a scheme leave it blank
    config: {
        api_key: "...",
        project_id: "...",
        options: {
            checkRevoked: true, // if enabled also enable the fetch_userinfo feature and put a sane expiry (cache ttl)
            ...
            see details here: https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
            // issuer and audience are automatically validated
        }
    },
    features: {
        fetch_userinfo: true,
        userinfo_expiry: 30 // if > 0 userinfo will be cached (seconds)
    },
    assertions: {
        /**
        * custom id_token assertions
        */
        id_token: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ],

        /**
        * custom userinfo assertions
        */
        userinfo: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ]
    }
}
```

## `oauth2`

Initiates oauth `Authorization Code Flow` for authentication with any provider.

Some providers only allow a single active token per-user per-client_id. This
can be a limitation if the same user is using multiple browsers/sessions.

Please read [further details](OAUTH_PLUGINS.md) about configuration.

```
{
    type: "oauth2",
    
    issuer: {
        authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
    },

    client: {
        client_id: "...",
        client_secret: "..."
    },

    // generally this should be unset and the provider default utilized (for authorization_code flow this is generally query)
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes
    //response_mode: , // query or fragment

    // generally this should be unset and the default utilized
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes
    //response_types: ["code"],

    scopes: [],

    // pkce settings
    // https://oauth.net/2/pkce/
    pkce: {
      enabled: false,
      code_challenge_method: 'S256' // can also be 'plain'
    },

    // custom authorization URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    // NOTE: all critical fields are managed automatically, this should only be used in advanced scenarios
    // ie: https://developers.google.com/identity/protocols/OpenIDConnect#refresh-tokens
    custom_authorization_parameters: {},

    // custom authorization code URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    // NOTE: all critical fields are managed automatically, this should only be used in advanced scenarios
    // ie:
    // - https://stackoverflow.com/questions/50143342/keycloak-backchannel-logout/63517092#63517092
    // - https://keycloak.discourse.group/t/admin-url-not-called-when-user-logs-out/4163/8
    custom_authorization_code_parameters: {},

    // custom refresh URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    custom_refresh_parameters: {},

    // custom revoke URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    custom_revoke_parameters: {},

    /**
    * static redirect URI
    * if your oauth provider does not support wildcards place the URL configured in the provider (that will return to this proper service) here
    */
    redirect_uri: "https://eas.example.com/oauth/callback",
    features: {
        /**
        * how to expire the cookie
        * true = cookies expire will expire with tokens
        * false = cookies will be 'session' cookies
        * num seconds = expire after given number of seconds
        */
        cookie_expiry: false,

        /**
        * how frequently to refresh userinfo data
        * true = refresh with tokens (assuming they expire)
        * false = never refresh
        * num seconds = expire after given number of seconds
        */
        userinfo_expiry: true,

        /**
        * how long to keep a session (server side) around
        * true = expire with tokenSet (if applicable)
        * false = never expire
        * num seconds = expire after given number of seconds (enables sliding window)
        *
        * sessions become a floating window *if*
        * - tokens are being refreshed
        * or
        * - userinfo being refreshed
        * or
        * - session_expiry_refresh_window is a positive number
        */
        session_expiry: true,

        /**
        * window to update the session window based on activity if
        * nothing else has updated it (ie: refreshing tokens or userinfo)
        *
        * should be a positive number less than session_expiry
        *
        * For example, if session_expiry is set to 60 seconds and session_expiry_refresh_window value is set to 20
        * then activity in the last 20 seconds (40-60) of the window will 'slide' the window
        * out session_expiry time from whenever the activity occurred
        */
        session_expiry_refresh_window: 86400,

        /**
        * will re-use the same id (ie: same cookie) for a particular client if a session has expired
        */
        session_retain_id: true,

        /**
        * if the access token is expired and a refresh token is available, refresh
        */
        refresh_access_token: true,

        /**
        * which token (if any) to send back to the proxy as the Authorization Bearer value
        * note the proxy must allow the token to be passed to the backend if desired
        *
        * possible values are access_token, or refresh_token
        */
        authorization_token: "access_token",

        /**
        * by default, X-Id-Token, X-Userinfo, and X-Access-Token are
        * returned to the proxy, you can suppress that behavior by adding
        * the headers you do **NOT** want here.
        */
        filtered_service_headers: [],

        /**
        * fetch userinfo and include as X-Userinfo header to backing service
        * only helpful if your specific provider has been implemented
        */
        fetch_userinfo: true,

        /**
        * if you have a supported provider and want to assert or send userinfo via header
        * select the correct provider here
        */
        userinfo: {
            provider: "github",
            config: {
                fetch_teams: true,
                fetch_organizations: true,
                fetch_emails: true
            }
        },

        logout: {
          /**
          * Tokens to revoke with the provider on logout
          * can be id_token, access_token, and refresh_token depending on provider support
          * https://tools.ietf.org/html/rfc7009
          */
          revoke_tokens_on_logout: [],
        },
    },
    assertions: {
        /**
        * assert the token(s) has not expired
        */
        exp: true,

        /**
        * custom userinfo assertions
        */
        userinfo: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ]
    },
    //xhr detection is determind by the presence of an 'origin' header OR X-Requested-With: XMLHttpRequest
    xhr: {
        //defaults to 302 but could be set to anything
        //if set to 401 the response will include a WWW-Authenticate header with proper realm/scopes
        //redirect_http_code: 302,

        //if set to true, the browser will be redirected to the referer
        //use_referer_as_redirect_uri: true
    },
    csrf_cookie: {
        //enabled: true, //can disable the use of csrf cookies completely
        //domain: "example.com", //defaults to request domain, could do sso with more generic domain
        //path: "/",
        //httpOnly: true,
        //secure: false,
        //sameSite: lax,
    },
    cookie: {
        //name: "_my_company_session",//default is _oeas_oauth_session
        //domain: "example.com", //defaults to request domain, could do sso with more generic domain
        //path: "/",
        //httpOnly: true,
        //secure: false,
        //sameSite: lax,
    },
    // see HEADERS.md for details
    custom_error_headers: {},
    custom_service_headers: {},
}
```

## `oidc`

Initiates OpenID Connect `Authorization Code Flow` for authentication with any provider.

Some providers only allow a single active token per-user per-client_id. This
can be a limitation if the same user is using multiple browsers/sessions.

Please read [further details](OAUTH_PLUGINS.md) about configuration.

```
{
    type: "oidc",
    issuer: {
        /**
        * via discovery (takes preference)
        */
        //discover_url: "https://<provider>/.well-known/openid-configuration",

        /**
        * via manual definition
        */
        //issuer: 'https://accounts.google.com',
        //authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        //token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
        //userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
        //jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
    },
    client: {
        /**
        * manually defined (preferred)
        */
        client_id: "...",
        client_secret: "..."

        /**
        * via client registration
        */
        //registration_client_uri: "",
        //registration_access_token: "",
    },

    // generally this should be unset and the provider default utilized (for authorization_code flow this is generally query)
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes
    //response_mode: , // query or fragment

    // generally this should be unset and the default utilized
    // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseTypesAndModes
    //response_types: ["code"],

    scopes: ["openid", "email", "profile"], // must include openid

    // pkce settings
    // https://oauth.net/2/pkce/
    pkce: {
      enabled: false,
      code_challenge_method: 'S256' // can also be 'plain'
    },

    // nonce settings
    // https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
    nonce: {
      enabled: false,
      // how long eas should retain nonce data
      // note the nonce data is removed as quickly as possible during normal operation
      ttl: 600
    },

    // custom authorization URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    // NOTE: all critical fields are managed automatically, this should only be used in advanced scenarios
    // ie: https://developers.google.com/identity/protocols/OpenIDConnect#refresh-tokens
    custom_authorization_parameters: {},

    // custom authorization code URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    // NOTE: all critical fields are managed automatically, this should only be used in advanced scenarios
    // ie:
    // - https://stackoverflow.com/questions/50143342/keycloak-backchannel-logout/63517092#63517092
    // - https://keycloak.discourse.group/t/admin-url-not-called-when-user-logs-out/4163/8
    custom_authorization_code_parameters: {},

    // custom refresh URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    custom_refresh_parameters: {},

    // custom revoke URL parameters
    // values can be handlebars syntax with access to `req` and `parentReqInfo` objects (see examples/parent_request_info.json)
    custom_revoke_parameters: {},

    /**
    * static redirect URI
    * if your oauth provider does not support wildcards place the URL configured in the provider (that will return to this proper service) here
    */
    redirect_uri: "https://eas.example.com/oauth/callback",

    /**
    *
    * https://github.com/travisghansen/external-auth-server/issues/158
    *
    * the /oauth/callback-ua-client-code endpoint will cause the browser/user-agent to directly exchange the code for token(s) instead of eas
    * generally this highly unecessary, but can be used in scenarios where the brower/user-agent can communicate with both eas and op,
    * but eas cannot directly access op
    *
    * in order to use this flow:
    * - pkce enabled
    * - nonce enabled
    * - disable refresh_access_token
    * - disable introspect_access_token
    * - highly recommended to enable the sig(nature) assertion (otherwise session/token data can be spoofed)
    * - if indeed eas cannot reach op, you will need to manually define the issuer endpoints instead of discovery url
    *
    * The general flow is:
    * - eas directs the browser to op
    * - after successful auth browser is redirected to /oauth/callback-ua-client-code
    * - browser uses code in exchange for tokens and submits tokens to eas (using pure javascript)
    * - browser is redirected to eas to continue remaining auth process
    *
    */
    //redirect_uri: "https://eas.example.com/oauth/callback-ua-client-code",
    
    features: {
        /**
        * how to expire the cookie
        * true = cookies expire will expire with tokens
        * false = cookies will be 'session' cookies
        * num seconds = expire after given number of seconds
        */
        cookie_expiry: false,

        /**
        * how frequently to refresh userinfo data
        * true = refresh with tokens (assuming they expire)
        * false = never refresh
        * num seconds = expire after given number of seconds
        */
        userinfo_expiry: true,

        /**
        * how long to keep a session (server side) around
        * true = expire with tokenSet (if applicable)
        * false = never expire
        * num seconds = expire after given number of seconds (enables sliding window)
        *
        * sessions become a floating window *if*
        * - tokens are being refreshed
        * or
        * - userinfo being refreshed
        * or
        * - session_expiry_refresh_window is a positive number
        */
        session_expiry: true,

        /**
        * window to update the session window based on activity if
        * nothing else has updated it (ie: refreshing tokens or userinfo)
        *
        * should be a positive number less than session_expiry
        *
        * For example, if session_expiry is set to 60 seconds and session_expiry_refresh_window value is set to 20
        * then activity in the last 20 seconds (40-60) of the window will 'slide' the window
        * out session_expiry time from whenever the activity occurred
        */
        session_expiry_refresh_window: 86400,

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

        /**
        * check token validity with provider during assertion process
        */
        introspect_access_token: false,

        /**
        * if introspect_access_token is true, how long in seconds to cache the result
        * if not a number greater than 0, the introspection endpoint will be requested *every* verify request
        * NOTE: the cache is stored on a per-eas-session basis vs a per-token (jti) basis
        */
        introspect_expiry: 0,

        /**
        * which token (if any) to send back to the proxy as the Authorization Bearer value
        * note the proxy must allow the token to be passed to the backend if desired
        *
        * possible values are id_token, access_token, or refresh_token
        */
        authorization_token: "access_token",

        /**
        * by default, X-Id-Token, X-Userinfo, and X-Access-Token are
        * returned to the proxy, you can suppress that behavior by adding
        * the headers you do **NOT** want here.
        */
        filtered_service_headers: [],

        logout: {
          /**
          * Tokens to revoke with the provider on logout
          * can be id_token, access_token, and refresh_token depending on provider support
          * https://tools.ietf.org/html/rfc7009
          */
          revoke_tokens_on_logout: [],

          // details: https://github.com/travisghansen/external-auth-server/blob/master/OAUTH_PLUGINS.md#logout
          // https://openid.net/specs/openid-connect-rpinitiated-1_0.html
          "end_provider_session": {
            "enabled": false,
            "post_logout_redirect_uri": "https://eas.example.com/oauth/end-session-redirect"
          },

          // details: https://github.com/travisghansen/external-auth-server/blob/master/OAUTH_PLUGINS.md#logout
          // https://openid.net/specs/openid-connect-backchannel-1_0.html
          "backchannel": {
            // NOTE: this value can be altered instance-wide with the env var EAS_BACKCHANNEL_LOGOUT_CONFIG
            // see OAUTH_PLUGINS.md doc above for more details
            "enabled": false
          },
        },
    },
    assertions: {
        /**
        * assert the token(s) has the appropriate aud (client_id)
        */
        aud: true,

        /**
        * assert the token(s) has not expired
        */
        exp: true,

        /**
        * assert the 'not before' attribute of the token(s)
        */
        nbf: true,

        /**
        * assert the correct issuer of the token(s)
        */
        iss: true,

        /**
        * assert the token(s) has a valid signature
        * usually only needed when using the /oauth/callback-ua-client-code redirect_uri with browser code exchange
        */
        sig: {
          enabled: false,
          // defaults to issuer jwks endpoint, can be jwks response data or plain shared key/public key
          // secret:
        },

        /**
        * custom userinfo assertions
        */
        userinfo: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ],

        /**
        * custom id_token assertions
        */
        id_token: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ],

        /**
        * custom access_token assertions
        */
        access_token: [
            {
                ...
                see ASSERTIONS.md for details
            },
            {
                ...
            }
        ]
    },
    //xhr detection is determind by the presence of an 'origin' header OR X-Requested-With: XMLHttpRequest
    xhr: {
        //defaults to 302 but could be set to anything
        //if set to 401 the response will include a WWW-Authenticate header with proper realm/scopes
        //redirect_http_code: 302,

        //if set to true, the browser will be redirected to the referer
        //use_referer_as_redirect_uri: true
    },
    csrf_cookie: {
        //enabled: true, //can disable the use of csrf cookies completely
        //domain: "example.com", //defaults to request domain, could do sso with more generic domain
        //path: "/",
        //httpOnly: true,
        //secure: false,
        //sameSite: lax,
    },
    cookie: {
        //name: "_my_company_session",//default is _oeas_oauth_session
        //domain: "example.com", //defaults to request domain, could do sso with more generic domain
        //path: "/",
        //httpOnly: true,
        //secure: false,
        //sameSite: lax,
    },
    // see HEADERS.md for details
    custom_error_headers: {},
    custom_service_headers: {},
}
```

## `forward`

Proxy the response from another external/forward authentication service.

```
{
    type: "forward",
    url: "https://my.other.forward.auth.service.com",
    allow_insecure: false // self-signed certs
}
```

## `request_header`

Checks the request headers to allow the request. It operates as a logical `OR`
meaning, as soon as a matched value is found for **ANY** of the specified
headers the request is allowed.

Be sure your reverse proxy is passing the appropriate headers to the service.

```
{
    type: "request_header",
    headers: {
        "X-FooBar": ["value1", "value2", ...],
        "X-FooBaz": "other value"
    }
}
```

## `request_js`

Is a powerful plugin to essentially build your own plugin. Due to the level of
_trust_ required between the deployment of the service and those issuing
`config_token`s the `request_js` plugin is only available if the
`EAS_ALLOW_EVAL` environment variable has been set. The plugin receives direct
access to `eas` internals and can execute arbitrary code on the server
including `process.exit()` etc. You have been warned :)

Having said all that, great power comes from this plugin. The context of the
invoked code will have access to several variables:

- `req` - the object representing the request to the `eas` server, this
  includes access to request headers
- `res` - the mock response object used by `eas` internally for all plugins.
  This primarily can/will be used to set the plugin's `statusCode` and any
  appropriate headers
- `configToken` - the decoded `config_token` for the request
- `plugin` - the invoked instance of the `request_js` plugin. Mostly useful to
  invoke various `util` methods and access the core `eas` server instance if
  necessary
- `parentReqInfo` - this is contains details about the request to the reverse
  proxy (as opposed to `eas` itself). For example, the original request method
  and uri parsed etc.

```
{
    type: "request_js",
    "snippet": "...javascript code...",
}
```

A common use-case for this plugin would be to selectively allow _public_
endpoints to be authenticated without going through the normal pipeline.

```
# allow request based on VERB
"snippet": "if (parentReqInfo.method == 'GET') res.statusCode = 200;",

# allow request based on HOST + PATH
"snippet": "if (parentReqInfo.parsedUri.host == 'foo.example.com' && parentReqInfo.parsedUri.path == '/public/endpoint') res.statusCode = 200;",

# setting a header
"snippet": "res.setHeader('foo', 'bar');",
```

## `request_param`

Checks the request parameters to allow the request. It operates as a logical
`OR` meaning, as soon as a matched value is found for **ANY** of the specified
params the request is allowed.

```
{
    type: "request_param",
    params: {
        "auth_param1": ["value1", "value2", ...],
        "auth_param1": "other value"
    }
}
```

## `noop`

Helpful if you want to only do [header injection](HEADERS.md). For example
inject a static `jwt` to a backing service.

```
{
    type: "noop",
    status_code: 200 // optional, can be used with pcb, etc to conditionally return failure codes
}
```
