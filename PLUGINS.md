# Plugins

## `htpasswd`

Performs `Basic` authentiaction using a standard `htpasswd` file.

```
{
    type: "htpasswed",
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
        ...
        see for details https://github.com/vesse/node-ldapauth-fork#ldapauth-config-options
    }
}
```

## `oauth2`

Initiates oauth `Authorization Code Flow` for authentication with any provider.

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
    scopes: [],
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
        set_cookie_expiry: false,

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
        authorization_token: "access_token"
    },
    assertions: {
        /**
        * assert the token(s) has not expired
        */
        exp: true,
    },
    cookie: {
        //name: "_my_company_session",//default is _oeas_oauth_session
        //domain: "example.com", //defaults to request domain, could do sso with more generic domain
        //path: "/",
    }
}
}
```

## `oidc`

Initiates OpenID Connect `Authorization Code Flow` for authentication with any provider.

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
    scopes: ["openid", "email", "profile"], // must include openid
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
        set_cookie_expiry: false,

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
        * which token (if any) to send back to the proxy as the Authorization Bearer value
        * note the proxy must allow the token to be passed to the backend if desired
        *
        * possible values are id_token, access_token, or refresh_token
        */
        authorization_token: "access_token"
    },
    assertions: {
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
    },
    cookie: {
        //name: "_my_company_session",//default is _oeas_oauth_session
        //domain: "example.com", //defaults to request domain, could do sso with more generic domain
        //path: "/",
    }
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
