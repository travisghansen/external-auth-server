# Headers

Various plugins (namely `oauth2` and `oidc`) allow for injecting specific
headers and values to be passed down to the backing service.

Note, the reverse proxy may need to be configured to pass/allow headers as
desired.

`custom_service_headers` can be declared at the `config_token` level or at the
`plugin` level.

```
{
    eas: {
        plugins: [
            {
                ...
                custom_service_headers: {}
            }
        ]
        custom_service_headers: {}
    }
}
```

```
{
    ...
    custom_service_headers: {
        "X-Injected-FooBarBaz": {
            source: "userinfo",// userinfo, id_token, access_token, refresh_token, static, config_token, plugin_config
            query_engine: "jp",
            query: "$.emails[*].email", // if left blank the data will be passed unaltered (ie: jwt encoded data)

            query_engine: "jp",
            query: "$.login",
            query_opts: {
                single_value: true // by default, a jsonpath query always returns a list (ie: array), this force the value to be the fist value in the array
            },

            //query_engine: "jq",
            //query: "[ .emails[].email ][0]",
            //query: "[ .emails[].email ] | first",
            //query: "[ .emails[].email ] | last",
            //query: "[ .emails[].email ] | nth(0)",

            //source: "static",
            //query_engine: "static",
            //query: "some static data"
        }
    }
    ...
}
```
