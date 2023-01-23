# Headers

Various plugins (namely `oauth2` and `oidc`) allow for injecting specific
headers and values to be passed down to the backing service.

Note, the reverse proxy may need to be configured to pass/allow headers as
desired.

`custom_service_headers` or `customer_error_headers` can be declared at the
`config_token` level or at the `plugin` level.

`custom_service_headers` are injected in the case of a successful
response/operation with `eas` and will be passed to the backing service.

`custom_error_headers` are injected in the case of a failure response/operation
with `eas` and will be passed to user agent (ie: browser) with the failure
response. Note that in failure scenario less data may be available to `query`
as tokens etc may not exist.

```
{
    eas: {
        plugins: [
            {
                ...
                custom_error_headers: {},
                custom_service_headers: {}
            }
        ]
        custom_error_headers: {},
        custom_service_headers: {}
    }
}
```

```
{
    ...
    custom_service_headers: {
        "X-Injected-FooBarBaz": {
            source: "userinfo",// userinfo, id_token, access_token, refresh_token, static, config_token, plugin_config, req, parentRequestInfo
            query_engine: "jp",
            query: "$.emails[*].email", // if left blank the data will be passed unaltered (ie: jwt encoded data)
            encoding: "plain", // may be set to base64

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
