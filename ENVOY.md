There is a fall through list of preference for each of the following:

- verify params
- proto
- port

For each the preference is in the following order:

1. header (only for proto since it can generally be trusted)
2. filter metadata (see below)
3. initial metadata (see below)
4. context
5. implicit data (such as the port envoy is running on etc)

## filter metadata syntax

```
          http_filters:
          - name: envoy.filters.http.lua
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
              inline_code: |
                function envoy_on_request(request_handle)
                  local headers = request_handle:headers()
                  request_handle:streamInfo():dynamicMetadata():set("eas", "eas", {
                    -- must use this key syntax due to hyphens in key name
                    -- must add `eas` to `metadata_context_namespaces` in the authz filter
                    -- remove the `--` below for the values/lines you wish to explicitly set/override
                    -- ["x-eas-verify-params"] = '{"config_token_store_id":"dep_a", "config_token_id":"keycloak"}',
                    -- ["x-forwarded-port"] = 443,
                    -- ["x-forwarded-proto"] = "http",
                  })
                end
...
          - name: envoy.filters.http.ext_authz-grpc
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              metadata_context_namespaces:
              - eas
```

## initial metadata syntax

```
          - name: envoy.filters.http.ext_authz-grpc
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              stat_prefix: ext_authz_eas
              transport_api_version: V3
              grpc_service:
                # uncomment the fields below you wish to explicitly set/override
                initial_metadata:
                #- key: x-eas-verify-params
                #  value: '{"config_token_store_id":"dep_a", "config_token_id":"keycloak"}'
                #- key: x-forwarded-proto
                #  value: https
                #- key: x-forwarded-port
                #  value: 443
                envoy_grpc:
                  cluster_name: eas-grpc
                timeout: 5.00s
```

Note that any of the above can be used simultaneous and the preference will be given as explained above. For example if both initial metadata and filter metadata set the `x-forwarded-port` value, the filter metadata value will 'win' and take precedence over the initial metadata value.
