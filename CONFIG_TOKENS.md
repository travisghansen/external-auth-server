# `config_token`s

`config_token`s are the foundational piece of `eas`. The whole configuration of
each authentication configuration is embedded in the token.

## stateless tokens

see [`bin/generate-config-token.js`](bin/generate-config-token.js) and
[authentication plugins](PLUGINS.md) for details.

## server-side tokens

`eas` allows for server-side tokens (stateful) to eliminate the need to update
reverse proxy configuration and/or centrally manage `config_token`s.

2 options exist to utilize server-side tokens:

1. specified via URL params
1. specified via a pointer token

Both methods are meant to relays 2 datapoints to the server:

1. `config_token_store_id`
1. `config_token_id`

The values for both are generally arbitrary.

The `config_token_store_id` must correlate to the appropriate backing store
configuration as declared in the `EAS_CONFIG_TOKEN_STORES` environment
variable (see [`bin/generate-config-token-stores.js`](bin/generate-config-token-stores.js)).

Subsequently, the `config_token_id` should be available as appropriate in the given
store.

### token specified via URL params

In the `/verify` endpoint simply specify the following URL params:

- `config_token_store_id` || `config_token_store_id_query_engine` AND `config_token_store_id_query`
- `config_token_id` || `config_token_id_query_engine` AND `config_token_id_query`

An example:

```
http://127.0.0.1:9000/verify?fallback_plugin=5&config_token_store_id=primary&config_token_id=1
```

The query `*_query*` variants allow you selectively pick a respective value
based on the _nature_ of the request. For example you create `config_token`s
which have IDs that correspond the URI or host of the service.

See below for further explanation about using the `*_query*` variants.

- https://github.com/travisghansen/external-auth-server/issues/29#issuecomment-541365383

### token specified via pointer token

See [`bin/generate-server-side-config-token.js`](bin/generate-server-side-config-token.js)

The general idea is to create 2 `config_token`s, one which contain essentially
a pointer to the real `config_token` and a 2nd which will be stored statefully.

The 'pointer' `config_token` will be used when configuring the reverse proxy
authentication URL and should contain 2 attributes:

```
{
...
    eas: {
        config_token_id: "token_id",
        config_token_store_id: "store_id"
    }
...
}
```

### `file` adapter

To store tokens in a file simply create a `.json` file with key/value pairs
where the key is the `token_id` and the value is the encrypted `config_token`
(be sure to use the non URL safe data)

Example store configuration:

```
{
    adapter: "file",
    options: {
        //cache_ttl: 3600, // optional, defaults to no caching
        path: "/path/to/token.json"
    }
}
```

Example `.json` file:

```
{
    "token_id_1": "encrypted token data",
    "token_id_2": "encrypted token data"
}
```

Again, the `token_id` (key) is arbitrary but must match whatever was used when
generating the corresponding `config_token` as configured at the reverse proxy.

### `env` adapter

The `env` adapter behaves exactly as the `file` adapter but insead of storing
the json data on disk it resides in an environment variable.

Example store configuration:

```
{
    adapter: "env",
    options: {
        //cache_ttl: 3600, // optional, defaults to no caching
        var: "CONFIG_TOKENS"
    }
}
```

### `sql` adapter

The `sql` adapter will lookup tokens as stored in a database.

Exapmle store configuration:

```
{
    adapter: "sql",
    options: {
        //cache_ttl: 3600, // optional, defaults to no caching
        query: "SELECT token as token from config_tokens WHERE id = ? AND revoked != 1",
        config: {
            client: "mysql",
            connection: {
                host: "dbhost",
                user: "dbuser",
                password: "dbpassword",
                database: "eas"
            }
        }
    }
}
```

The column containing the `config_token` must be `SELECT`ed as `token`. Place
the `?` where the `token_id` will be injected.

The details of the `options.config` block can be found at the
[knex documentation](https://knexjs.org/#Installation-client).

Supported databases include mysql, postgres, sqlite, mssql, and oracle.

Example schema (mysql):

```
CREATE DATABASE `eas`;

CREATE TABLE `config_tokens` (
  `id` char(255) NOT NULL,
  `token` text NOT NULL,
  `revoked` tinyint NOT NULL
);

ALTER TABLE `config_tokens`
ADD PRIMARY KEY `id` (`id`);

ALTER TABLE `config_tokens`
ADD INDEX `id_revoked` (`id`, `revoked`);
```
