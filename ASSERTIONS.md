# Assertions

Custom assertions allow you place fine-grained access controls over who can
authenticate and who cannot or plugin behavior via `pcb` (pipeline/plugin)
circuit breakers.

Assertions are logical `AND`s so **all** must pass.

The basic idea is to select a value from the dataset using a `query` with
[`jsonpath`](https://github.com/dchester/jsonpath) or
[`jq`](https://stedolan.github.io/jq/) syntax.

You pick the `query` syntax by setting the `query_engine` parameter:

- `handlebars` uses handlebars syntax
- `jp` for jsonpath (highest performance)
- `jq` for jq (highly flexible, slowest performance)
- `jsonata` for jsonata (highly flexible, high performance)
- `js` for eval'd js code (env var `EAS_ALLOW_EVAL` required) For this engine
  the data will be available as a variable named `data`.

You then define the `rule` by declaring the following properties:

- `method` - this determines how the assertion will be compared
- `value` - this determines what the selected `query` value will be compared
  against
- `negate` - this will negate the comparison result
- `case_insensitive` - will make sure compared values are done in a
  case-insensitive manner

Valid options for method are:

- `eq` - The values are equal. This assumes the `query` is ensured to only
  return a single value.
- `regex` - The value passes a regex comparison. This assumes the `query` is
  ensured to only return a single value.
- `in` - The selected value is `in` the provided list. This assumes the `query`
  is ensured to only return a single value. The `value` should be an array.
- `contains` - The selected value `contains` the option specified as the
  `value`. This assumes the `query` is returning a list of values.
- `contains-any` - Similar to `contains` but allows the `value` to be a list of
  items. If **any** of the items in `value` are found in the `query` result then
  the assertion passes. This assumes the `query` is returning a list of values.
- `contains-all` - Similar to `contains` but allows the `value` to be a list of
  items. If **all** of the items in `value` are found in the `query` result then
  the assertion passes. This assumes the `query` is returning a list of values.

## examples

These examples are taken from the `userinfo` dataset supplied by the `github`
`userinfo` provider. Each provider will have varying syntax and dataset for the
`userinfo` and/or `id_token` values so it's impossible to document them all
here. You can refer to the documentation of your provider or observe the values
in logs or request headers to backing services (if properly enabled).

```
{
    query_engine: "jp",
    query: "$.login",
    rule: {
        method: "eq",
        value: "myusername",

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.login",
    rule: {
        method: "regex",

        // "/pattern/[flags]"
        value: "/^myuser/",

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.login",
    rule: {
        method: "in",
        value: ["myuser1", "myuser2", ...],

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.emails[*].email",
    rule: {
        method: "contains",
        value: "myemail@example.com",

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.emails[*].email",
    rule: {
        method: "contains-any",
        value: ["user1@example.com", "user2@example.com", ...],

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.emails[*].email",
    rule: {
        method: "contains-all",
        value: ["user1@example.com", "user1@another.com", ...]

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.teams[*].id",
    rule: {
        method: "contains-any",
        value: ["12345678", "99999999", ...]

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.teams[*].organization.id",
    rule: {
        method: "contains-any",
        value: ["12345678", "99999999", ...]

        //negate: true,
        //case_insensitive: true
    }
}

{
    query_engine: "jp",
    query: "$.two_factor_authentication",
    rule: {
        method: "eq",
        value: true,

        //negate: true,
        //case_insensitive: true
    }
}
```

An example of each engine all yielding the same result:

```
{
  "query_engine": "handlebars",
  "query": "{{ login }}",
  "rule": {
    "method": "eq",
    "value": "travisghansen"
  }
}

{
  "query_engine": "jp",
  "query": "$.login",
  "rule": {
    "method": "eq",
    "value": "travisghansen"
  }
}

{
  "query_engine": "jq",
  "query": ".login",
  "rule": {
    "method": "eq",
    "value": "travisghansen"
  }
}

{
  "query_engine": "jsonata",
  "query": "login",
  "rule": {
    "method": "eq",
    "value": "travisghansen"
  }
}

{
  "query_engine": "js",
  "query": "return data.login;",
  "rule": {
    "method": "eq",
    "value": "travisghansen"
  }
}
```
