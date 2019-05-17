# Assertions

Custom assertions allow you place fine-grained access controls over who can
authenticate and who cannot. Assertions apply to `userinfo` in the case of
both `oauth2` and `oidc` plugins. `id_token` assertions are only available in
the case of `oidc`.

The basic idea is to select a `path` (relative to `userinfo` or `id_token`
respectively) using [`jsonpath`](https://github.com/dchester/jsonpath) syntax.

You then define the `rule` by declare the following properties:

- `method` - this determines how the assertion will be compared
- `value` - this determines what the selected `path` value will be compared
  against
- `negate` - this will negate the comparison result
- `case_insensitive` - will make sure compared values are done in a
  case-insensitive manner

Valid options for method are:

- `eq` - The values are equal. This assumes the `path` is ensured to only
  return a single value.
- `regex` - The value passes a regex comparison. This assumes the `path` is
  ensured to only return a single value.
- `in` - The selected value is `in` the provided list. This assumes the `path`
  is ensured to only return a single value. The `value` should be an array.
- `contains` - The selected value `contains` the option specified as the
  `value`. This assumes the `path` is returning a list of values.
- `contains-any` - Similar to `contains` but allows the `value` to be a list of
  items. If **any** of the items in `value` are found in the `path` result then
  the assertion passes. This assumes the `path` is returning a list of values.
- `contains-all` - Similar to `contains` but allows the `value` to be a list of
  items. If **all** of the items in `value` are found in the `path` result then
  the assertion passes. This assumes the `path` is returning a list of values.

## examples

These examples are taken from the `userinfo` dataset supplied by the `github`
`userinfo` provider. Each provider will have varying syntax and dataset for the
`userinfo` and/or `id_token` values so it's impossible to document them all
here. You can refer to the documentation of your provider or observe the values
in logs or request headers to backing services (if properly enabled).

```
{
    path: "$.login",
    rule: {
        method: "eq",
        value: "myusername",

        //negate: true,
        //case_insensitive: true
    }
}

{
    path: "$.login",
    rule: {
        method: "regex",

        // "/pattern/[flags]"
        value: "/^myuser/",

        //negate: true,
        //case_insensitive: true
    }
}

{
    path: "$.login",
    rule: {
        method: "in",
        value: ["myuser1", "myuser2", ...],

        //negate: true,
        //case_insensitive: true
    }
}

{
    path: "$.emails[*].email",
    rule: {
        method: "contains",
        value: "myemail@example.com",

        //negate: true,
        //case_insensitive: true
    }
}

{
    path: "$.emails[*].email",
    rule: {
        method: "contains-any",
        value: ["user1@example.com", "user2@example.com", ...],

        //negate: true,
        //case_insensitive: true
    }
}

{
    path: "$.emails[*].email",
    rule: {
        method: "contains-all",
        value: ["user1@example.com", "user1@another.com", ...]

        //negate: true,
        //case_insensitive: true
    }
}
```
