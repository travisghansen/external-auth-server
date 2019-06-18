# Intro

By far the `oidc` and `oauth2` plugins are the most copmlex of `eas`. Several
factors are involved in this but this also makes the configuration more
intricate. This document is an effort to provide as much info as possible to
provide more detail into the various parts.

# Stateful

A key thing to understand is that the `oidc` and `oauth2` plugins create a
stateful session with `eas`. This is why redis is generally required if using
either plugin as sessions are stored in redis.

All of this is managed via a signed cookie which is stored by the user-agent
(browser) for a configurable period of time (see `cookie_expiry` option). The
various other cookie options are configurable as well
(`name`, `domain`, `path`, etc) on a per-`config_token` basis. With careful
configuration you can enable SSO scenarios amongst other options.

Generally, `eas` ensures the presense of the appropriately named cookie and
ensures it was signed by `eas`. This can however result in an insecure setup as
several services secured by the same `eas` deployment all share the same cookie
signing key. To overcome this threat, `eas` sessions are bound to a particular
audience. You can configure this audience by setting the `aud` value in the/a
`config_token` to a specific value. Any services sharing that same `aud` will
consider sessions valid. If the `aud` value is omitted in the `config_token`
then `eas` will generate a unique hash of the complete `config_token` data and
use that as the `aud` value. This is a 'secure by default' approach but allows
for powerful control by operators to meet their unique/individual needs.

If you intend to secure several services with the same `config_token` using
`oidc` or `oauth2` (SSO), then there are several recommendations:

- explicitly set the `aud` value in the `config_token`
- explicitly set the `redirect_uri` to point to
  `https://eas.example.com/oauth/callback`
- explicitly set the `cookie.domain` value to the generic domain `example.com`
- carefully consider the `cookie.name` and `cookie.path` values as appropriate
- ensure unique combinations of `aud`, `cookie.domain`, and `cookie.name` for
  disperse services which should **NOT** share sessions

As an example, consider a scenario with 2 different `config_token`s (perhaps
different `oidc` providers or perhaps requiring different `assertions`) which
will be used across 10 different services (5 each) each with the same TLD. The
configuration outlined below will ensure each `config_token` is only used when
appropriate and will ensure different services are not conflicting with each
other for the session data. It also ensures the services are properly secured
according to operator desires.

The applicable `config_token` options would be:

## token 1

- `aud` set to `company-basic`
- `cookie.domain` set to `example.com`
- `cookie.name` set to `_oeas_oauth_session_basic`
- `redirect_uri` set to `https://eas.example.com/oauth/callback`

## token 2

- `aud` set to `admins`
- `cookie.domain` set to `example.com`
- `cookie.name` set to `_oeas_oauth_session_admins`
- `redirect_uri` set to `https://eas.example.com/oauth/callback`
