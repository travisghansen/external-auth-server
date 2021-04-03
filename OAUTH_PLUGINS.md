# Intro

By far the `oidc` and `oauth2` plugins are the most complex of `eas`. Several
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

## Logout

If you wish to destroy a session with `eas` you may send the user to any link
that would invoke `eas` from an authentication perspective (ie: do NOT send the
user agent to `eas` directly) including the following `GET` parameters:

- `__eas_oauth_handler__=logout`
- `redirect_uri=<url encoded redirect location>`

As an example, if you are authenticating the domain `https://svc.example.com`
with `eas` you could direct the browser to
`https://svc.example.com?__eas_oauth_handler__=logout&redirect_uri=https%3A%2F%2Fgithub.com`

### Token revocation

Optionally, when invoking the logout URL `eas` can revoke the tokens with the
provider. This is controlled by the `features.logout.revoke_tokens_on_logout`
setting in the `config_token` plugin config. It implements
https://tools.ietf.org/html/rfc7009 and is available for both `oauth2` and
`oidc`.

- https://tools.ietf.org/html/rfc7009
- https://identityserver4.readthedocs.io/en/latest/endpoints/endsession.html

### End provider session (`oidc`)

When `features.logout.end_provider_session.enabled` is `true` then upon logout
`eas` will redirect the user to end the session with the provider.

For the complete process to work you should register `https://eas.example.com/oauth/end-session-redirect`
as a valid `redirect_uri` with your provider. The endpoint should be directly
accessing the `eas` service, and accessible to the user agent (ie: browser).

The `redirect_uri` `GET` parameter of the `eas` logout page mentioned above
will still be the final destination of the brower but a couple detours are made
to ensure that happens. The series of redirects looks like this:

```
`eas` logout page requested ->
session is destroyed (with `eas`) and optionally tokens revoked ->
brower redirected to provider endpoint to destroy session ->
session is destroy with provider -> (note, typically this action would result in the provider invoking the backchannel logout (see below) for all relevant client_id's)
provider forward back to `features.logout.end_provider_session.post_logout_redirect_uri` (which should be `eas` directly exposed `/oauth/end-session-redirect` endpoint) ->
originally requested `redirect_uri` is parsed from encrypted `state` and finally browser is redirected to final destination
```

- https://openid.net/specs/openid-connect-rpinitiated-1_0.html

### Backchannel (`oidc`)

`backchannel` logout is a feature where logouts that occur with the provider
are propogated down immediately any/all oidc `client_id`'s that have been
configured to support the feature implementing a form of single logout.

#### Considerations

Typically, providers only allow you register a single `backchannel` URI. As
such (this may seem obvious) proper utilization of the feature is only
available when a `cliend_id` with your provider maps to a single deployment of
`eas`. If you share a `client_id` that spans multiple `eas` deployments you
cannot effectively leverage the `backchannel` logout feature.

Due to the unique approach of `eas` and the various configuration possibilities
when `backchannel` logouts occur the `tokens` are **NOT** revoked with the
provider immediately but will be revoked the first time a user tries to access
a relevant `eas`-secured service. Note that the `eas` session is effectively
revoked immediately but if the tokens are being used downstream of `eas` to
access other services, then the tokens will remain unrevoked until the user
accesses an `eas` backed service which will finalize the `backchannel` logout
process revoking the `tokens` with the provider.

If your store (ie: redis) does not persist to disk then `backchannel` support
not be effective in the case of catostrophic failure/restart of the store.

#### Configuration

For `backchannel` logout to work, the `eas` must be directly exposed to the
provider. The `/oauth/backchannel-logout` endpoint of `eas` will be invoked by
the provider (ie: `https://eas.example.com/oauth/backchannel-logout?...`).

1. Create a `backchannel_config_token` in a similar fashion as a `config_token`
   is created. See `bin/generate-backchannel-config-token.js`.

1. Use the `backchannel_config_token` generated above to register the
   `backchannel` logout URL with your provider. ie:
   `https://eas.example.com/oauth/backchannel-logout?backchannel_config_token=<generated token>`

1. In your `config_token` ensure the `backchannel` feature has been enabled. If
   you wish to force this value and/or set defaults you may use the env var
   `EAS_BACKCHANNEL_LOGOUT_CONFIG`

```
env EAS_BACKCHANNEL_LOGOUT_CONFIG syntax

default/forced values can be true/false and/or omitted

The value of `forced` **IS** the forced value, not if forcing
is enabled/disabled. If you do not wish to force a value omit
the `forced` key in your config.

Precidence is given to issuer specific keys over _fallback if present.

{
  "enabled": {
    "_fallback": {
      "default": true,
      "forced": true
    },
    "issuers": {
      "some issuer": {
        "default": true,
        "forced": true
      },
      "https://<keycloak>/auth/realms/<my realm>": {
        "default": true,
        "forced": true
      }
      ...
    }
  },
  "ttl": {
    ...same syntax as 'enabled' key, value of default/forced should be # of seconds to retain logout entries in the store
  }
}

# example: backchannel support enabled unconditionally
{
  "enabled": {
    "_fallback": {
      "forced": true
    }
  }
}

# example: backchannel support disabled unconditionally
{
  "enabled": {
    "_fallback": {
      "forced": false
    }
  }
}

# example: backchannel support enabled unconditionally for specific issuer
{
  "enabled": {
    "issuers": {
      "myissuer": {
        "forced": true
      }
    }
  }
}

# example: backchannel support relagated to `config_token` unless the value is not explicitly set
# otherwise default to off
{
  "enabled": {
    "_fallback": {
      "default": false
    }
  }
}
```

- https://openid.net/specs/openid-connect-backchannel-1_0.html
