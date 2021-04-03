const { Assertion } = require("../../assertion");
const { BasePlugin } = require("..");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const { Issuer, custom } = require("openid-client");

custom.setHttpOptionsDefaults({
  followRedirect: false,
  timeout: 10000,
  headers: {},
});

if (process.env.DEBUG_OIDC) {
  custom.setHttpOptionsDefaults({
    hooks: {
      beforeRequest: [
        (options) => {
          console.log(
            "--> %s %s",
            options.method.toUpperCase(),
            options.url.href
          );
          console.log("--> HEADERS %o", options.headers);
          if (options.body) {
            console.log("--> BODY %s", options.body);
          }
        },
      ],
      afterResponse: [
        (response) => {
          console.log(
            "<-- %i FROM %s %s",
            response.statusCode,
            response.request.options.method.toUpperCase(),
            response.request.options.url.href
          );
          console.log("<-- HEADERS %o", response.headers);
          if (response.body) {
            console.log("<-- BODY %s", response.body);
          }
          return response;
        },
      ],
    },
  });
}

const INTROSPECTION_CACHE_PREFIX = "introspection:jwt:";
const USERINFO_CACHE_PREFIX = "userinfo:jwt:";
const DEFAULT_CLIENT_CLOCK_TOLERANCE = 5;
const ISSUER_CACHE_DURATION = 43200 * 1000;
const CLIENT_CACHE_DURATION = 43200 * 1000;

const CACHE_TYPE_INTROSPECTION = "introspection";
const CACHE_TYPE_USERINFO = "userinfo";

function token_is_expired(token) {
  return !!(token.exp && token.exp < Date.now() / 1000);
}

function initialize_common_config_options(config) {
  config.oidc = config.oidc || {};
  config.assertions = config.assertions || {};

  if (!config.oidc.hasOwnProperty("enabled")) {
    config.oidc.enabled = false;
  }

  if (!config.oidc.features) {
    config.oidc.features = {};
  }
}

/**
 * https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
 */
class JwtPlugin extends BasePlugin {
  static initialize(server) {}

  /**
   * Create new instance
   *
   * @name constructor
   * @param {*} config
   */
  constructor(server, config) {
    initialize_common_config_options(config);
    super(...arguments);
  }

  /**
   * Verify the request
   *
   * @name verify
   * @param {*} configToken
   * @param {*} req
   * @param {*} res
   */
  async verify(configToken, req, res) {
    const plugin = this;
    const cache = plugin.server.cache;
    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    plugin.server.logger.verbose("parent request info: %j", parentReqInfo);

    let realm = plugin.config.realm;

    if (!realm && plugin.config.oidc.enabled) {
      const issuer = await plugin.get_issuer();
      realm = issuer.token_endpoint;
    }

    if (!realm) {
      realm = parentReqInfo.uri;
    }

    let header_name = plugin.config.header_name
      ? plugin.config.header_name
      : "authorization";
    header_name = header_name.toLowerCase();

    let scheme = plugin.config.scheme;

    if (!scheme) {
      if (header_name == "authorization") {
        scheme = "bearer";
      }
    }

    scheme = scheme.toLowerCase();

    let error, error_description;
    const failure_response = function (code = 401) {
      res.statusCode = code || 401;

      if (scheme == "bearer") {
        //Bearer realm="example", error="invalid_token", error_description="The access token expired"
        let value = 'Bearer realm="' + realm + '"';
        if (error) {
          value = value + ', error="' + error + '"';
        }

        if (error_description) {
          value = value + ', error_description="' + error_description + '"';
        }

        res.setHeader("WWW-Authenticate", value);
      }
    };

    if (!req.headers[header_name]) {
      failure_response();
      return res;
    }

    if (
      scheme &&
      !plugin.server.utils.authorization_scheme_is(
        req.headers[header_name],
        scheme
      )
    ) {
      failure_response();
      return res;
    }

    let creds = {};
    if (scheme) {
      creds = plugin.server.utils.parse_bearer_authorization_header(
        req.headers[header_name]
      );
    } else {
      creds.token = req.headers[header_name];
    }

    const config = plugin.config.config;

    // configure jwks secret automatically when oidc is enabled
    if (plugin.config.oidc.enabled && !config.secret) {
      const issuer = await plugin.get_issuer();
      config.secret = issuer.metadata.jwks_uri;
    }

    function getKey(header, callback) {
      if (
        config.secret.startsWith("http://") ||
        config.secret.startsWith("https://")
      ) {
        /**
         * cache the client in memory to inherit the jwks caching from the upstream lib/client
         * https://github.com/auth0/node-jwks-rsa#caching
         */
        const jwksClientOptionHash = plugin.server.utils.md5(
          JSON.stringify(config.secret)
        );
        const cache_key = "jwt:jwks:clients:" + jwksClientOptionHash;
        let client = cache.get(cache_key);
        if (client === undefined) {
          plugin.server.logger.debug(
            "creating jwks client for URI %s",
            config.secret
          );
          client = jwksClient({
            jwksUri: config.secret,
          });
          cache.set(cache_key, client, CLIENT_CACHE_DURATION);
        } else {
          plugin.server.logger.debug(
            "using cached jwks client for URI %s",
            config.secret
          );
        }

        client.getSigningKey(header.kid, function (err, key) {
          if (err) {
            callback(err, null);
          } else {
            const signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
          }
        });
      } else {
        callback(null, config.secret);
      }
    }

    try {
      const token = await new Promise((resolve, reject) => {
        jwt.verify(creds.token, getKey, config.options, (err, decoded) => {
          if (err) {
            reject(err);
          }
          resolve(decoded);
        });
      });

      plugin.server.logger.debug("jwt token: %j", token);

      // not really a session per-se, but treating it as such below
      const session_id = plugin.server.utils.md5(
        JSON.stringify(plugin.config) + ":" + creds.token
      );

      const valid = await plugin.assertions(creds.token, token, session_id);
      if (valid !== true) {
        error = "invalid_user";
        error_description = "user did not pass assertions";

        failure_response(403);
        return res;
      }

      // introspection
      if (
        plugin.config.oidc.enabled &&
        plugin.config.oidc.features.introspect_access_token
      ) {
        const valid = await plugin.introspect_access_token(
          creds.token,
          session_id
        );
        if (valid !== true) {
          error = "invalid_token";
          error_description = "token failed introspection";

          failure_response();
          return res;
        }
      }

      // userinfo
      let userinfo;
      if (
        plugin.config.oidc.enabled &&
        plugin.config.oidc.features.fetch_userinfo
      ) {
        userinfo = await plugin.get_userinfo(creds.token, token, session_id);
      }

      if (plugin.config.oidc.enabled && plugin.config.assertions.userinfo) {
        let valid = await Assertion.assertSet(
          userinfo,
          plugin.config.assertions.userinfo
        );

        if (!valid) {
          error = "invalid_user";
          error_description = "user did not pass userinfo assertions";

          failure_response(403);
          return res;
        }
      }

      if (plugin.config.oidc.enabled) {
        if (plugin.config.oidc.features.fetch_userinfo) {
          res.setHeader("X-Userinfo", JSON.stringify(userinfo));
        }
        res.setHeader("X-Access-Token", creds.token);
      }

      res.setAuthenticationData({
        id_token: creds.token,
        userinfo: userinfo,
      });
      res.statusCode = 200;
      return res;
    } catch (e) {
      switch (e.name) {
        case "TokenExpiredError":
        case "JsonWebTokenError":
        case "NotBeforeError":
          error = e.name;
          error_description = e.message;
          break;
        default:
          throw e;
      }
    }

    failure_response();
    return res;
  }

  async assertions(token, token_decoded, session_id) {
    const plugin = this;
    let isValid = true;

    if (plugin.config.assertions && plugin.config.assertions.id_token) {
      isValid = await Assertion.assertSet(
        token_decoded,
        plugin.config.assertions.id_token
      );

      if (!isValid) {
        return false;
      }
    }

    return true;
  }

  async get_issuer() {
    const plugin = this;
    const cache = plugin.server.cache;
    const discover_url = plugin.config.oidc.issuer.discover_url;
    let issuer;

    if (discover_url) {
      const cache_key = "issuer:" + plugin.server.utils.md5(discover_url);
      issuer = cache.get(cache_key);
      if (issuer !== undefined) {
        return issuer;
      }
      issuer = await Issuer.discover(discover_url);
      cache.set(cache_key, issuer, ISSUER_CACHE_DURATION);
      return issuer;
    } else {
      const cache_key =
        "issuer:" +
        plugin.server.utils.md5(JSON.stringify(plugin.config.oidc.issuer));
      issuer = cache.get(cache_key);
      if (issuer !== undefined) {
        return issuer;
      }

      issuer = new Issuer(plugin.config.oidc.issuer);
      plugin.server.logger.verbose(
        "manual issuer %s %O",
        issuer.issuer,
        issuer.metadata
      );
      cache.set(cache_key, issuer, ISSUER_CACHE_DURATION);
      return issuer;
    }
  }

  async get_client() {
    const plugin = this;
    const cache = plugin.server.cache;
    const cache_key =
      "client:" + plugin.server.utils.md5(JSON.stringify(plugin.config));
    let client;
    const issuer = await plugin.get_issuer();

    client = cache.get(cache_key);
    if (client !== undefined) {
      return client;
    }

    if (
      plugin.config.oidc.client.client_id &&
      plugin.config.oidc.client.client_secret
    ) {
      client = new issuer.Client({
        client_id: plugin.config.oidc.client.client_id,
        client_secret: plugin.config.oidc.client.client_secret,
      });
      client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;

      cache.set(cache_key, client, CLIENT_CACHE_DURATION);
      return client;
    } else if (
      plugin.config.oidc.client.registration_client_uri &&
      plugin.config.oidc.client.registration_access_token
    ) {
      client = await issuer.Client.fromUri(
        plugin.config.oidc.client.registration_client_uri,
        plugin.config.oidc.client.registration_access_token
      );

      client.CLOCK_TOLERANCE = DEFAULT_CLIENT_CLOCK_TOLERANCE;
      cache.set(cache_key, client, CLIENT_CACHE_DURATION);
      return client;
    } else {
      throw new Error("invalid client configuration");
    }
  }

  async get_userinfo(token, token_decoded, session_id) {
    const plugin = this;
    const client = await plugin.get_client();

    let response;
    let cacheHit = false;
    let ttl;

    plugin.server.logger.debug("get userinfo with token: %j", token);

    let cache_enabled =
      plugin.config.oidc.features.userinfo_expiry > 0 ||
      plugin.config.oidc.features.userinfo_expiry === true;

    if (
      plugin.config.oidc.features.userinfo_expiry === true &&
      token_decoded.exp
    ) {
      if (token_is_expired(token_decoded)) {
        cache_enabled = false;
      } else {
        ttl = token_decoded.exp - Date.now() / 1000;
      }
    }

    if (
      plugin.config.oidc.features.userinfo_expiry !== true &&
      plugin.config.oidc.features.userinfo_expiry > 0
    ) {
      ttl = plugin.config.oidc.features.userinfo_expiry;
    }

    if (session_id && cache_enabled) {
      response = await plugin.get_cache(CACHE_TYPE_USERINFO, session_id);
      cacheHit = Boolean(response);
    }

    if (!response) {
      plugin.server.logger.verbose(
        "fetching userinfo from issuer with token: %s",
        token
      );
      response = await client.userinfo(token);
    }

    plugin.server.logger.verbose("userinfo details %j", response);

    if (!cacheHit && session_id && cache_enabled) {
      await plugin.set_cache(CACHE_TYPE_USERINFO, session_id, response, ttl);
    }

    return response;
  }

  async introspect_access_token(token, session_id) {
    const plugin = this;
    const issuer = await plugin.get_issuer();
    const client = await plugin.get_client();

    if (!issuer.introspection_endpoint) {
      plugin.server.logger.error("issuer does not support introspection");
      throw new Error("issuer does not support introspection");
    }

    let response;
    let cacheHit = false;
    if (session_id && plugin.config.oidc.features.introspect_expiry > 0) {
      response = await plugin.get_cache(CACHE_TYPE_INTROSPECTION, session_id);
      cacheHit = Boolean(response);
    }

    if (!response) {
      console.log("introspecting token: " + token);
      response = await client.introspect(token);
    }

    plugin.server.logger.verbose("token introspect details %j", response);
    if (response.active === false) {
      plugin.server.logger.verbose("token no longer active!!!");
      return false;
    }

    if (
      !cacheHit &&
      session_id &&
      plugin.config.oidc.features.introspect_expiry > 0
    ) {
      await plugin.set_cache(
        CACHE_TYPE_INTROSPECTION,
        session_id,
        response,
        plugin.config.oidc.features.introspect_expiry
      );
    }

    return true;
  }

  async set_cache(cache_type, session_id, payload, ttl) {
    const plugin = this;
    const store = plugin.server.store;

    let cache_key;
    switch (cache_type) {
      case CACHE_TYPE_INTROSPECTION:
        cache_key = INTROSPECTION_CACHE_PREFIX + session_id;
        break;
      case CACHE_TYPE_USERINFO:
        cache_key = USERINFO_CACHE_PREFIX + session_id;
        break;
      default:
        throw new Error("unknown cache type");
    }

    if (!session_id) {
      return;
    }

    plugin.server.logger.verbose(
      `setting ${cache_type} cache with TTL: %s`,
      ttl
    );

    await store.set(
      cache_key,
      plugin.server.utils.encrypt(
        plugin.server.secrets.session_encrypt_secret,
        JSON.stringify(payload)
      ),
      ttl
    );
  }

  async get_cache(cache_type, session_id) {
    const plugin = this;
    const store = plugin.server.store;

    let cache_key;
    switch (cache_type) {
      case CACHE_TYPE_INTROSPECTION:
        cache_key = INTROSPECTION_CACHE_PREFIX + session_id;
        break;
      case CACHE_TYPE_USERINFO:
        cache_key = USERINFO_CACHE_PREFIX + session_id;
        break;
      default:
        throw new Error("unknown cache type");
    }

    if (!session_id) {
      return false;
    }

    plugin.server.logger.verbose(
      `retrieving ${cache_type} introspection cache: %s`,
      session_id
    );

    const encrypted = await store.get(cache_key);

    plugin.server.logger.verbose(
      `retrieved encrypted ${cache_type} content: %s`,
      encrypted
    );

    if (!encrypted) {
      plugin.server.logger.verbose(`failed to decrypt ${cache_type}`);
      return false;
    }

    let unencrypted = plugin.server.utils.decrypt(
      plugin.server.secrets.session_encrypt_secret,
      encrypted
    );
    plugin.server.logger.debug(`${cache_type} data: %s`, unencrypted);
    unencrypted = JSON.parse(unencrypted);

    return unencrypted;
  }
}

module.exports = {
  JwtPlugin,
};
