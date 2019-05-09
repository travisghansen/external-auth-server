const LdapAuth = require("ldapauth-fork");
const { BasePlugin } = require("..");

const CLIENT_CACHE_DURATION = 43200 * 1000;
const SESSION_CACHE_PREFIX = "session:ldap:";

/**
 * https://github.com/vesse/node-ldapauth-fork
 * https://github.com/joyent/node-ldapjs/blob/v1.0.1/docs/client.md
 */
class LdapPlugin extends BasePlugin {
  static initialize(server) {}

  /**
   * Create new instance
   *
   * @name constructor
   * @param {*} config
   */
  constructor(server, config) {
    config.connection.cache = config.connection.hasOwnProperty("cache")
      ? config.connection.cache
      : true;
    config.connection.reconnect = true;
    config.connection.timeout = config.connection.hasOwnProperty("timeout")
      ? config.connection.timeout
      : 3000;
    config.connection.connectTimeout = config.connection.hasOwnProperty(
      "connectTimeout"
    )
      ? config.connection.connectTimeout
      : 10000;
    config.session_cache_ttl = config.hasOwnProperty("session_cache_ttl")
      ? config.session_cache_ttl
      : 900;

    config.connection.idleTimeout = config.connection.hasOwnProperty(
      "idleTimeout"
    )
      ? config.connection.idleTimeout
      : 10000;
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
    const store = plugin.server.store;
    const clientOptionHash = plugin.server.utils.md5(
      JSON.stringify(plugin.config.connection)
    );

    let realm = plugin.config.realm
      ? plugin.config.realm
      : "external authentication server";

    // remove garbage
    realm = realm.replace("\\", "");
    realm = realm.replace('"', "");

    const failure_response = function() {
      res.statusCode = 401;
      res.setHeader("WWW-Authenticate", 'Basic realm="' + realm + '"');
    };

    if (!req.headers.authorization) {
      failure_response();
      return res;
    }

    if (
      !plugin.server.utils.authorization_scheme_is(
        req.headers.authorization,
        "basic"
      )
    ) {
      failure_response();
      return res;
    }

    const creds = plugin.server.utils.parse_basic_authorization_header(
      req.headers.authorization
    );

    const cache_key = "ldap:connections:" + clientOptionHash;
    let ldap = cache.get(cache_key);
    if (ldap === undefined) {
      ldap = new LdapAuth(plugin.config.connection);

      ldap.close(function(err) {});

      ldap.on("error", function(err) {
        console.error("LdapAuth: ", err);
      });

      cache.set(cache_key, ldap, CLIENT_CACHE_DURATION);
    }

    let store_key;
    if (plugin.config.session_cache_ttl > 0) {
      store_key =
        SESSION_CACHE_PREFIX +
        clientOptionHash +
        ":" +
        plugin.server.utils.md5(req.headers.authorization);

      const userdata = await store.get(store_key);

      if (userdata !== null) {
        res.statusCode = 200;
        return res;
      }
    }

    await new Promise(resolve => {
      ldap.authenticate(creds.username, creds.password, function(err, user) {
        if (err) {
          console.log("LdapPlugin authenticate error: ", err);
          console.log(err.name);
          if (err.name) {
            switch (err.name) {
              case "TimeoutError":
              case "ConnectionError":
                cache.del(cache_key);
                break;
            }
          }
          failure_response();
          resolve();
        } else {
          if (plugin.config.session_cache_ttl > 0) {
            store
              .set(
                store_key,
                plugin.server.utils.encrypt(
                  plugin.server.secrets.session_encrypt_secret,
                  JSON.stringify(user)
                ),
                plugin.config.session_cache_ttl
              )
              .then(() => {
                res.statusCode = 200;
                resolve();
              });
          } else {
            resolve();
          }
        }
      });
    });

    return res;
  }
}

module.exports = {
  LdapPlugin
};
