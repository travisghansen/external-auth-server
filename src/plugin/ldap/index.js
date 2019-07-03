const { Assertion } = require("../../assertion");
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

    if (!config.assertions) {
      config.assertions = {};
    }

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

    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    plugin.server.logger.verbose("parent request info: %j", parentReqInfo);

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

    let store_key;
    if (plugin.config.session_cache_ttl > 0) {
      store_key =
        SESSION_CACHE_PREFIX +
        clientOptionHash +
        ":" +
        plugin.server.utils.md5(req.headers.authorization);

      const userinfo = await store.get(store_key);

      if (userinfo !== null) {
        plugin.server.logger.verbose("ldap userinfo: %s", userinfo);
        res.setAuthenticationData({
          userinfo: userinfo.data
        });
        res.statusCode = 200;
        return res;
      }
    }

    const cache_key = "ldap:connections:" + clientOptionHash;
    let ldap = cache.get(cache_key);
    if (ldap === undefined) {
      const connection = JSON.parse(JSON.stringify(plugin.config.connection));
      if (connection.log) {
        connection.log = plugin.server.logger.bunyan;
      }
      ldap = new LdapAuth(connection);

      ldap.close(function(err) {
        plugin.server.logger.verbose("LdapAuth connection closed: %s", err);
        cache.del(cache_key);
      });

      ldap.on("error", function(err) {
        plugin.server.logger.error("LdapAuth err: %s", err);
        cache.del(cache_key);
      });

      //cache.set(cache_key, ldap, CLIENT_CACHE_DURATION);
    }

    await new Promise(resolve => {
      ldap.authenticate(creds.username, creds.password, async function(
        err,
        user
      ) {
        if (err) {
          plugin.server.logger.error("LdapPlugin authenticate error: %s", err);
          if (err.name) {
            switch (err.name) {
              case "TimeoutError":
              case "ConnectionError":
              case "InvalidCredentialsError":
                cache.del(cache_key);
                res.statusCode = 503;
                resolve();
                return;
            }
          }
          failure_response();
          resolve();
          return;
        } else {
          const userinfo = {
            iat: Math.floor(Date.now() / 1000),
            data: user
          };

          plugin.server.logger.verbose("ldap userinfo: %s", userinfo);

          // run assertions on userinfo
          if (plugin.config.assertions.userinfo) {
            const userinfoValid = await plugin.userinfo_assertions(
              userinfo.data
            );

            if (!userinfoValid) {
              plugin.server.logger.verbose("userinfo failed assertions");
              res.statusCode = 403;
              resolve();
              return;
            }
          }

          if (plugin.config.session_cache_ttl > 0) {
            store
              .set(
                store_key,
                plugin.server.utils.encrypt(
                  plugin.server.secrets.session_encrypt_secret,
                  JSON.stringify(userinfo)
                ),
                plugin.config.session_cache_ttl
              )
              .then(() => {
                res.setAuthenticationData({
                  userinfo: userinfo.data
                });
                res.statusCode = 200;
                resolve();
              });
          } else {
            res.setAuthenticationData({
              userinfo: userinfo.data
            });
            res.statusCode = 200;
            resolve();
          }
        }
      });
    });

    return res;
  }

  async userinfo_assertions(userinfo) {
    const plugin = this;

    return await Assertion.assertSet(
      userinfo,
      plugin.config.assertions.userinfo
    );
  }
}

module.exports = {
  LdapPlugin
};
