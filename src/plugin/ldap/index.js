const LdapAuth = require("ldapauth-fork");
const { BasePlugin } = require("..");

const CLIENT_CACHE_DURATION = 43200 * 1000;

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
    config.connection.cache = true;
    config.connection.reconnect = true;
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
  verify(configToken, req, res) {
    const plugin = this;
    const cache = plugin.server.cache;
    const clientOptionHash = plugin.server.utils.md5(
      JSON.stringify(plugin.config.connection)
    );

    let realm = plugin.config.realm
      ? plugin.config.realm
      : "external authentication server";

    // remove garbage
    realm = realm.replace("\\", "");
    realm = realm.replace('"', "");

    return new Promise(resolve => {
      const failure_response = function() {
        res.statusCode = 401;
        res.setHeader("WWW-Authenticate", 'Basic realm="' + realm + '"');
        resolve(res);
      };

      if (!req.headers.authorization) {
        failure_response();
        return;
      }

      if (
        !plugin.server.utils.authorization_scheme_is(
          req.headers.authorization,
          "basic"
        )
      ) {
        failure_response();
        return;
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

      ldap.authenticate(creds.username, creds.password, function(err, user) {
        if (err) {
          console.log(err);
          failure_response();
          return;
        } else {
          console.log(user);
          res.statusCode = 200;
          resolve(res);
        }
      });
    });
  }
}

module.exports = {
  LdapPlugin
};
