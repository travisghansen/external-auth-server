const htpasswd = require("htpasswd-js");
const { BasePlugin } = require("..");

/**
 * https://github.com/sripberger/htpasswd-js (purejs)
 * https://github.com/jdxcode/htpasswd-auth (uses c++ module)
 * http://www.htaccesstools.com/htpasswd-generator/
 * https://en.wikipedia.org/wiki/Basic_access_authentication
 * https://stackoverflow.com/questions/9534602/what-is-the-difference-between-digest-and-basic-authentication
 */
class HtPasswdPlugin extends BasePlugin {
  static initialize(server) {}

  /**
   * Create new instance
   *
   * @name constructor
   * @param {*} config
   */
  constructor(server, config) {
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

      if (!plugin.config.htpasswd) {
        failure_response();
        return;
      }

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

      htpasswd
        .authenticate({
          username: creds.username,
          password: creds.password,
          data: plugin.config.htpasswd
        })
        .then(result => {
          if (result) {
            res.statusCode = 200;
            resolve(res);
          } else {
            failure_response();
            return;
          }
        });
    });
  }
}

module.exports = {
  HtPasswdPlugin
};
