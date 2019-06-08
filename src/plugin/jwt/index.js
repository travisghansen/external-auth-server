const { Assertion } = require("../../assertion");
const { BasePlugin } = require("..");
const jwt = require("jsonwebtoken");

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
    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    plugin.server.logger.verbose("parent request info: %j", parentReqInfo);

    let realm = plugin.config.realm ? plugin.config.realm : parentReqInfo.uri;

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
    const failure_response = function(code = 401) {
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
    try {
      const token = jwt.verify(creds.token, config.secret, config.options);
      plugin.server.logger.debug("jwt token: %j", token);

      const valid = await plugin.assertions(token);
      if (valid !== true) {
        error = "invalid_user";
        error_description = "user did not pass assertions";

        failure_response(403);
        return res;
      } else {
        res.setAuthenticationData({
          id_token: creds.token
        });
        res.statusCode = 200;
        return res;
      }
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

  async assertions(token) {
    const plugin = this;

    if (plugin.config.assertions && plugin.config.assertions.id_token) {
      return await Assertion.assertSet(
        token,
        plugin.config.assertions.id_token
      );
    }
    return true;
  }
}

module.exports = {
  JwtPlugin
};
