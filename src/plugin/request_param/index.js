const { BasePlugin } = require("..");

class RequestParamPlugin extends BasePlugin {
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
    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    plugin.server.logger.verbose("parent request info: %j", parentReqInfo);

    const redirectHttpCode = req.query.redirect_http_code
      ? req.query.redirect_http_code
      : 302;

    return new Promise(resolve => {
      for (let [key, value] of Object.entries(plugin.config.params)) {
        if (!Array.isArray(value)) {
          value = [value];
        }

        if (value.includes(parentReqInfo.parsedQuery[key])) {
          res.statusCode = 200;
          resolve(res);
          return;
        }
      }

      res.statusCode = 403;
      resolve(res);
    });
  }
}

module.exports = {
  RequestParamPlugin
};
