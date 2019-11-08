const { BasePlugin } = require("..");

class RequestJsPlugin extends BasePlugin {
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
    const func = new Function('req', 'res', 'configToken', 'plugin', 'parentReqInfo', plugin.config.snippet);
    func(req, res, configToken, plugin, parentReqInfo);

    return res;
  }
}

module.exports = {
  RequestJsPlugin
};
