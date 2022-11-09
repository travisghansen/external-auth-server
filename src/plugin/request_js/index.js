const { BasePlugin } = require("..");

const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
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
    // https://www.codegrepper.com/code-examples/javascript/how+to+create+a+dynamic+function+in+javascript
    const func = new AsyncFunction('req', 'res', 'configToken', 'plugin', 'parentReqInfo', plugin.config.snippet);
    //const func = new Function('req', 'res', 'configToken', 'plugin', 'parentReqInfo', plugin.config.snippet);
    await func(req, res, configToken, plugin, parentReqInfo);

    return res;
  }
}

module.exports = {
  RequestJsPlugin
};
