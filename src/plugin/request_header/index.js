const { BasePlugin } = require("..");

class RequestHeaderPlugin extends BasePlugin {
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

    return new Promise(resolve => {
      for (let [key, value] of Object.entries(plugin.config.headers)) {
        if (!Array.isArray(value)) {
          value = [value];
        }

        if (value.includes(req.headers[key.toLowerCase()])) {
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
  RequestHeaderPlugin
};
