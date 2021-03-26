const { BasePlugin } = require("..");

class NoopPlugin extends BasePlugin {
  /**
   * This is invoked once during application start. It can be used to register
   * new endpoints with the express webserver.
   *
   * `server` is the application instance. It provides access various utils,
   * store, cache, etc.
   *
   * @param {*} server
   */
  static initialize(server) {}

  /**
   * This is invoked *every* authentication request just before the `verify`
   * method is invoked. You can use it to set default values on the config etc.
   *
   * `server` is the application instance. It provides access to various utils,
   * store, cache, etc
   *
   * `config` is the config block relating to this plugin from the
   * `config_token` plugin array.
   *
   * @name constructor
   * @param {*} server
   * @param {*} config
   */
  constructor(server, config) {
    super(...arguments);
  }

  /**
   * Verify the request. Should return a promise which resolves the `res` object.
   *
   * `configToken` is the **full** decoded token. Generally you will want to
   * use the particular plugin config which is available at `this.config`. The
   * `server` instance is available at `this.server`.
   *
   * `req` is the express request object. It gives you access not to the
   * **original** request but rather the request to the authentication server.
   *
   * `res` is a light-weight response object (see `PluginVerifyResponse` in
   * `src/plugin/index.js`) which supports a sub-set of the express server
   * response methods.
   *
   * @name verify
   * @param {*} configToken
   * @param {*} req
   * @param {*} res
   */
  async verify(configToken, req, res) {
    const plugin = this;
    res.statusCode = plugin.config.status_code || 200;
    return res;
  }
}

module.exports = {
  NoopPlugin
};
