const { BasePlugin } = require("..");
const request = require("request");

/**
 * https://stackoverflow.com/questions/10435407/proxy-with-express-js
 * https://stackoverflow.com/questions/7559862/no-response-using-express-proxy-route/20539239#20539239
 * https://stackoverflow.com/questions/16038705/how-to-wrap-a-buffer-as-a-stream2-readable-stream
 */
class ForwardPlugin extends BasePlugin {
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
    const rheaders = JSON.parse(JSON.stringify(req.headers));
    delete rheaders["host"];

    const upstream = await new Promise(resolve => {
      const options = {
        method: "GET",
        url: plugin.config.url,
        headers: rheaders,
        gzip: true,
        agentOptions: {
          rejectUnauthorized: !!!plugin.config.allow_insecure
        }
      };
 
      request(options, function(err, res, body) {
        resolve({ err, res, body });
      });
    });

    if (upstream.err) {
      plugin.server.logger.error(upstream.err);
      res.statusCode = 503;
      return res;
    }
    
    plugin.server.logger.verbose("forward response: %j", upstream);
    

    /**
     * let express set this header automatically
     */
    delete upstream.res.headers["content-length"];

    /**
     * the `body` attribute has already been decoded
     * so we unset this to ensure proper responses
     * and/or let express handle it
     */
    delete upstream.res.headers["content-encoding"];

    res.statusCode = upstream.res.statusCode;
    res.headers = upstream.res.headers;
    res.body = upstream.body;
    return res;
  }
}

module.exports = {
  ForwardPlugin
};
