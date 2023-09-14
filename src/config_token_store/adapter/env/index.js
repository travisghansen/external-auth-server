const { BaseConfigTokenStoreAdapter } = require("..");
const YAML = require("yaml");

class EnvConfigTokenStoreAdapter extends BaseConfigTokenStoreAdapter {
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
   * Retrieve to the token with the given id
   *
   * @param {*} id
   */
  async getTokenInternal(id) {
    const adapter = this;
    adapter.server.logger.debug("adapter config: %j", adapter.config);

    try {
      let data = process.env[adapter.config.options.var];
      data = YAML.parse(data);
      let token;
      token = data[id];

      return typeof token !== "string" ? JSON.stringify(token) : token;
    } catch (e) {
      throw e;
    }
  }
}

module.exports = {
  EnvConfigTokenStoreAdapter
};
