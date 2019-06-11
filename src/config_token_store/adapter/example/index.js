const { BaseConfigTokenStoreAdapter } = require("..");

class ExampleConfigTokenStoreAdapter extends BaseConfigTokenStoreAdapter {
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
      // should be the signed and ecrypted variant
      return token;
    } catch (e) {
      throw e;
    }
  }
}

module.exports = {
  ExampleConfigTokenStoreAdapter
};
