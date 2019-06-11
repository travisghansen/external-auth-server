class BaseConfigTokenStoreAdapter {
  constructor(server, config = {}) {
    this.server = server;
    this.config = config;
  }

  async getToken(id) {
    return this.getTokenInternal(id);
  }
}

module.exports = {
  BaseConfigTokenStoreAdapter
};
