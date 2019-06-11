const { FileConfigTokenStoreAdapter } = require("../file");
const jwt = require("jsonwebtoken");

class FileDevConfigTokenStoreAdapter extends FileConfigTokenStoreAdapter {
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
    let token = await FileConfigTokenStoreAdapter.prototype.getTokenInternal.call(
      this,
      ...arguments
    );

    token = jwt.sign(token, adapter.server.secrets.config_token_sign_secret);
    token = adapter.server.utils.encrypt(
      adapter.server.secrets.config_token_encrypt_secret,
      token
    );

    return token;
  }
}

module.exports = {
  FileDevConfigTokenStoreAdapter
};
