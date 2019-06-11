const { BaseConfigTokenStoreAdapter } = require("..");
const knex = require("knex");

const CLIENT_CACHE_DURATION = 43200 * 1000;

/**
 * https://knexjs.org/#Installation-client
 * https://knexjs.org/#Raw-Queries
 */
class SqlConfigTokenStoreAdapter extends BaseConfigTokenStoreAdapter {
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
    const cache = adapter.server.cache;
    const clientOptionHash = adapter.server.utils.md5(
      JSON.stringify(adapter.config)
    );

    adapter.server.logger.debug("adapter config: %j", adapter.config);

    const cache_key =
      "config_token_adapater:sql:connections:" + clientOptionHash;
    adapter.server.logger.verbose("cache key: %s", cache_key);
    let client = cache.get(cache_key);
    if (client === undefined) {
      adapter.server.logger.verbose("initializing new SQL connection");
      client = knex(adapter.config.options.config);
      cache.set(cache_key, client, CLIENT_CACHE_DURATION);
    } else {
      adapter.server.logger.verbose("cached SQL connection");
    }

    try {
      const resp = await client.raw(adapter.config.options.query, [id]);
      const row = resp[0][0];
      return row.token;
    } catch (e) {
      throw e;
    }
  }
}

module.exports = {
  SqlConfigTokenStoreAdapter
};
