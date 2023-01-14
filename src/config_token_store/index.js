// config token store adapters
const { EnvConfigTokenStoreAdapter } = require("./adapter/env");
const { FileConfigTokenStoreAdapter } = require("./adapter/file");
const { FileDevConfigTokenStoreAdapter } = require("./adapter/file_dev");
const { SqlConfigTokenStoreAdapter } = require("./adapter/sql");
const YAML = require("yaml");

const TOKEN_CACHE_PREFIX = "token_store:";
let config_token_stores = process.env["EAS_CONFIG_TOKEN_STORES"];

if (config_token_stores) {
  config_token_stores = YAML.parse(config_token_stores);
} else {
  config_token_stores = {};
}

class ConfigTokenStoreManager {
  constructor(server) {
    this.server = server;
  }

  async getToken(id, store_id) {
    const manager = this;
    const store = manager.server.store;
    const configTokenStoreConfig = config_token_stores[store_id];

    let configTokenStoreAdapter;
    switch (configTokenStoreConfig.adapter) {
      case "env":
        configTokenStoreAdapter = new EnvConfigTokenStoreAdapter(
          manager.server,
          configTokenStoreConfig
        );
        break;
      case "file":
        configTokenStoreAdapter = new FileConfigTokenStoreAdapter(
          manager.server,
          configTokenStoreConfig
        );
        break;
      case "sql":
        configTokenStoreAdapter = new SqlConfigTokenStoreAdapter(
          manager.server,
          configTokenStoreConfig
        );
        break;

      default:
        throw new Error("invalid adapter: " + configTokenStore.adapter);
        break;
    }

    let configToken;
    let store_key = TOKEN_CACHE_PREFIX + store_id + ":" + id;

    if (configTokenStoreConfig.options.cache_ttl > 0) {
      try {
        configToken = await store.get(store_key);
        if (configToken) {
          manager.server.logger.verbose("cached config token");
          return configToken;
        }
      } catch (e) {}
    }

    configToken = await configTokenStoreAdapter.getToken(id);

    if (!configToken) {
      throw new Error(
        "could not find config_token id: %s, store_id: %s",
        id,
        store_id
      );
    }

    if (configTokenStoreConfig.options.cache_ttl > 0) {
      await store.set(
        store_key,
        configToken,
        configTokenStoreConfig.options.cache_ttl
      );
    }

    return configToken;
  }
}

module.exports = {
  ConfigTokenStoreManager
};
