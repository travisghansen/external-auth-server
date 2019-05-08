const { cache } = require("./cache");
const secrets = require("./secrets");
const store = require("./store");
const utils = require("./utils");

class ExternalAuthServer {
  static setResponse(res, pluginResponse) {
    res.statusCode = pluginResponse.statusCode;
    pluginResponse.cookies.forEach(cookie => {
      res.cookie(...cookie);
    });

    pluginResponse.clearCookies.forEach(cookie => {
      res.clearCookie(...cookie);
    });

    for (let [key, value] of Object.entries(pluginResponse.headers)) {
      res.header(key, value);
    }
    res.end(pluginResponse.body);
  }

  setConfigTokenDefaults(configToken) {
    const configAudMD5 = configToken.hasOwnProperty("aud")
      ? this.utils.md5(JSON.stringify(configToken.aud))
      : this.utils.md5(JSON.stringify(configToken));

    configToken.audMD5 = configAudMD5;

    return configToken;
  }

  get utils() {
    return utils;
  }

  get secrets() {
    return secrets;
  }

  get cache() {
    return cache;
  }

  get store() {
    return store;
  }
}

module.exports = {
  ExternalAuthServer
};
