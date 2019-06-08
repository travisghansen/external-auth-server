class BasePlugin {
  constructor(server, config = {}) {
    this.server = server;
    this.config = config;
  }
}

class PluginVerifyResponse {
  constructor() {
    this.statusCode = "";
    this.statusMessage = "";
    this.body = "";
    this.cookies = [];
    this.clearCookies = [];
    this.headers = {};
    this.authenticationData = {};
    this.plugin = null;
  }

  body(body) {
    this.body = body;
  }

  cookie() {
    this.cookies.push([...arguments]);
  }

  clearCookie() {
    this.clearCookies.push([...arguments]);
  }

  setHeader(name, value) {
    this.headers[name] = value;
  }

  setAuthenticationData(data) {
    this.authenticationData = data;
  }

  setAuthenticationDataValue(name, value) {
    this.authenticationData[name] = value;
  }

  setPlugin(plugin) {
    this.plugin = plugin;
  }
}

module.exports = {
  BasePlugin,
  PluginVerifyResponse
};
