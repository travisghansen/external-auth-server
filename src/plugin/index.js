class BasePlugin {
  constructor(server, config = {}) {
    this.server = server;
    this.config = config;
  }
}

class PluginVerifyResponse {
  constructor() {
    this.statusCode = "";
    this.body = "";
    this.cookies = [];
    this.clearCookies = [];
    this.headers = {};
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
}

module.exports = {
  BasePlugin,
  PluginVerifyResponse
};
