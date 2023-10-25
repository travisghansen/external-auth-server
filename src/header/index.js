const jp = require("jsonpath");
const jq = require("node-jq");
const jwt = require("jsonwebtoken");
const { logger } = require("../logger");
const { base64_encode } = require("../utils");

class HeaderInjector {
  constructor(config, data) {
    this.config = config;
    this.data = data;
  }

  async injectHeaders(res) {
    if (!this.config) {
      return;
    }

    for (let [headerName, headerConfig] of Object.entries(this.config)) {
      try {
        let value;
        if (headerConfig.query) {
          value = await this.query(headerConfig);
        } else {
          value = this.data[headerConfig.source];
        }

        if (typeof value !== "string") {
          value = JSON.stringify(value);
        }

        if (headerConfig.encoding) {
          switch (headerConfig.encoding) {
            case "base64":
              value = base64_encode(value);
              break;
            case "uri":
            case "url":
              value = encodeURIComponent(value);
              break;
            default:
            case "plain":
              // noop
              break;
          }
        }

        this.setHeader(res, headerName, value);
      } catch (e) {
        logger.error("failed setting header: %s error: %s", headerName, e);
      }
    }
  }

  async jsonpath_query(headerConfig, data) {
    let singleValue = false;

    if (headerConfig.query_opts && headerConfig.query_opts.single_value) {
      singleValue = true;
    }

    const values = jp.query(data, headerConfig.query);
    if (singleValue) {
      if (values.length > 1) {
        throw new Error("more than 1 value in jsonpath query result");
      }

      return values[0];
    }
    return values;
  }

  async jq_query(headerConfig, data) {
    const options = {
      input: "json",
      output: "json",
    };

    const values = await jq.run(headerConfig.query, data, options);
    return values;
  }

  async query(headerConfig) {
    let value;
    let data;

    if (headerConfig.source == "static") {
      return headerConfig.query;
    }

    switch (headerConfig.source) {
      case "static":
        return headerConfig.query;
        break;
      case "id_token":
      case "access_token":
      case "refresh_token":
        if (this.data[headerConfig.source] === undefined) {
          throw new Error("invalid data source: " + headerConfig.source);
        }
        data = jwt.decode(this.data[headerConfig.source]);
        break;
      default:
        if (this.data[headerConfig.source] === undefined) {
          throw new Error("invalid data source: " + headerConfig.source);
        }
        data = this.data[headerConfig.source];
        break;
    }

    switch (headerConfig.query_engine) {
      case "jp":
        value = await this.jsonpath_query(headerConfig, data);
        break;
      case "jq":
        value = await this.jq_query(headerConfig, data);
        break;
      case "static":
        value = headerConfig.query;
        break;
      default:
        throw new Error("invalid query engine: " + this.config.query_engine);
    }

    return value;
  }

  /**
   * Sets the given header on the response object.
   *
   * If the value is not a string then the value will be `JSON.stringify`'d.
   */
  setHeader(res, headerName, value) {
    if (typeof value !== "string") {
      value = JSON.stringify(value);
    }

    if (value === undefined) {
      value = "";
    }
    logger.debug("injecting header: %s with value: %s", headerName, value);
    res.setHeader(headerName, value);
  }
}

module.exports = {
  HeaderInjector,
};
