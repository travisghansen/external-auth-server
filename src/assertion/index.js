const jp = require("jsonpath");
const jq = require("node-jq");
const { logger } = require("../logger");
const utils = require("../utils");

class Assertion {
  constructor(data, config) {
    this.data = data;
    this.config = config;
  }

  static async assertSet(data = {}, assertionConfigs = []) {
    /**
     * currently only support crude logic ANDs
     * ie: **all** assertions must pass
     */
    for (let i = 0; i < assertionConfigs.length; i++) {
      const assertion = new this(data, assertionConfigs[i]);
      const test = await assertion.assert();
      if (test === false) {
        return false;
      }
    }

    return true;
  }

  async jsonpath_query() {
    let singleValue = false;

    switch (this.config.rule.method) {
      case "contains":
      case "contains-any":
      case "contains-all":
        singleValue = false;
        break;
      default:
        singleValue = true;
        break;
    }

    const values = jp.query(this.data, this.config.query);
    if (singleValue) {
      if (values.length > 1) {
        throw new Error("more than 1 value in jsonpath query result");
      }

      return values[0];
    }
    return values;
  }

  async jq_query() {
    const options = {
      input: "json",
      output: "json"
    };

    const values = await jq.run(this.config.query, this.data, options);
    return values;
  }

  async query() {
    let value;

    switch (this.config.query_engine) {
      case "jp":
        value = await this.jsonpath_query();
        break;
      case "jq":
        value = await this.jq_query();
        break;
      default:
        throw new Error("invalid query engine: " + this.config.query_engine);
    }

    return value;
  }

  async assert() {
    let rule = this.config.rule;
    let value = await this.query();
    let test;

    logger.debug("asserting: %j against value: %j", this.config, value);

    if (rule.case_insensitive) {
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          value[i] = value[i].toString().toLowerCase();
        }
      } else {
        value = value.toString().toLowerCase();
      }

      if (Array.isArray(rule.value)) {
        for (let i = 0; i < rule.value.length; i++) {
          rule.value[i] = rule.value[i].toString().toLowerCase();
        }
      } else {
        rule.value = rule.value.toString().toLowerCase();
      }
    }

    let a, b, c;
    switch (rule.method) {
      case "contains":
        if (!Array.isArray(value)) {
          throw new Error("value must be an array for 'contains' method");
        }

        test = value.includes(rule.value);
        break;
      case "contains-any":
        if (!Array.isArray(value)) {
          throw new Error("value must be an array for 'contains-any' method");
        }

        if (!Array.isArray(rule.value)) {
          throw new Error(
            "rule.value must be an array for 'contains-any' method"
          );
        }

        a = utils.array_unique(value);
        b = utils.array_unique(rule.value);
        c = utils.array_intersect(a, b);
        test = c.length > 0;
        break;
      case "contains-all":
        if (!Array.isArray(value)) {
          throw new Error("value must be an array for 'contains-all' method");
        }

        if (!Array.isArray(rule.value)) {
          throw new Error(
            "rule.value must be an array for 'contains-all' method"
          );
        }

        a = utils.array_unique(value);
        b = utils.array_unique(rule.value);
        c = utils.array_intersect(a, b);
        test = b.length == c.length;
        break;
      case "eq":
        test = rule.value == value;
        break;
      case "in":
        if (!Array.isArray(rule.value)) {
          throw new Error("rule.value must be an array for 'in' method");
        }

        test = rule.value.includes(value);
        break;
      case "regex":
        /**
         * this splits the simple "/pattern/[flags]" syntaxt into something the
         * regex constructor understands
         */
        const parts = /\/(.*)\/(.*)/.exec(rule.value);
        const regex = new RegExp(parts[1], parts[2]);
        test = regex.test(value);
        break;
      default:
        throw new Error("unknown assert method: " + rule.method);
    }

    if (rule.negate) {
      test = !!!test;
    }

    if (test === false) {
      logger.warn("failed assertion: %j against value: %j", this.config, value);
    } else {
      logger.debug(
        "passed assertion: %j against value: %j",
        this.config,
        value
      );
    }

    return test;
  }
}

module.exports = {
  Assertion
};
