const jq = require("node-jq");

const JQ_OPTIONS = {
  input: "json",
  output: "json",
};

/**
 * Populates response headers using the given JQ config and data payload.
 *
 * Config can either be an object mapping of headerName --> jq query for that
 * value. Alternatively it can be a string representation of a jq query that
 * returns an object mapping of headerName --> value.
 */
const populateResponseHeader = async (res, config, data, logger) => {
  if (!config) {
    return;
  }

  // When the config is a string we expect it to be a jq expression that returns
  // an object of `headerName` --> `value`.
  if (typeof config === "string") {
    const headers = await jq.run(config, data, JQ_OPTIONS);
    if (typeof headers !== "object" || headers instanceof Array) {
      logger.warn(
        `Invalid jq response when processing configured headers. Skipping.`);
        return;
    }
    for (let [headerName, value] of Object.entries(headers)) {
      setHeader(res, headerName, value);
    }
  } else {
    for (let [headerName, query] of Object.entries(config)) {
      const value = await jq.run(query, data, JQ_OPTIONS);
      setHeader(res, headerName, value);
    }
  }
};

/**
 * Sets the given header on the response object.
 *
 * If the value is not a string then the value will be `JSON.stringify`'d.
 */
const setHeader = (res, headerName, value) => {
  if (typeof value !== "string") {
    value = JSON.stringify(value);
  }
  res.setHeader(headerName, value);
};

module.exports = {
  populateResponseHeader,
};
