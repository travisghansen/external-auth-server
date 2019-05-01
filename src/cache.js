const LRU = require("lru-cache");

const cache = new LRU({ max: 500 });

module.exports = {
  cache
};
