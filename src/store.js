const { logger } = require("./logger");

const cacheManager = require("cache-manager");
const redisStore = require("cache-manager-redis-store");
const ioredisStore = require("cache-manager-ioredis");

let cacheOpts = process.env["EAS_STORE_OPTS"];
if (cacheOpts) {
  cacheOpts = JSON.parse(cacheOpts);
} else {
  cacheOpts = {
    store: "memory",
    max: 0,
    ttl: 0
  };
}

// force 0 ttl
cacheOpts.ttl = 0;
logger.debug("cache opts: %j", cacheOpts);

const storeString = cacheOpts.store;

switch (cacheOpts.store) {
  case "redis":
    cacheOpts.store = redisStore;
    break;
  case "ioredis":
    cacheOpts.store = ioredisStore;
    break;
}

const cache = cacheManager.caching(cacheOpts);

switch (storeString) {
  case "ioredis":
    const redisClient = cache.store.getClient();

    redisClient.on("error", error => {
      logger.error("ioredis error: %s", error);
    });

    break;
}

function set(key, val, ttl = 0) {
  ttl = Math.floor(ttl);
  return new Promise((resolve, reject) => {
    cache.set(key, val, { ttl: ttl }, err => {
      if (err) {
        reject(err);
      }
      resolve();
    });
  });
}

function get(key) {
  return new Promise((resolve, reject) => {
    cache.get(key, (err, result) => {
      if (err) {
        reject(err);
      }
      resolve(result);
    });
  });
}

function del(key) {
  return new Promise((resolve, reject) => {
    cache.del(key, err => {
      if (err) {
        reject(err);
      }
      resolve();
    });
  });
}

module.exports = {
  set,
  get,
  del
};
