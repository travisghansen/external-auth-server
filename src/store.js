var cacheManager = require("cache-manager");
var redisStore = require("cache-manager-redis-store");

let cacheOpts = process.env["OEAS_STORE_OPTS"];
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
console.log("store options: %j", cacheOpts);

switch (cacheOpts.store) {
  case "redis":
    cacheOpts.store = redisStore;
    break;
}

var cache = cacheManager.caching(cacheOpts);

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
