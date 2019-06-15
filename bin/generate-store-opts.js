// ioredis adapter (preferred over redis adapter)
// https://github.com/luin/ioredis/blob/master/API.md#new-redisport-host-options
var config = {
  store: "ioredis",
  host: "localhost" // default value
  //port: 6379, // default value
  //password: "XXXXX",
  //db: 0,
  //keyPrefix: "eas:"
};

// ioredis adapter (preferred over redis adapter)
// sentinel example
// https://github.com/luin/ioredis#sentinel
var config = {
  store: "ioredis",
  name: "mymaster",
  sentinels: [
    {
      host: "eas-redis-ha-announce-0",
      port: 26379
    },
    {
      host: "eas-redis-ha-announce-1",
      port: 26379
    },
    {
      host: "eas-redis-ha-announce-2",
      port: 26379
    }
  ]
  //password: "XXXXX",
  //db: 0,
  //keyPrefix: "eas:"
};

// redis adapter
// https://www.npmjs.com/package/redis#options-object-properties
var config = {
  store: "redis",
  host: "localhost" // default value
  //port: 6379, // default value
  //auth_pass: "XXXXX",
  //db: 0,
  //prefix: "eas:"
};

console.log(JSON.stringify(config));
