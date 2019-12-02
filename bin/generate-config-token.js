const jwt = require("jsonwebtoken");
const utils = require("../src/utils");

const config_token_sign_secret =
  process.env.EAS_CONFIG_TOKEN_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_SIGN_SECRET env variable");
const config_token_encrypt_secret =
  process.env.EAS_CONFIG_TOKEN_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ENCRYPT_SECRET env variable");

let config_token = {
  /**
   * future feature: allow blocking certain token IDs
   */
  //jti: <some known value>

  /**
   * using the same aud for multiple tokens allows sso for all services sharing the aud
   */
  //aud: "some application id", //should be unique to prevent cookie/session hijacking, defaults to a hash unique to the whole config
  eas: {
    plugins: [{...}, {...},{...}], // list of plugin definitions, refer to PLUGINS.md for details
  }
};

config_token = jwt.sign(config_token, config_token_sign_secret);
const config_token_encrypted = utils.encrypt(
  config_token_encrypt_secret,
  config_token
);

//console.log("token: %s", config_token);
//console.log("");

console.log("encrypted token (for server-side usage): %s", config_token_encrypted);
console.log("");

console.log(
  "URL safe config_token: %s",
  encodeURIComponent(config_token_encrypted)
);
console.log("");
