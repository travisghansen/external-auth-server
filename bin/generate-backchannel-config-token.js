const jwt = require("jsonwebtoken");
const utils = require("../src/utils");

const config_token_sign_secret =
  process.env.EAS_CONFIG_TOKEN_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_SIGN_SECRET env variable");
const config_token_encrypt_secret =
  process.env.EAS_CONFIG_TOKEN_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ENCRYPT_SECRET env variable");

let config_token = {
  eas: {
    /**
     * should be as long as a tokenSet is able to function
     * the largest possible window of the id_token, access_token, or refresh_token
     * based on your configuration.
     * 
     * for example if refresh_tokens are enabled you would set to
     * refresh_token window + 1
     * 
     */
    ttl: 2678400, // 31 days
    issuer: {
      discover_url:
        "https://<domain>/.well-known/openid-configuration",
    },
    client: {
      client_id: "...",
      client_secret: "...",
    },
  },
};

config_token = jwt.sign(config_token, config_token_sign_secret);
const config_token_encrypted = utils.encrypt(
  config_token_encrypt_secret,
  config_token
);

//console.log("token: %s", config_token);
//console.log("");

console.log(
  "encrypted token (for backchannel usage): %s",
  config_token_encrypted
);
console.log("");

console.log(
  "URL safe backchannel_config_token: %s",
  encodeURIComponent(config_token_encrypted)
);
console.log("");
