const jwt = require("jsonwebtoken");
const utils = require("../src/utils");
const fs = require('fs');

const config_token_sign_secret =
  process.env.EAS_CONFIG_TOKEN_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_SIGN_SECRET env variable");
const config_token_encrypt_secret =
  process.env.EAS_CONFIG_TOKEN_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ENCRYPT_SECRET env variable");

const data = fs.readFileSync(0, 'utf-8');
  
let config_token = JSON.parse(data)  

config_token = jwt.sign(config_token, config_token_sign_secret);
const config_token_encrypted = utils.encrypt(
  config_token_encrypt_secret,
  config_token
);

console.log(config_token_encrypted);
