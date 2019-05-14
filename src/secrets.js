const config_token_sign_secret =
  process.env.EAS_CONFIG_TOKEN_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_SIGN_SECRET env variable");
const config_token_encrypt_secret =
  process.env.EAS_CONFIG_TOKEN_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ENCRYPT_SECRET env variable");
const cookie_sign_secret =
  process.env.EAS_COOKIE_SIGN_SECRET ||
  utils.exit_failure("missing EAS_COOKIE_SIGN_SECRET env variable");
const cookie_encrypt_secret =
  process.env.EAS_COOKIE_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_COOKIE_ENCRYPT_SECRET env variable");
const session_encrypt_secret =
  process.env.EAS_SESSION_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_SESSION_ENCRYPT_SECRET env variable");

module.exports = {
  config_token_sign_secret,
  config_token_encrypt_secret,
  session_encrypt_secret,
  cookie_sign_secret,
  cookie_encrypt_secret
};
