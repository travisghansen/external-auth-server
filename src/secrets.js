const jwt_sign_secret =
  process.env.OEAS_JWT_SIGN_SECRET ||
  utils.exit_failure("missing OEAS_JWT_SIGN_SECRET env variable");
const proxy_encrypt_secret =
  process.env.OEAS_PROXY_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_PROXY_ENCRYPT_SECRET env variable");
const issuer_encrypt_secret =
  process.env.OEAS_ISSUER_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_ISSUER_ENCRYPT_SECRET env variable");
const session_encrypt_secret =
  process.env.OEAS_SESSION_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_SESSION_ENCRYPT_SECRET env variable");
const cookie_sign_secret =
  process.env.OEAS_COOKIE_SIGN_SECRET ||
  utils.exit_failure("missing OEAS_COOKIE_SIGN_SECRET env variable");
const cookie_encrypt_secret =
  process.env.OEAS_COOKIE_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_COOKIE_ENCRYPT_SECRET env variable");

module.exports = {
  jwt_sign_secret,
  proxy_encrypt_secret,
  issuer_encrypt_secret,
  session_encrypt_secret,
  cookie_sign_secret,
  cookie_encrypt_secret
};
