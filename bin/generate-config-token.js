const jwt = require("jsonwebtoken");
const utils = require("../src/utils");

const jwt_sign_secret =
  process.env.OEAS_JWT_SIGN_SECRET ||
  utils.exit_failure("missing OEAS_JWT_SIGN_SECRET env variable");
const proxy_encrypt_secret =
  process.env.OEAS_PROXY_ENCRYPT_SECRET ||
  utils.exit_failure("missing OEAS_PROXY_ENCRYPT_SECRET env variable");

let config_token = {
  /**
   * future feature: allow blocking certain token IDs
   */
  //jti: <some known value>

  /**
   * using the same aud for multiple tokens allows sso for all services sharing the aud
   */
  //aud: "some application id", //should be unique to prevent cookie/session hijacking, defaults to a hash unique to the whole config
  oeas: {
    issuer: {
      /**
       * via discovery (takes preference)
       * preferred is to *include* the /.well-known/ portion of the URL
       * look up your provider documentation to get the exact URL
       */
      discover_url: "https://<provider>/.well-known/openid-configuration"

      /**
       * via manual definition
       */
      //issuer: 'https://accounts.google.com',
      //authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      //token_endpoint: 'https://www.googleapis.com/oauth2/v4/token',
      //userinfo_endpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
      //jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
    },
    client: {
      /**
       * manually defined (preferred)
       */
      client_id: "<client-id>",
      client_secret: "<client-secret>"

      /**
       * via client registration
       */
      //registration_client_uri: "",
      //registration_access_token: "",
    },
    /**
     * openid is required
     */
    scopes: ["openid", "email", "profile"],
    features: {
      /**
       * if false cookies will be 'session' cookies
       * if true and cookies expire will expire with tokens
       */
      set_cookie_expiry: false,

      /**
       * if the access token is expired and a refresh token is available, refresh
       */
      refresh_access_token: true,

      /**
       * fetch userinfo and include as X-Userinfo header to backing service
       */
      fetch_userinfo: true,

      /**
       * check token validity with provider during assertion process
       */
      introspect_access_token: false
    },
    assertions: {
      /**
       * assert the token aud is the client_id
       */
      aud: true,

      /**
       * assert the token(s) has not expired
       */
      exp: true,

      /**
       * assert the 'not before' attribute of the token(s)
       */
      nbf: true,

      /**
       * assert the correct issuer of the token(s)
       */
      iss: true
    },
    cookie: {
      //name: "_my_company_session",//default is _oeas_session
      //domain: null, //defaults to request domain, could do sso with more generic domain
      //path: "/",
    }
  }
};

config_token = jwt.sign(config_token, jwt_sign_secret);
const conifg_token_encrypted = utils.encrypt(
  proxy_encrypt_secret,
  config_token
);

//console.log("token: %s", config_token);
//console.log("");

//console.log("encrypted token: %s", conifg_token_encrypted);
//console.log("");

console.log(
  "URL safe config_token: %s",
  encodeURIComponent(conifg_token_encrypted)
);
console.log("");
