const jwt = require("jsonwebtoken");
const yaml = require("yaml");
const utils = require("../src/utils");

const config_token_sign_secret =
  process.env.EAS_CONFIG_TOKEN_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_SIGN_SECRET env variable");
const config_token_encrypt_secret =
  process.env.EAS_CONFIG_TOKEN_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ENCRYPT_SECRET env variable");
const config_issuer_sign_secret =
  process.env.EAS_CONFIG_ISSUER_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_ISSUER_SIGN_SECRET env variable");
const config_issuer_encrypt_secret =
  process.env.EAS_CONFIG_ISSUER_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_ISSUER_ENCRYPT_SECRET env variable");
const config_cookie_sign_secret =
  process.env.EAS_CONFIG_COOKIE_SIGN_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_COOKIE_SIGN_SECRET env variable");
const config_cookie_encrypt_secret =
  process.env.EAS_CONFIG_COOKIE_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_COOKIE_ENCRYPT_SECRET env variable");
const config_session_encrypt_secret =
  process.env.EAS_CONFIG_SESSION_ENCRYPT_SECRET ||
  utils.exit_failure("missing EAS_CONFIG_SESSION_ENCRYPT_SECRET env variable");
const github_client_id =
  process.env.EAS_GITHUB_CLIENT_ID ||
  utils.exit_failure("missing EAS_GITHUB_CLIENT_ID env variable");
const github_client_secret =
  process.env.EAS_GITHUB_CLIENT_SECRET ||
  utils.exit_failure("missing EAS_GITHUB_CLIENT_SECRET env variable");
const github_team_ids =
  process.env.EAS_GITHUB_TEAM_IDS.split(' ').map(x => Number(x)) ||
  utils.exit_failure("missing EAS_GITHUB_TEAM_IDS env variable");
const base_domain =
  process.env.EAS_BASE_DOMAIN ||
  utils.exit_failure("missing EAS_BASE_DOMAIN env variable");
const config_token_id =
  process.env.EAS_CONFIG_TOKEN_ID ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_ID env variable");
const config_token_store_id =
  process.env.EAS_CONFIG_TOKEN_STORE_ID ||
  utils.exit_failure("missing EAS_CONFIG_TOKEN_STORE_ID env variable");

let config_token_real = {
  /**
   * using the same aud for multiple tokens allows sso for all services sharing the aud
   */
  eas: {
    // list of plugin definitions, refer to PLUGINS.md for details
    plugins: [
      {
        type: "oauth2",
        issuer: {
          authorization_endpoint: "https://github.com/login/oauth/authorize",
          token_endpoint: "https://github.com/login/oauth/access_token"
        },
        client: {
          client_id: github_client_id,
          client_secret: github_client_secret
        },
        scopes: ["user"],
        /**
         * static redirect URI
         * if your oauth provider does not support wildcards place the URL configured in the provider (that will return to this proper service) here
         */
        redirect_uri: `https://eas.${base_domain}/oauth/callback`,

        features: {
          /**
           * if false cookies will be 'session' cookies
           * if true and cookies expire will expire with tokens
           */
          cookie_expiry: false,

          userinfo_expiry: 86400, // 24 hours

          /**
           * sessions become a floating window *if* tokens are being refreshed or userinfo being refreshed
           */
          session_expiry: 604800, // 7 days

          /**
           * if session_expiry is a number and this is set then sessions become a 'floating window'
           * if activity is triggered in this amount of time *before* preceeding the end of the
           * session then the expiration time is extended + session_expiry
           */
          session_expiry_refresh_window: 86400, // 24 hours

          /**
           * will re-use the same id (ie: same cookie) for a particular client if a session has expired
           */
          session_retain_id: true,

          /**
           * if the access token is expired and a refresh token is available, refresh
           */
          refresh_access_token: true,

          /**
           * fetch userinfo and include as X-Userinfo header to backing service
           */
          fetch_userinfo: true,

          userinfo: {
            provider: "github",
            config: {
              fetch_teams: true,
              fetch_organizations: true,
              fetch_emails: true
            }
          },

          /**
           * which token (if any) to send back to the proxy as the Authorization Bearer value
           * note the proxy must allow the token to be passed to the backend if desired
           *
           * possible values are access_token, or refresh_token
           */
          //authorization_token: "access_token"
        },
        assertions: {
          /**
           * assert the token(s) has not expired
           */
          exp: true,
          userinfo: [
            {
              query_engine: "jp",
              query: "$.teams[*].id",
              rule: {
                method: "contains-any",
                value: github_team_ids
                //negate: true,
                //case_insensitive: true
              }
            },
            {
              query_engine: "jp",
              query: "$.two_factor_authentication",
              rule: {
                  method: "eq",
                  value: true,
                  //negate: true,
                  //case_insensitive: true
              }
            }
          ]
        },
        cookie: {
          name: "_eas_github_session_", //default is _oeas_oauth_session
          domain: base_domain //defaults to request domain, could do sso with more generic domain
          //path: "/",
        }
      }
    ]
  }
};

let config_token_alias = {
  /**
   * future feature: allow blocking certain token IDs
   */
  //jti: <some known value>

  /**
   * using the same aud for multiple tokens allows sso for all services sharing the aud
   */
  //aud: "some application id", //should be unique to prevent cookie/session hijacking, defaults to a hash unique to the whole config
  eas: {
    config_token_id: config_token_id,
    config_token_store_id: config_token_store_id
  }

};

console.log("Token real config: \n%s", JSON.stringify(config_token_real, null, 4));
console.log("");

config_token_real_jwt = jwt.sign(config_token_real, config_token_sign_secret);
const config_token_real_encrypted = utils.encrypt(
  config_token_encrypt_secret,
  config_token_real_jwt
);

config_token_real_encrypted_uri = encodeURIComponent(config_token_real_encrypted);


console.log("Token alias config: \n%s", JSON.stringify(config_token_alias, null, 4));
console.log("");

config_token_alias_jwt = jwt.sign(config_token_alias, config_token_sign_secret);
const config_token_alias_encrypted = utils.encrypt(
  config_token_encrypt_secret,
  config_token_alias_jwt
);

config_token_alias_encrypted_uri = encodeURIComponent(config_token_alias_encrypted);

let helm_config = {
  configTokenSignSecret: config_token_sign_secret,
  configTokenEncryptSecret: config_token_encrypt_secret,
  issuerSignSecret: config_issuer_sign_secret,
  issuerEncryptSecret: config_issuer_sign_secret,
  cookieSignSecret: config_cookie_sign_secret,
  cookieEncryptSecret: config_cookie_encrypt_secret,
  sessionEncryptSecret: config_session_encrypt_secret,
  configTokenStores: {
    [config_token_store_id]: {
      adapter: "env",
      options: {
        cache_ttl: 0,
        var: "EAS_CONFIG_TOKENS"
      }
    }
  },
  configTokens: {
    [config_token_id]: config_token_real_encrypted
  },
  logLevel: "info",
  ingress: {
    enabled: true,
    annotations: {
      "kubernetes.io/ingress.class": "traefik",
      "kubernetes.io/tls-acme": "true",
      "traefik.ingress.kubernetes.io/frontend-entry-points": "http,https",
      "traefik.ingress.kubernetes.io/redirect-entry-point": "https"
    },
    hosts: [
      `eas.${base_domain}`
    ],
    paths: [
      "/"
    ],
    tls: [
      {
        hosts: [
          `eas.${base_domain}`
        ],
        secretName: `eas-${base_domain}-tls`.replace(/\./g,'-')
      }
    ]
  }
}

const ingress_config = {
  "kubernetes.io/ingress.class": "traefik",
  "kubernetes.io/tls-acme": "true",
  "traefik.ingress.kubernetes.io/frontend-entry-points": "http,https",
  "traefik.ingress.kubernetes.io/redirect-entry-point": "https",
  "ingress.kubernetes.io/auth-response-headers": "X-Userinfo,X-Id-Token,X-Access-Token,Authorization",
  "ingress.kubernetes.io/auth-type": "forward"
}

console.log("Helm values for central external-auth-server deployment: \n\n%s", yaml.stringify(helm_config));
console.log("");

console.log("Ingress annotations for each protected application (crypted query param): \n\n%s", yaml.stringify({...ingress_config, "ingress.kubernetes.io/auth-url": `https://eas.${base_domain}/verify?config_token=${config_token_alias_encrypted_uri}` }));
console.log("Ingress annotations for each protected application (plain query params): \n\n%s", yaml.stringify({...ingress_config, "ingress.kubernetes.io/auth-url": `https://eas.${base_domain}/verify?config_token_id=${config_token_id}&config_token_store_id=${config_token_store_id}`}));
console.log("");
