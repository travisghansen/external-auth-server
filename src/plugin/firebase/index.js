const { Assertion } = require("../../assertion");
const { BasePlugin } = require("..");
const jwt = require("jsonwebtoken");
const request = require("request");

FIREBASE_JWT_KEYS_URI =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
FIREBASE_JWT_KEYS_CACHE_KEY = "firebase_jwt:sign_keys";
FIREBASE_USERINFO_URI =
  "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo";
FIREBASE_USERINFO_CACHE_PREFIX = "firebase_jwt:userinfo:";

/**
 * https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
 */
class FirebaseJwtPlugin extends BasePlugin {
  static initialize(server) {}

  /**
   * Create new instance
   *
   * @name constructor
   * @param {*} config
   */
  constructor(server, config) {
    super(...arguments);
  }

  /**
   * Verify the request
   *
   * @name verify
   * @param {*} configToken
   * @param {*} req
   * @param {*} res
   */
  async verify(configToken, req, res) {
    const plugin = this;
    const store = plugin.server.store;
    const parentReqInfo = plugin.server.utils.get_parent_request_info(req);
    plugin.server.logger.verbose("parent request info: %j", parentReqInfo);

    let realm = plugin.config.realm ? plugin.config.realm : parentReqInfo.uri;

    let header_name = plugin.config.header_name
      ? plugin.config.header_name
      : "authorization";
    header_name = header_name.toLowerCase();

    let scheme = plugin.config.scheme;

    if (!scheme) {
      if (header_name == "authorization") {
        scheme = "bearer";
      }
    }

    scheme = scheme.toLowerCase();

    let error, error_description;
    const failure_response = function(code = 401) {
      res.statusCode = code || 401;

      if (scheme == "bearer") {
        //Bearer realm="example", error="invalid_token", error_description="The access token expired"
        let value = 'Bearer realm="' + realm + '"';
        if (error) {
          value = value + ', error="' + error + '"';
        }

        if (error_description) {
          value = value + ', error_description="' + error_description + '"';
        }

        res.setHeader("WWW-Authenticate", value);
      }
    };

    if (!req.headers[header_name]) {
      failure_response();
      return res;
    }

    if (
      scheme &&
      !plugin.server.utils.authorization_scheme_is(
        req.headers[header_name],
        scheme
      )
    ) {
      failure_response();
      return res;
    }

    let creds = {};
    if (scheme) {
      creds = plugin.server.utils.parse_bearer_authorization_header(
        req.headers[header_name]
      );
    } else {
      creds.token = req.headers[header_name];
    }

    const config = plugin.config.config;

    let publicKeys;

    publicKeys = await store.get(FIREBASE_JWT_KEYS_CACHE_KEY);

    if (publicKeys == null) {
      plugin.server.logger.verbose(
        "firebase-jwt: fetching public signing keys"
      );
      let cache_ttl;
      publicKeys = await new Promise((resolve, reject) => {
        const options = {
          method: "GET",
          url: FIREBASE_JWT_KEYS_URI
        };
        request(options, function(error, res, body) {
          if (error) {
            reject(error);
          }

          if (res.headers.hasOwnProperty("cache-control")) {
            const cacheControlHeader = res.headers["cache-control"];
            const parts = cacheControlHeader.split(",");
            parts.forEach(part => {
              const subParts = part.trim().split("=");
              if (subParts[0] === "max-age") {
                const maxAge = +subParts[1];
                cache_ttl = maxAge;
              }
            });
          }
          resolve(JSON.parse(body));
        });
      });

      if (cache_ttl) {
        await store.set(
          FIREBASE_JWT_KEYS_CACHE_KEY,
          publicKeys,
          cache_ttl,
        );
      }
    } else {
      plugin.server.logger.verbose(
        "firebase-jwt: using cached public signing keys"
      );
    }

    config.options = config.options || {};
    config.features = config.features || {};

    // set hard-coded validation options
    // https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
    config.options.issuer =
      "https://securetoken.google.com/" + config.project_id;
    config.options.audience = config.project_id;

    function getKey(header, callback) {
      const key = publicKeys[header.kid];
      callback(null, key);
    }

    try {
      const token = await new Promise((resolve, reject) => {
        jwt.verify(creds.token, getKey, config.options, (err, decoded) => {
          if (err) {
            reject(err);
          }
          resolve(decoded);
        });
      });

      plugin.server.logger.debug("jwt token: %j", token);

      const valid = await plugin.id_token_assertions(token);
      if (valid !== true) {
        error = "invalid_user";
        error_description = "user did not pass assertions";

        failure_response(403);
        return res;
      } else {
        let userinfo;
        if (
          plugin.config.features.fetch_userinfo ||
          plugin.config.config.options.checkRevoked
        ) {
          userinfo = await plugin.fetch_userinfo(creds.token, token);
        }

        // assert userinfo here
        const valid = await plugin.userinfo_assertions(userinfo);
        if (valid !== true) {
          error = "invalid_user";
          error_description = "user did not pass assertions";

          failure_response(403);
          return res;
        }

        //validSince
        if (plugin.config.config.options.checkRevoked && userinfo.validSince) {
          if (token.auth_time < userinfo.validSince) {
            error = "token_invalidated";
            error_description = "token has been invalidated";

            failure_response(403);
            return res;
          }
        }

        res.setAuthenticationData({
          id_token: creds.token,
          userinfo: userinfo
        });
        res.statusCode = 200;
        return res;
      }
    } catch (e) {
      switch (e.name) {
        case "TokenExpiredError":
        case "JsonWebTokenError":
        case "NotBeforeError":
          error = e.name;
          error_description = e.message;
          break;
        default:
          throw e;
      }
    }

    failure_response();
    return res;
  }

  /**
   * https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key=[API_KEY]
   *
   * @param {*} id_token
   */
  async fetch_userinfo(id_token, decoded_id_token) {
    const plugin = this;
    const store = plugin.server.store;

    const store_key = FIREBASE_USERINFO_CACHE_PREFIX + decoded_id_token.sub;
    let userinfo = await store.get(store_key);

    if (userinfo == null) {
      let userdata = await new Promise((resolve, reject) => {
        const options = {
          method: "POST",
          url: FIREBASE_USERINFO_URI + "?key=" + plugin.config.config.api_key,
          headers: {
            "Content-Type": "application/json"
          },
          json: true,
          body: {
            idToken: id_token
          }
        };
        request(options, function(error, res, body) {
          if (error) {
            reject(error);
          }

          if (res.statusCode == 200) {
            resolve(body);
          } else {
            reject(
              "failed retrieving userinfo: code=" +
                body.error.code +
                ", message=" +
                body.error.message
            );
          }
        });
      });

      plugin.server.logger.verbose("userdata: %j", userdata);

      userinfo = userdata.users.find(function(element) {
        return element.localId == decoded_id_token.sub;
      });

      if (plugin.config.features.userinfo_expiry > 0) {
        //userinfo = await plugin.fetch_userinfo(creds.token, token);
        await store.set(
          store_key,
          plugin.server.utils.encrypt(
            plugin.server.secrets.session_encrypt_secret,
            JSON.stringify(userinfo)
          ),
          plugin.config.features.userinfo_expiry
        );
      }
    } else {
      userinfo = plugin.server.utils.decrypt(
        plugin.server.secrets.session_encrypt_secret,
        userinfo
      );
      userinfo = JSON.parse(userinfo);
    }

    plugin.server.logger.verbose("userinfo: %j", userinfo);

    return userinfo;
  }

  async id_token_assertions(id_token) {
    const plugin = this;

    if (plugin.config.assertions && plugin.config.assertions.id_token) {
      return await Assertion.assertSet(
        id_token,
        plugin.config.assertions.id_token
      );
    }
    return true;
  }

  async userinfo_assertions(userinfo) {
    const plugin = this;

    if (plugin.config.assertions && plugin.config.assertions.userinfo) {
      return await Assertion.assertSet(
        userinfo,
        plugin.config.assertions.userinfo
      );
    }
    return true;
  }
}

module.exports = {
  FirebaseJwtPlugin
};
