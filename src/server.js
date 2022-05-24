const { Assertion } = require("./assertion");
const bodyParser = require("body-parser");
const ConfigToken = require("./config_token");
const cookieParser = require("cookie-parser");
const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const https = require("https");
const { HeaderInjector } = require("./header");
const { PluginVerifyResponse } = require("./plugin");
const { ExternalAuthServer } = require("./");
const promBundle = require("express-prom-bundle");

const queryString = require("query-string");
const URI = require("uri-js");

// auth plugins
const { OauthPlugin, OpenIdConnectPlugin } = require("./plugin/oauth");
const { RequestHeaderPlugin } = require("./plugin/request_header");
const { RequestJsPlugin } = require("./plugin/request_js");
const { RequestParamPlugin } = require("./plugin/request_param");
const { HtPasswdPlugin } = require("./plugin/htpasswd");
const { LdapPlugin } = require("./plugin/ldap");
const { JwtPlugin } = require("./plugin/jwt");
const { ForwardPlugin } = require("./plugin/forward");
const { FirebaseJwtPlugin } = require("./plugin/firebase");
const { NoopPlugin } = require("./plugin/noop");

// create app instance
const externalAuthServer = new ExternalAuthServer();
const app = express();

externalAuthServer.WebServer = app;

// config token store
const { ConfigTokenStoreManager } = require("./config_token_store");
const configTokenStoreManager = new ConfigTokenStoreManager(externalAuthServer);

/**
 * register middleware
 */
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser(externalAuthServer.secrets.cookie_sign_secret));
app.use(
  promBundle({
    includeMethod: true,
    includePath: true,
    promClient: {
      collectDefaultMetrics: {
        timeout: 2000,
      },
    },
  })
);

let revokedJtis = process.env["EAS_REVOKED_JTIS"];
if (revokedJtis) {
  revokedJtis = JSON.parse(revokedJtis);
} else {
  revokedJtis = [];
}

if (!Array.isArray(revokedJtis)) {
  externalAuthServer.logger.warn("EAS_REVOKED_JTIS must be an array");
  revokedJtis = [];
}

externalAuthServer.logger.info("revoked JTIs: %j", revokedJtis);

/**
 * TODO: call initialize only if method exists and make sure to call on all plugins
 */
OauthPlugin.initialize(externalAuthServer);
OpenIdConnectPlugin.initialize(externalAuthServer);
RequestParamPlugin.initialize(externalAuthServer);
RequestHeaderPlugin.initialize(externalAuthServer);
HtPasswdPlugin.initialize(externalAuthServer);
LdapPlugin.initialize(externalAuthServer);
JwtPlugin.initialize(externalAuthServer);
FirebaseJwtPlugin.initialize(externalAuthServer);
ForwardPlugin.initialize(externalAuthServer);
NoopPlugin.initialize(externalAuthServer);

app.get("/ping", (req, res) => {
  res.statusCode = 200;
  res.end("pong");
});

verifyHandler = async (req, res, options = {}) => {
  try {
    await _verifyHandler(req, res, options)
  } catch (error) {
    externalAuthServer.logger.error(error)
  }
}

_verifyHandler = async (req, res, options = {}) => {
  externalAuthServer.logger.silly("verify request details: %j", {
    url: req.url,
    params: req.params,
    query: req.query,
    http_method: req.method,
    http_version: req.httpVersion,
    headers: req.headers,
    body: req.body,
  });

  externalAuthServer.logger.info("starting verify pipeline");

  let easVerifyParams;
  if (
    req.headers["x-eas-verify-params"] &&
    options.trust_verify_params_header
  ) {
    easVerifyParams = JSON.parse(req.headers["x-eas-verify-params"]);
  } else if (req.params["verify_params"]) {
    easVerifyParams = JSON.parse(req.params["verify_params"]);
  } else {
    easVerifyParams = req.query;
  }

  externalAuthServer.logger.silly("verify params: %j", easVerifyParams);

  /**
   * pull the config token
   */
  let configToken;
  let isServerSideConfigToken = false;
  let serverSideConfigTokenId = null;
  let serverSideConfigTokenStoreId = null;
  const parentRequestInfo =
    externalAuthServer.utils.get_parent_request_info(req);
  try {
    if (easVerifyParams.config_token) {
      configToken = externalAuthServer.utils.decrypt(
        externalAuthServer.secrets.config_token_encrypt_secret,
        easVerifyParams.config_token
      );
      configToken = jwt.verify(
        configToken,
        externalAuthServer.secrets.config_token_sign_secret
      );

      if (
        configToken.eas.config_token_id &&
        configToken.eas.config_token_store_id
      ) {
        isServerSideConfigToken = true;
        serverSideConfigTokenId = configToken.eas.config_token_id;
        serverSideConfigTokenStoreId = configToken.eas.config_token_store_id;
      }
    } else if (
      (easVerifyParams.config_token_id ||
        (easVerifyParams.config_token_id_query &&
          easVerifyParams.config_token_id_query_engine)) &&
      (easVerifyParams.config_token_store_id ||
        (easVerifyParams.config_token_store_id_query &&
          easVerifyParams.config_token_store_id_query_engine))
    ) {
      let queryValue;
      isServerSideConfigToken = true;

      // prep queryable data block
      let queryData = { req: {} };
      if (
        (easVerifyParams.config_token_id_query &&
          easVerifyParams.config_token_id_query_engine) ||
        (easVerifyParams.config_token_store_id_query &&
          easVerifyParams.config_token_store_id_query_engine)
      ) {
        queryData.req.headers = req.headers;
        queryData.req.cookies = req.cookies;
        queryData.req.signedCookies = req.signedCookies;
        queryData.req.query = req.query;
        queryData.req.method = req.method;
        queryData.req.httpVersionMajor = req.httpVersionMajor;
        queryData.req.httpVersionMinor = req.httpVersionMinor;
        queryData.req.httpVersion = req.httpVersion;
        queryData.parentRequestInfo = parentRequestInfo;
        queryData.parentReqInfo = parentRequestInfo;
      }

      // determine token_id
      if (easVerifyParams.config_token_id) {
        serverSideConfigTokenId = easVerifyParams.config_token_id;
      } else if (
        easVerifyParams.config_token_id_query &&
        easVerifyParams.config_token_id_query_engine
      ) {
        externalAuthServer.logger.debug(
          "server-side config_token_id query info - query: %s, query_engine: %s, data: %j",
          easVerifyParams.config_token_id_query,
          easVerifyParams.config_token_id_query_engine,
          queryData
        );

        queryValue = await externalAuthServer.utils.json_query(
          easVerifyParams.config_token_id_query_engine,
          easVerifyParams.config_token_id_query,
          queryData
        );

        if (Array.isArray(queryValue) && queryValue.length == 1) {
          queryValue = queryValue[0];
        }

        serverSideConfigTokenId = queryValue;
      }

      // determine config_token_store_id
      if (easVerifyParams.config_token_store_id) {
        serverSideConfigTokenStoreId = easVerifyParams.config_token_store_id;
      } else if (
        easVerifyParams.config_token_store_id_query &&
        easVerifyParams.config_token_store_id_query_engine
      ) {
        externalAuthServer.logger.debug(
          "server-side config_token_store_id query info - query: %s, query_engine: %s, data: %j",
          easVerifyParams.config_token_store_id_query,
          easVerifyParams.config_token_store_id_query_engine,
          queryData
        );

        queryValue = await externalAuthServer.utils.json_query(
          easVerifyParams.config_token_store_id_query_engine,
          easVerifyParams.config_token_store_id_query,
          queryData
        );

        if (Array.isArray(queryValue) && queryValue.length == 1) {
          queryValue = queryValue[0];
        }

        serverSideConfigTokenStoreId = queryValue;
      }
    } else {
      throw new Error("missing valid config_token configuration");
    }

    // server-side token
    if (isServerSideConfigToken) {
      externalAuthServer.logger.info(
        "sever-side token: store=%s, id=%s",
        serverSideConfigTokenStoreId,
        serverSideConfigTokenId
      );

      configToken = await configTokenStoreManager.getToken(
        serverSideConfigTokenId,
        serverSideConfigTokenStoreId
      );
      externalAuthServer.logger.debug(
        "server-side config token: %s",
        configToken
      );

      // server-side tokens can be stored encrypted or not
      if (!externalAuthServer.utils.is_jwt(configToken)) {
        configToken = externalAuthServer.utils.decrypt(
          externalAuthServer.secrets.config_token_encrypt_secret,
          configToken
        );
      }

      configToken = jwt.verify(
        configToken,
        externalAuthServer.secrets.config_token_sign_secret
      );
    }

    configToken = externalAuthServer.setConfigTokenDefaults(configToken);
    configToken = new ConfigToken(configToken);

    externalAuthServer.logger.debug("config token: %j", configToken);

    if (!configToken.eas || !configToken.eas.plugins) {
      throw new Error("missing plugins");
    }

    if (configToken.jti && revokedJtis.includes(configToken.jti)) {
      throw new Error("revoked jti: " + configToken.jti);
    }

    const fallbackPlugin = easVerifyParams.fallback_plugin
      ? easVerifyParams.fallback_plugin
      : null;

    let fallbackPluginResponse;
    let lastPluginResponse;

    return new Promise((resolve) => {
      async function processPipeline() {
        for (let i = 0; i < configToken.eas.plugins.length; i++) {
          const pluginConfig = configToken.eas.plugins[i];
          pluginConfig.pcb = pluginConfig.pcb || {};

          const pluginResponse = new PluginVerifyResponse();

          let plugin;
          switch (pluginConfig.type) {
            case "oidc":
              plugin = new OpenIdConnectPlugin(
                externalAuthServer,
                pluginConfig
              );
              break;
            case "oauth2":
              plugin = new OauthPlugin(externalAuthServer, pluginConfig);
              break;
            case "request_header":
              plugin = new RequestHeaderPlugin(
                externalAuthServer,
                pluginConfig
              );
              break;
            case "request_js":
              if (process.env.EAS_ALLOW_EVAL) {
                plugin = new RequestJsPlugin(externalAuthServer, pluginConfig);
              } else {
                continue;
              }
              break;
            case "request_param":
              plugin = new RequestParamPlugin(externalAuthServer, pluginConfig);
              break;
            case "htpasswd":
              plugin = new HtPasswdPlugin(externalAuthServer, pluginConfig);
              break;
            case "ldap":
              plugin = new LdapPlugin(externalAuthServer, pluginConfig);
              break;
            case "jwt":
              plugin = new JwtPlugin(externalAuthServer, pluginConfig);
              break;
            case "forward":
              plugin = new ForwardPlugin(externalAuthServer, pluginConfig);
              break;
            case "firebase_jwt":
              plugin = new FirebaseJwtPlugin(externalAuthServer, pluginConfig);
              break;
            case "noop":
              plugin = new NoopPlugin(externalAuthServer, pluginConfig);
              break;
            default:
              continue;
          }

          pluginResponse.setPlugin(plugin);

          externalAuthServer.logger.info(
            "starting verify for plugin: %s",
            pluginConfig.type
          );

          try {
            /**
             * check if we should skip this plugin
             */
            if (pluginConfig.pcb.skip) {
              const data = {
                req: {},
                res: {},
                parentReqInfo: parentRequestInfo,
                configToken,
              };

              data.req.headers = JSON.parse(JSON.stringify(req.headers));
              data.req.cookies = JSON.parse(JSON.stringify(req.cookies));

              let skip = await Assertion.assertSet(data, pluginConfig.pcb.skip);

              if (skip) {
                externalAuthServer.logger.info(
                  "skipping plugin due to pcb assertions: %s",
                  pluginConfig.type
                );
                continue;
              }
            }
            await plugin.verify(configToken, req, pluginResponse);
          } catch (e) {
            externalAuthServer.logger.error(e);
            if (configToken.eas.plugins.length == i + 1) {
              if (fallbackPluginResponse) {
                resolve(fallbackPluginResponse);
              } else {
                resolve(lastPluginResponse);
              }
            }
            continue;
          }

          lastPluginResponse = pluginResponse;
          externalAuthServer.logger.debug("plugin response %j", pluginResponse);

          if (fallbackPlugin !== null) {
            if (i == fallbackPlugin) {
              fallbackPluginResponse = pluginResponse;
            }
          } else if (i + 1 == configToken.eas.plugins.length) {
            fallbackPluginResponse = pluginResponse;
          }

          if (
            pluginResponse.statusCode >= 200 &&
            pluginResponse.statusCode < 300
          ) {
            resolve(pluginResponse);
            break;
          }

          /**
           * check to see if we should stop pipeline immediately
           */
          if (pluginConfig.pcb.stop) {
            const data = {
              req: {},
              res: {},
              parentReqInfo: parentRequestInfo,
              configToken,
            };

            data.req.headers = JSON.parse(JSON.stringify(req.headers));
            data.req.cookies = JSON.parse(JSON.stringify(req.cookies));

            data.res.headers = JSON.parse(
              JSON.stringify(
                externalAuthServer.utils.lower_case_keys(pluginResponse.headers)
              )
            );

            data.res.statusCode = JSON.parse(
              JSON.stringify(pluginResponse.statusCode)
            );

            let stop = await Assertion.assertSet(data, pluginConfig.pcb.stop);

            if (stop === true) {
              externalAuthServer.logger.info(
                "stopping pipeline due to pcb assertions: %s",
                pluginConfig.type
              );
              resolve(pluginResponse);
              break;
            }
          }

          if (configToken.eas.plugins.length == i + 1) {
            if (!fallbackPluginResponse) {
              fallbackPluginResponse = pluginResponse;
            }
            resolve(fallbackPluginResponse);
            break;
          }
        }

        // bad configuration (ie: no valid plugins defined)
        resolve();
      }

      await processPipeline();
    }).then(async (pluginResponse) => {
      if (!pluginResponse) {
        pluginResponse = new PluginVerifyResponse();
        pluginResponse.plugin = {};
        pluginResponse.plugin.config = {};
        pluginResponse.statusCode = 503;
      }
      externalAuthServer.logger.info(
        "end verify pipeline with status: %d",
        pluginResponse.statusCode
      );

      const pluginConfig = pluginResponse.plugin.config;
      const injectData = pluginResponse.authenticationData;
      injectData.plugin_config = pluginConfig;
      injectData.config_token = configToken;
      injectData.req = {};
      injectData.req.headers = req.headers;
      injectData.req.cookies = req.cookies;
      injectData.req.signedCookies = req.signedCookies;
      injectData.req.query = req.query;
      injectData.req.method = req.method;
      injectData.req.httpVersionMajor = req.httpVersionMajor;
      injectData.req.httpVersionMinor = req.httpVersionMinor;
      injectData.req.httpVersion = req.httpVersion;
      injectData.parentRequestInfo = parentRequestInfo;
      injectData.parentReqInfo = parentRequestInfo;

      if (pluginResponse.statusCode >= 200 && pluginResponse.statusCode < 300) {
        // set config_token headers
        if (configToken.eas.custom_service_headers) {
          const headersInjector = new HeaderInjector(
            configToken.eas.custom_service_headers,
            injectData
          );
          await headersInjector.injectHeaders(pluginResponse);
        }

        // set plugin headers
        if (pluginConfig.custom_service_headers) {
          const headersInjector = new HeaderInjector(
            pluginConfig.custom_service_headers,
            injectData
          );
          await headersInjector.injectHeaders(pluginResponse);
        }
      } else {
        // set config_token headers
        if (configToken.eas.custom_error_headers) {
          const headersInjector = new HeaderInjector(
            configToken.eas.custom_error_headers,
            injectData
          );
          await headersInjector.injectHeaders(pluginResponse);
        }

        // set plugin headers
        if (pluginConfig.custom_error_headers) {
          const headersInjector = new HeaderInjector(
            pluginConfig.custom_error_headers,
            injectData
          );
          await headersInjector.injectHeaders(pluginResponse);
        }
      }

      if (options.return_response) {
        return pluginResponse;
      } else {
        ExternalAuthServer.setResponse(res, pluginResponse);
      }
    });
  } catch (e) {
    externalAuthServer.logger.error(e);
    if (options.return_response) {
      throw e;
    } else {
      res.statusCode = 503;
      res.end();
      return;
    }
  }
};

/**
 * Verify the request with the given ConfigToken
 *
 */
app.all("/verify", verifyHandler);

// deprecated endpoint
app.all("/ambassador/verify-params-url/:verify_params/*", async (req, res) => {
  externalAuthServer.logger.warn(
    "/ambassador endpoints have been deprecated in favor of /envoy variants"
  );

  req.headers["x-forwarded-uri"] =
    externalAuthServer.utils.get_envoy_forwarded_uri(req);
  req.headers["x-forwarded-method"] = req.method;

  verifyHandler(req, res);
});

app.all("/envoy/verify-params-url/:verify_params/*", async (req, res) => {
  req.headers["x-forwarded-uri"] =
    externalAuthServer.utils.get_envoy_forwarded_uri(req);
  req.headers["x-forwarded-method"] = req.method;

  verifyHandler(req, res);
});

app.all("/envoy/verify-params-header(/*)?", async (req, res) => {
  req.headers["x-forwarded-uri"] =
    externalAuthServer.utils.get_envoy_forwarded_uri(req, 3);
  req.headers["x-forwarded-method"] = req.method;

  verifyHandler(req, res, { trust_verify_params_header: true });
});

// ingress-nginx
app.get("/nginx/auth-signin", (req, res) => {
  externalAuthServer.logger.silly("%j", {
    headers: req.headers,
    body: req.body,
  });

  try {
    const parsedRequestURI = URI.parse(req.url);
    externalAuthServer.logger.verbose(
      "parsed request uri: %j",
      parsedRequestURI
    );

    let parsedRequestQuery = queryString.parse(parsedRequestURI.query);
    /**
     * Hack to workaround nginx configuration limitations
     */
    if (Object.keys(parsedRequestQuery).length > 1) {
      const rd_index = parsedRequestURI.query.indexOf("rd=");
      const query_before_rd = parsedRequestURI.query.substring(0, rd_index);
      const query_after_rd = parsedRequestURI.query.substring(rd_index + 3);
      parsedRequestQuery = queryString.parse(
        query_before_rd + "rd=" + encodeURIComponent(query_after_rd)
      );
    }

    externalAuthServer.logger.verbose(
      "parsed request query: %j",
      parsedRequestQuery
    );
    let redirect_uri;
    if (!redirect_uri && parsedRequestQuery.rd) {
      redirect_uri = parsedRequestQuery.rd;
    }

    if (!redirect_uri) {
      throw new Error("missing redirect_uri");
    }

    externalAuthServer.logger.info("redirecting browser to: %j", redirect_uri);

    res.statusCode = 302;
    res.setHeader("Location", redirect_uri);
    res.end();
    return;
  } catch (e) {
    server.logger.error(e);
    res.statusCode = 503;
    res.end();
  }
});

const port = process.env.EAS_PORT || 8080;
externalAuthServer.logger.info("starting http(s) server on port %s", port);

if (process.env.EAS_SSL_CERT) {
  https
    .createServer(
      {
        key: fs.readFileSync(process.env.EAS_SSL_KEY, "utf8"),
        cert: fs.readFileSync(process.env.EAS_SSL_CERT, "utf8"),
        ca: process.env.EAS_SSL_CA
          ? fs.readFileSync(process.env.EAS_SSL_CA, "utf8")
          : undefined,
      },
      app
    )
    .listen(port);
} else {
  app.listen(port);
}

// grpc

/**
 * ::: ipv6
 * 0.0.0.0 ipv4
 */
const grpcAddress = process.env.EAS_GRPC_ADDRESS || "0.0.0.0";
const grpcPort = process.env.EAS_GRPC_PORT || 50051;

/**
 * grpc (c-based implementation)
 * @grpc/grpc-js (pure js implementation)
 */
const grpcImplementation = process.env.EAS_GRPC_IMPLEMENTATION || "@grpc/grpc-js";
const grpc = require(grpcImplementation);
const protoLoader = require("@grpc/proto-loader");

const sign = require("cookie-signature").sign;
const cookie = require("cookie");
const merge = require("utils-merge");

const PROTO_PATH =
  __dirname + "/../grpc/envoy/service/auth/v3/external_auth.proto";
const googleProtos = require("google-proto-files");

const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [__dirname + "/../grpc", googleProtos.getProtoPath() + "/../"],
});

const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
const grpcServer = new grpc.Server();

grpcServer.addService(
  protoDescriptor.envoy.service.auth.v3.Authorization.service,
  {
    async Check(call, callback) {
      let grpcRes;

      try {
        let cleansedCall = JSON.parse(externalAuthServer.utils.stringify(call));
        externalAuthServer.logger.debug(
          "new grpc request - Check call: %j",
          cleansedCall
        );

        /**
         * create mock req object
         */
        const req = {};
        req.url = ""; // URL used to invoke eas itself, empty when using grpc
        req.params = {}; // URL params when invoking eas itself, empty when using grpc
        req.query = {}; // URL query params when invoking eas itself, empty when using grpc
        req.http_method = ""; // method used to invoke eas itself, empty when using grpc
        req.http_version = ""; // version used to invoke eas itself, empty when using grpc
        req.headers = call.request.attributes.request.http.headers; // headers from parent
        req.body = call.request.attributes.request.http.body; // body from parent
        //req.query.redirect_http_code? really only exists to workaround nginx shortcomings, likely not needed here

        // c-based grpc metadata is present at this attribute
        let metadata = _.get(call, "metadata._internal_repr");

        // c-based grpc not in use
        if (!metadata) {
          // get metadata object and convert to basic json object
          metadata = _.get(call, "metadata", {});
          metadata = JSON.parse(JSON.stringify(metadata));
        }
        let filter_metadata = _.get(
          call,
          "request.attributes.metadata_context.filter_metadata.eas.fields.eas.structValue.fields"
        );

        // function to prroperly retrieve value from filter_metadata
        const getFilterMetadataValue = function (filter_metadata, key) {
          const field = _.get(filter_metadata, key);
          if (field) {
            return field[field["kind"]];
          }
        };

        // for explanation on order of preference of the data below see the following
        // https://github.com/travisghansen/external-auth-server/pull/126#issuecomment-980094773

        let verify_params;

        // header
        // not safe

        // filter_metadata
        if (!verify_params) {
          verify_params = getFilterMetadataValue(
            filter_metadata,
            "x-eas-verify-params"
          );
        }

        // initial_metadata
        if (!verify_params) {
          verify_params = _.last(_.get(metadata, "x-eas-verify-params"));
        }

        // context
        if (!verify_params) {
          verify_params =
            call.request.attributes.context_extensions["x-eas-verify-params"];
        }

        req.headers["x-eas-verify-params"] = verify_params;

        let scheme;
        let host = call.request.attributes.request.http.host;
        let port;
        let destination_port = "";

        // header
        // this head can be trusted as being set by envoy
        if (!scheme) {
          scheme = _.get(req.headers, "x-forwarded-proto");
        }

        // filter_metadata
        if (!scheme) {
          scheme = getFilterMetadataValue(filter_metadata, "x-forwarded-proto");
        }

        // initial_metadata
        if (!scheme) {
          scheme = _.last(_.get(metadata, "x-forwarded-proto"));
        }

        // context
        if (!scheme) {
          scheme = _.get(
            call.request.attributes.context_extensions,
            "x-forwarded-proto"
          );
        }

        // fallback to scheme of the envoy request directly
        if (!scheme) {
          switch (call.request.attributes.request.http.scheme) {
            case "http":
            case "https":
              scheme = call.request.attributes.request.http.scheme;
              break;
          }
        }

        if (!scheme) {
          throw new Error("unknown request scheme");
        }

        if (host.includes(":")) {
          host = host.split(":", 1)[0];
        }

        // header
        // by default this CANNOT be trusted
        //if (!port) {
        //  port = _.get(req.headers, "x-forwarded-port");
        //}

        // filter_metadata
        if (!port) {
          port = getFilterMetadataValue(filter_metadata, "x-forwarded-port");
        }

        // initial_metadata
        if (!port) {
          port = _.last(_.get(metadata, "x-forwarded-port"));
        }

        // context
        if (!port) {
          port = _.get(
            call.request.attributes.context_extensions,
            "x-forwarded-port"
          );
        }

        // request host
        if (!port) {
          if (call.request.attributes.request.http.host.includes(":")) {
            port = call.request.attributes.request.http.host.split(":", 2)[1];
          }
        }

        // fallback to port of the envoy request directly
        if (!port) {
          port =
            call.request.attributes.destination.address.socket_address
              .port_value;
        }

        if (!port) {
          throw new Error("unknown request port");
        }

        // only set port if non-standard to the scheme
        switch (scheme) {
          case "http":
            if (port !== 80) {
              destination_port = `:${port}`;
            }
            break;
          case "https":
            if (port !== 443) {
              destination_port = `:${port}`;
            }
            break;
          default:
            throw new Error("unknown request scheme");
            break;
        }

        req.headers[
          "x-eas-request-uri"
        ] = `${scheme}://${host}${destination_port}${call.request.attributes.request.http.path}`;
        req.headers["x-forwarded-method"] =
          call.request.attributes.request.http.method;

        // parse cookies into req object
        cookieParser(externalAuthServer.secrets.cookie_sign_secret)(
          req,
          {},
          () => {}
        );

        //console.log(req);

        /**
         * tell verify function to return to us directly the pluginResponse
         */
        let pluginResponse = await verifyHandler(
          req,
          {},
          { return_response: true, trust_verify_params_header: true }
        );

        //console.log("pluginResponse", pluginResponse);
        let grpcHeaders = [];

        // deal with cookies
        let setCookieHeaders = [];
        const clearCookie = function clearCookie(name, options) {
          var opts = merge({ expires: new Date(1), path: "/" }, options);

          return setCookie(name, "", opts);
        };

        const setCookie = function (name, value, options) {
          var opts = merge({}, options);
          var secret = externalAuthServer.secrets.cookie_sign_secret;
          var signed = opts.signed;

          if (signed && !secret) {
            throw new Error(
              'cookieParser("secret") required for signed cookies'
            );
          }

          var val =
            typeof value === "object"
              ? "j:" + JSON.stringify(value)
              : String(value);

          if (signed) {
            val = "s:" + sign(val, secret);
          }

          if ("maxAge" in opts) {
            opts.expires = new Date(Date.now() + opts.maxAge);
            opts.maxAge /= 1000;
          }

          if (opts.path == null) {
            opts.path = "/";
          }

          return cookie.serialize(name, String(val), opts);
        };

        pluginResponse.cookies.forEach((cookie) => {
          setCookieHeaders.push(setCookie(...cookie));
        });

        pluginResponse.clearCookies.forEach((cookie) => {
          setCookieHeaders.push(clearCookie(...cookie));
        });

        for (let header of setCookieHeaders) {
          grpcHeaders.push({
            header: {
              key: "Set-Cookie",
              value: header,
            },
            append: {
              value: false,
            },
          });
        }

        // deal with headers
        for (let header in pluginResponse.headers) {
          grpcHeaders.push({
            header: {
              key: header,
              value: pluginResponse.headers[header],
            },
            append: {
              value: false,
            },
          });
        }

        /**
         * translate the pluginResponse to the appropriate grpc response
         * https://cloud.google.com/natural-language/docs/reference/rpc/google.rpc#status
         */
        if (
          pluginResponse.statusCode >= 200 &&
          pluginResponse.statusCode < 300
        ) {
          grpcRes = {
            status: {
              code: grpc.status.OK,
              message: "OK",
            },
            //denied_response: {},
            ok_response: {
              // headers to add before upstream service
              headers: grpcHeaders,
              // headers to remove before upstream service
              headers_to_remove: [],
              // headers to send to downstream client (after upstream has handled request)
              response_headers_to_add: [],
              // key value pairs for upstream filters
              dynamic_metadata: {},
            },
          };
        } else {
          grpcRes = {
            status: {
              code: grpc.status.PERMISSION_DENIED,
              message: pluginResponse.statusMessage,
            },
            denied_response: {
              status: {
                code: pluginResponse.statusCode,
              },
              headers: grpcHeaders,
              body: pluginResponse.body,
            },
          };
        }

        externalAuthServer.logger.debug(
          "new grpc response - Check call: %j",
          grpcRes
        );
        callback(null, grpcRes);
      } catch (e) {
        externalAuthServer.logger.error(e);
        grpcRes = {
          status: {
            code: grpc.status.UNAVAILABLE,
            message: "",
          },
          denied_response: {
            status: {
              code: 503,
            },
            //headers: grpcHeaders,
            //body: pluginResponse.body,
          },
        };

        externalAuthServer.logger.debug(
          "new grpc response - Check call: %j",
          grpcRes
        );
        callback(null, grpcRes);
      }
    },
  }
);

// https://grpc.github.io/grpc/node/grpc.ServerCredentials.html
let grpcCredentials;
if (process.env.EAS_GRPC_SSL_CERT) {
  // <static> createSsl(rootCerts, keyCertPairs [, checkClientCertificate])
  grpcCredentials = grpc.ServerCredentials.createSsl(
    null,
    [
      {
        private_key: Buffer.from(
          fs.readFileSync(process.env.EAS_GRPC_SSL_KEY, "utf8")
        ),
        cert_chain: Buffer.from(
          fs.readFileSync(process.env.EAS_GRPC_SSL_CERT, "utf8")
        ),
      },
    ],
    false
  );
} else {
  grpcCredentials = grpc.ServerCredentials.createInsecure();
}

externalAuthServer.logger.info("starting grpc server on port %s", grpcPort);

// https://grpc.github.io/grpc/node/grpc.Server.html
grpcServer.bindAsync(`${grpcAddress}:${grpcPort}`, grpcCredentials, () => {
  grpcServer.start();
});
