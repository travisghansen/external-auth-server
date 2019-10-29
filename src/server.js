const { Assertion } = require("./assertion");
const express = require("express");
const bodyParser = require("body-parser");
const ConfigToken = require("./config_token");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { HeaderInjector } = require("./header");
const { PluginVerifyResponse } = require("./plugin");
const { ExternalAuthServer } = require("./");
const promBundle = require("express-prom-bundle");

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
        timeout: 2000
      }
    }
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
  externalAuthServer.logger.silly("verify request details: %j", {
    url: req.url,
    params: req.params,
    query: req.query,
    http_method: req.method,
    http_version: req.httpVersion,
    headers: req.headers,
    body: req.body
  });

  externalAuthServer.logger.info("starting verify pipeline");

  let easVerifyParams;
  if (req.headers["x-eas-verify-params"]) {
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
        queryData.req.query = req.query;
        queryData.req.method = req.method;
        queryData.req.method.httpVersionMajor = req.method.httpVersionMajor;
        queryData.req.method.httpVersionMinor = req.method.httpVersionMinor;
        queryData.req.method.httpVersion = req.method.httpVersion;
        queryData.parentRequestInfo = externalAuthServer.utils.get_parent_request_info(
          req
        );
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

      configToken = externalAuthServer.utils.decrypt(
        externalAuthServer.secrets.config_token_encrypt_secret,
        configToken
      );
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

    new Promise(resolve => {
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
                res: {}
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
              res: {}
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

      processPipeline();
    }).then(async pluginResponse => {
      if (!pluginResponse) {
        pluginResponse = new PluginVerifyResponse();
        pluginResponse.statusCode = 503;
      }
      externalAuthServer.logger.info(
        "end verify pipeline with status: %d",
        pluginResponse.statusCode
      );

      if (pluginResponse.statusCode >= 200 && pluginResponse.statusCode < 300) {
        const pluginConfig = pluginResponse.plugin.config;
        const injectData = pluginResponse.authenticationData;
        injectData.plugin_config = pluginConfig;
        injectData.config_token = configToken;

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
      }

      ExternalAuthServer.setResponse(res, pluginResponse);
    });
  } catch (e) {
    externalAuthServer.logger.error(e);
    res.statusCode = 503;
    res.end();
    return;
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

  req.headers[
    "x-forwarded-uri"
  ] = externalAuthServer.utils.get_envoy_forwarded_uri(req);
  req.headers["x-forwarded-method"] = req.method;

  verifyHandler(req, res);
});

app.all("/envoy/verify-params-url/:verify_params/*", async (req, res) => {
  req.headers[
    "x-forwarded-uri"
  ] = externalAuthServer.utils.get_envoy_forwarded_uri(req);
  req.headers["x-forwarded-method"] = req.method;

  verifyHandler(req, res);
});

app.all("/envoy/verify-params-header(/*)?", async (req, res) => {
  req.headers[
    "x-forwarded-uri"
  ] = externalAuthServer.utils.get_envoy_forwarded_uri(req, 3);
  req.headers["x-forwarded-method"] = req.method;

  verifyHandler(req, res);
});

const port = process.env.EAS_PORT || 8080;
externalAuthServer.logger.info("starting server on port %s", port);
app.listen(port);
