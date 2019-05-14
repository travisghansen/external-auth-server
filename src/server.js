const express = require("express");
const bodyParser = require("body-parser");
const ConfigToken = require("./config_token");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { PluginVerifyResponse } = require("./plugin");
const { ExternalAuthServer } = require("./");

const { OauthPlugin, OpenIdConnectPlugin } = require("./plugin/oauth");
const { RequestParamPlugin } = require("./plugin/request_param");
const { RequestHeaderPlugin } = require("./plugin/request_header");
const { HtPasswdPlugin } = require("./plugin/htpasswd");
const { LdapPlugin } = require("./plugin/ldap");

//Issuer.defaultHttpOptions = { timeout: 2500, headers: { 'X-Your-Header': '<whatever>' } };
const externalAuthServer = new ExternalAuthServer();
const app = express();

externalAuthServer.WebServer = app;

/**
 * register middleware
 */
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser(externalAuthServer.secrets.cookie_sign_secret));

/**
 * TODO: call initialize only if method exists and make sure to call on all plugins
 */
OauthPlugin.initialize(externalAuthServer);
OpenIdConnectPlugin.initialize(externalAuthServer);
RequestParamPlugin.initialize(externalAuthServer);
RequestHeaderPlugin.initialize(externalAuthServer);
HtPasswdPlugin.initialize(externalAuthServer);
LdapPlugin.initialize(externalAuthServer);

app.get("/ping", (req, res) => {
  res.statusCode = 200;
  res.end("pong");
});

/**
 * Verify the request with the given ConfigToken
 *
 */
app.get("/verify", (req, res) => {
  externalAuthServer.logger.silly("%j", {
    headers: req.headers,
    body: req.body
  });

  externalAuthServer.logger.info("starting verify pipeline");

  /**
   * pull the config token
   */
  let configToken;
  try {
    configToken = externalAuthServer.utils.decrypt(
      externalAuthServer.secrets.config_token_encrypt_secret,
      req.query.config_token
    );
    configToken = jwt.verify(
      configToken,
      externalAuthServer.secrets.config_token_sign_secret
    );

    configToken = externalAuthServer.setConfigTokenDefaults(configToken);
    configToken = new ConfigToken(configToken);

    externalAuthServer.logger.debug("config token: %j", configToken);

    const fallbackPlugin = req.query.fallback_plugin
      ? req.query.fallback_plugin
      : null;

    let fallbackPluginResponse;
    let lastPluginResponse;

    new Promise(resolve => {
      async function process() {
        for (let i = 0; i < configToken.eas.plugins.length; i++) {
          const pluginConfig = configToken.eas.plugins[i];
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
            case "request_param":
              plugin = new RequestParamPlugin(externalAuthServer, pluginConfig);
              break;
            case "request_header":
              plugin = new RequestHeaderPlugin(
                externalAuthServer,
                pluginConfig
              );
              break;
            case "htpasswd":
              plugin = new HtPasswdPlugin(externalAuthServer, pluginConfig);
              break;
            case "ldap":
              plugin = new LdapPlugin(externalAuthServer, pluginConfig);
              break;
            default:
              continue;
          }

          //plugin = new LdapPlugin(externalAuthServer, pluginConfig);

          externalAuthServer.logger.info(
            "starting verify for plugin: %s",
            pluginConfig.type
          );

          try {
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
          externalAuthServer.logger.debug(
            "plugin response %j",
            pluginResponse
          );

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

          if (configToken.eas.plugins.length == i + 1) {
            if (!fallbackPluginResponse) {
              fallbackPluginResponse = pluginResponse;
            }
            resolve(fallbackPluginResponse);
            break;
          }
        }
      }

      process();
    }).then(pluginResponse => {
      if (!pluginResponse) {
        pluginResponse = new PluginVerifyResponse();
        pluginResponse.statusCode = 503;
      }
      externalAuthServer.logger.info(
        "end verify pipeline with status: %d",
        pluginResponse.statusCode
      );
      ExternalAuthServer.setResponse(res, pluginResponse);
    });
  } catch (e) {
    externalAuthServer.logger.error(e);
    res.statusCode = 503;
    res.end();
    return;
  }
});

const port = process.env.EAS_PORT || 8080;
externalAuthServer.logger.info("starting server on port %s", port);
app.listen(port);
