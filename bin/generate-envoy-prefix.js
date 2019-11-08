let verify_params = {
  config_token: "...", // the non URL safe variant
  fallback_plugin: 0
};

console.log(
  "URL safe path_prefix: %s",
  "/envoy/verify-params-url/" +
    encodeURIComponent(JSON.stringify(verify_params))
);
console.log("");
