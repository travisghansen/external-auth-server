A small example of a kustomize plugin that generates istio EnvoyFilter resource

HTPASSWD
--

* [example showing http password plugin with automatic htpasswd encoding from a list of users](htpasswd-auth-filter-generator.yaml)

OIDC
--

* [example showing oidc setup for keycloak permitting users with the admin role](oidc-auth-filter-generator.yaml)
* [example of generated output](oidc-auth-filter-generator-output.yaml)
* [demo of executing the plugin outside kustomize](oidc-auth-filter-generator-example.sh)


Installation
--

Requires the following command line tools to be installed

* docker
* htpasswd
* [deno](http://deno.land/)

Instructions for where to install the plugin https://github.com/kubernetes-sigs/kustomize/blob/master/docs/plugins/execPluginGuidedExample.md