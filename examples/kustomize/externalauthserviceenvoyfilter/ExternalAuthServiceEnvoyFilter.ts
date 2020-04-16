//
// https://github.com/kubernetes-sigs/kustomize/blob/master/docs/plugins/execPluginGuidedExample.md
//
import { readFileStr } from "https://deno.land/std/fs/mod.ts";
import { stringify, parse } from "https://deno.land/std/encoding/yaml.ts";

type PluginSpec = Record<string, string> & HtpasswdPluginSpec

type UsernamePassword = {
  username: string
  password: string
}
type HtpasswdPluginSpec = {
  type: 'htpasswd',
  htpasswd ?: string
  users? : UsernamePassword[]
}
type EasSpec = Record<string,string> & {
  plugins: PluginSpec[]
}
type TokenSpec = {
  eas: EasSpec
}

type SidecarSpec = {
  selector : Record<string, string>
  port: number
}
type ConfigSpec = {
  dockerImage ?: string
  configTokenSignSecret : string
  configTokenEncryptSecret : string
  token : TokenSpec
  sidecar: SidecarSpec
}

type Metadata = {
  name:string
}
type Config = {
  metadata: Metadata
  spec: ConfigSpec
}

async function encodeHtpasswd(user : UsernamePassword) : Promise<string> {
  const p = Deno.run({
    args: ["htpasswd", "-B",  "-n", "-b", user.username, user.password],
    stdout: "piped",
    stderr: "piped",
  });

  const { code } = await p.status();
  
  if (code === 0) {
    return (new TextDecoder().decode(await p.output()) as string).trim()
  }
  else {
    console.error(`Failed encoding htpasswd: ${code}\n${new TextDecoder().decode(await p.stderrOutput()) as string}`)
    Deno.exit(1)
    return ""
  }

}

async function encodeHtpasswds(users : UsernamePassword[]) : Promise<string> {
  return (await Promise.all(users.map(encodeHtpasswd))).join("\n")
}

async function preProcessHtpasswdPlugin(plugin: HtpasswdPluginSpec) {
  if (plugin.users && plugin.users.length) {
    plugin.htpasswd = await encodeHtpasswds(plugin.users)
    delete plugin.users
  }
}
async function preProcess(token: TokenSpec) {
  if (token.eas && token.eas.plugins) {
    await Promise.all(token.eas.plugins.map(plugin=>{
      if (plugin.type == 'htpasswd') {
        return preProcessHtpasswdPlugin(plugin as HtpasswdPluginSpec)
      }
    }))
  }
}

async function generateConfigToken(config : Config) : Promise<string> {
  let configTokenSignSecret = config.spec.configTokenSignSecret
  let configTokenEncryptSecret = config.spec.configTokenEncryptSecret
  let dockerImage = config.spec.dockerImage || 'external-auth-server' // default is to use custom image, can change to travisghansen/external-auth-server

  await preProcess(config.spec.token)
  let configTokenString = JSON.stringify(config.spec.token)
  // console.error(configTokenString)
  
  const p = Deno.run({
    args: [
      "docker",
      "run", 
      "-i",
      "--rm",
      "-e",
      `EAS_CONFIG_TOKEN_SIGN_SECRET=${configTokenSignSecret}`,
      "-e",
      `EAS_CONFIG_TOKEN_ENCRYPT_SECRET=${configTokenEncryptSecret}`,
      dockerImage,
      "generate-config-token",
    ],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  });

  await p.stdin?.write(new TextEncoder().encode(configTokenString))

  p.stdin?.close()

  const { code } = await p.status();
  
  if (code === 0) {
    return (new TextDecoder().decode(await p.output()) as string).trim()
  } else {
    console.error(`Failed ${code} ${new TextDecoder().decode(await p.stderrOutput()) as string}`)
    Deno.exit(1)
    return ""
  }
}

async function main() {

  let configFile = Deno.args[0]  
  let configFileContents = await readFileStr(configFile)
  let config = parse(configFileContents) as any

  let config_token = await generateConfigToken(config)

  let r = parse(`
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata: {}
spec:
  workloadLabels: {}
  filters:
    - filterConfig:
        failure_mode_allow: false
        httpService:
          authorizationRequest:
            allowedHeaders:
              patterns:
                - exact: cookie
                - exact: X-Forwarded-Host
                - exact: X-Forwarded-Method
                - exact: X-Forwarded-Proto
                - exact: X-Forwarded-Uri
            headers_to_add:
              - key: "x-eas-verify-params"
          pathPrefix: /envoy/verify-params-header
          serverUri:
            cluster: outbound|80||eas-external-auth-server.external-auth-server.svc.cluster.local
            timeout: 10s
            uri: http://eas-external-auth-server.external-auth-server.svc.cluster.local
        statusOnError:
          code: Forbidden
        withRequestBody:
          allowPartialMessage: true
          maxRequestBytes: 4096
      filterName: envoy.ext_authz
      filterType: HTTP
      insertPosition:
        index: FIRST
      listenerMatch:
        listenerProtocol: HTTP
        listenerType: SIDECAR_INBOUND
        portNumber: 0
  `) as any
  r.metadata.name = config.metadata.name
  r.spec.filters[0].filterConfig.httpService.authorizationRequest.headers_to_add[0].value = JSON.stringify({
    config_token: config_token
  })
  r.spec.filters[0].listenerMatch.portNumber = config.spec.sidecar.port
  r.spec.workloadLabels = config.spec.sidecar.selector

  console.log(stringify(r))
}

main()