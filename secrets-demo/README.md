# secrets-demo

Two small apps for **demonstrating and validating** secrets-manager integrations on Kubernetes
(HashiCorp Vault, Idira Secrets Manager / Conjur, External Secrets, CSI, plain K8s Secrets) and
**SPIFFE** service-to-service auth. They deliberately *display* secret values and credentials.
Use non-critical secrets only.

```
 browser ──NodePort──▶ web (Rust BFF + static UI) ──(optional JWT-SVID)──▶ api (Rust, GraphQL) ◀──NodePort── curl / GraphiQL
                                                                              │ reads
                                              env vars · mounted files · K8s Secret volumes · Vault agent files · CSI mounts
```

| | |
|---|---|
| **api** (`api/`) | GraphQL: `secrets` (name, delivery *method*, *kind* env/file, location, **value**, size, sha256, mtime), `config` (its ConfigMap + pod info), `identity` (SPIFFE caller + own X.509-SVID), **subscription** `secretValue(name)` (emits now and on every change). GraphiQL at `/`. |
| **web** (`web/`) | UI tabs: *Secrets*, *Live secret* (subscription), *Configuration* (web + API ConfigMaps), *SPIFFE* (X.509-SVID, JWT-SVID header/claims/token, how the API sees the caller, and an authorisation test). |
| **chart** (`deploy/helm/secrets-demo`) | Both deployments, ConfigMaps, NodePorts (API 30080, web 30081), optional SPIFFE wiring. |

The browser never talks to the API directly: the web back end holds the SPIFFE identity and relays
(GraphQL pass-through at `/bff/graphql`, the subscription is bridged to SSE). The API's own NodePort stays
reachable so you can show that, with SPIFFE on, direct calls are refused.

## Quick start

```bash
helm install demo deploy/helm/secrets-demo --set image.api.repository=ghcr.io/wvanbesien/secrets-demo-api \
  --set image.web.repository=ghcr.io/wvanbesien/secrets-demo-web
# web UI  http://<node-ip>:30081      API  http://<node-ip>:30080/
```

The default scenario needs nothing external: a chart-created K8s Secret delivered as env vars and as files.

### Without Helm (plain YAML)

`deploy/manifests/secrets-demo.yaml` is the default scenario as one plain file (two Deployments, NodePort
Services 30081 web / 30080 API, ConfigMaps, ServiceAccounts, demo Secret):

```bash
kubectl create namespace demo
kubectl apply -f deploy/manifests/secrets-demo.yaml -n demo
```

Edit the `image:` lines in the file to use a different tag or registry. To change the scenario, edit the two
ConfigMaps in the file and run `kubectl rollout restart deploy -n demo`. (The file is generated from the chart
with `helm template`, which you only need if you want to regenerate it for another scenario.)

Run locally without Kubernetes:

```bash
cargo build --release
DB_PASSWORD=hunter2 CONFIG_FILE=./my-api.yaml LISTEN_ADDR=127.0.0.1:8080 target/release/secrets-demo-api
CONFIG_FILE=./my-web.yaml LISTEN_ADDR=127.0.0.1:8081 API_URL=http://127.0.0.1:8080 target/release/secrets-demo-web
```

## Switching scenarios = changing settings

Everything about *which secrets are shown* and *how they got there* is in the ConfigMap
(`api.config` in Helm values; the file is `config.yaml`). Pods restart automatically on change.

```yaml
scenario: my-label            # free text, shown in both UIs
watchIntervalMs: 1000         # subscription poll interval
secrets:                      # explicit
  - {name: db, method: vault-agent-injector, kind: file, source: /vault/secrets/db}
  - {name: tok, method: k8s-secret-env,      kind: env,  source: DB_TOKEN}
secretDirs:                   # every file below the dir (K8s ..data symlinks handled)
  - {path: /mnt/secrets-store, method: vault-csi-file, namePrefix: "csi/"}
envPrefixes:                  # every env var with this prefix
  - {prefix: DEMO_SECRET_, method: k8s-secret-env, namePrefix: "env/"}
labels: {vaultRole: demo}
```

`method` is just the label you want displayed. Ready-made scenarios in `deploy/examples/`:

| file | scenario |
|---|---|
| `01-k8s-secret.yaml` | K8s Secret as env + volume (default) |
| `02-vault-agent-injector.yaml` | Vault Agent sidecar renders files; rotation shows in the subscription |
| `03-vault-csi.yaml` | Secrets Store CSI + Vault provider, with synced K8s Secret |
| `04-external-secrets.yaml` | External Secrets Operator → K8s Secret |
| `05-conjur-secrets-provider.yaml` | Idira/Conjur Secrets Provider, push-to-file sidecar |
| `10-spiffe.yaml` | overlay: enable SPIFFE on top of any of the above |

```bash
helm upgrade --install demo deploy/helm/secrets-demo -f deploy/examples/02-vault-agent-injector.yaml -f deploy/examples/10-spiffe.yaml
```

Generic hooks for anything else: `api.podAnnotations`, `api.env`, `api.envFrom`, `api.volumes`,
`api.volumeMounts`, `api.extraContainers`, `api.initContainers`, `extraObjects` (templated manifests).

Note: env vars are fixed at pod start, so an env-delivered secret appears once in the subscription;
files (Vault agent, CSI with rotation, K8s Secret volumes, Conjur push-to-file) update live.
**Examples 02–05 are starting points**: edit hosts, paths and identities for your environment.

## SPIFFE

`spiffe.enabled: true` (chart) / `spiffe.enabled` in each ConfigMap:

* **web** fetches a JWT-SVID (audience `spiffe.audience`) from the Workload API for each API call.
* **api** requires `Authorization: Bearer <JWT-SVID>` on `/graphql` and `/graphql/ws`; the SVID issuer (via the Workload API)
  validates signature/expiry/audience. If `spiffe.allowedIds` is set (the chart defaults it to the web's
  service account ID) any other, otherwise valid, identity gets **403**. No credentials → **401**; agent
  unreachable → **503** (fails closed). `/` (GraphiQL) and `/healthz` stay open but expose nothing.
* The **SPIFFE tab** shows the web's X.509-SVID (SPIFFE ID, serial, validity, SAN, PEM), its JWT-SVID
  (header, claims, raw token), the API's own X.509-SVID, how the API sees the caller, and a
  **Run authorisation test** button: no credentials / garbage token / valid SVID but wrong audience /
  correct SVID. With SPIFFE on, only the last succeeds; with it off, all succeed.

SPIFFE is **off by default** and independent of the secrets scenarios. The apps are issuer-agnostic:
they only use the standard SPIFFE Workload API (`SPIFFE_ENDPOINT_SOCKET`), so whichever product issues the
SVIDs just has to expose that socket to the pods (`spiffe.workloadApiVolume`, `socketDir`, `socketName`) and
issue identities to the two service accounts. Nothing SPIRE-specific is deployed by this chart.
Requirement on the issuer: it must implement the Workload API's `FetchJWTSVID`, `FetchX509SVID` and
`ValidateJWTSVID` calls (the API delegates JWT validation to it). Authentication uses JWT-SVIDs; X.509-SVIDs
are displayed but mTLS is not used on the wire.

## Build and publish

```bash
docker build --build-arg BIN=secrets-demo-api -t ghcr.io/wvanbesien/secrets-demo-api:dev .
docker build --build-arg BIN=secrets-demo-web -t ghcr.io/wvanbesien/secrets-demo-web:dev .
```

`.github/workflows/secrets-demo.yml (repo root)` runs fmt/clippy/tests, pushes both images to GHCR on `main` and `secrets-demo-v*` tags
(linux/amd64), and on tags also publishes the chart to `oci://ghcr.io/wvanbesien/charts`.
Make the GHCR packages public after the first push.

## Status of this repo

Verified: Rust builds, clippy/fmt clean, unit tests; API and web run end to end locally with real
env/file/K8s-symlink-layout secrets, live subscription updates, browser UI under Playwright; with SPIFFE
enabled and no credentials the API returns 401/503 on HTTP and WebSocket.
**Not yet verified:** SPIFFE against a real SVID issuer, `helm lint`/`helm template`/install,
the Docker build, and examples 02–05 against real Vault/Conjur/ESO/CSI.
