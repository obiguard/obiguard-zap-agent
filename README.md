# obiguard-zap-agent

Runs an [OWASP ZAP](https://www.zaproxy.org/) security scan inside your own network, on Obiguard's behalf, for internal applications Obiguard's hosted scanner can't otherwise reach.

## Why this exists

Obiguard's Attack Surface Scanning normally runs from Obiguard's own servers, which only ever see what's exposed to the public internet. If your application is internal-only — behind a VPN, in a private VPC, with no public ingress — Obiguard's scanner physically cannot reach it. This agent solves that by running the scan from inside your network instead, using your own outbound internet access, with no inbound port ever opened.

## What it does

1. Polls `https://zap-agent.obiguard.ai` (or your configured relay URL) for a queued scan job — the same request/response shape a CI runner uses to check for pipeline work.
2. When a job arrives, it contains a complete, ready-to-run [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) plan, built entirely on Obiguard's side. This agent has no logic for building scan plans, choosing targets, or interpreting findings — it only ever runs what it's given.
3. Runs `zap.sh -cmd -autorun plan.yaml` as a local process, using your network to reach the target. There's no separate container spun up per scan — ZAP runs directly alongside this binary. If the machine has no ZAP, the agent installs its own copy first (see [Requirements](#requirements)); you never have to.
4. Uploads the resulting report back to Obiguard, then deletes every local trace of that job (the plan file and any working directory) before polling for the next one.

That's the entire feature set. There is no other code path.

## What it explicitly does not do

- **No inbound connections, ever.** This binary only makes outbound HTTPS requests to Obiguard. It never listens on a port, never accepts a connection from anywhere.
- **No arbitrary network access.** The only network access ZAP gets is whatever the plan it was handed drives it to make — never an ad-hoc destination or command supplied at request time beyond that plan.
- **No persistence beyond one job.** Nothing is cached, logged to disk, or kept around between runs. See [SECURITY.md](SECURITY.md) for what a scan plan contains and how it's handled.
- **No telemetry beyond what's needed to run a job and report results.**

## Requirements

- **Nothing to install but this agent.** ZAP is a Java application, and the agent provisions both — a pinned ZAP release and an Eclipse Temurin JRE — into `~/.obiguard-zap-agent/toolchain` the first time it starts. That's a ~335 MB download (about 460 MB unpacked), once; every run after that reuses it. If the host already has ZAP (and a Java 17+ runtime for it), those are used exactly as they are and nothing is downloaded.
- Outbound HTTPS access to your configured relay URL, and — only for that one-time provisioning step — to `github.com`, where both ZAP and Temurin publish their releases. Behind a proxy, set `HTTPS_PROXY`/`NO_PROXY` as usual; the agent honours them.
- Enough resources to run a ZAP active scan (a JVM-based process) for the duration of a scan — this varies with target size, budget a few hundred MB of memory and some CPU headroom.

Every download is pinned in [`internal/toolchain/toolchain.go`](internal/toolchain/toolchain.go) to an exact version, an exact URL, and the SHA-256 those bytes must hash to; anything that doesn't match is discarded rather than run. Nothing a job or the relay says can change what gets fetched.

## Running it

### Option A: the bundled Docker image (simplest)

This repo's own [Dockerfile](Dockerfile) layers the agent binary onto ZAP's official image, so ZAP and its JVM are already inside it — the agent finds them on `PATH` and downloads nothing. Published images are built by [this repo's own release workflow](.github/workflows/release.yml), from this source, for `linux/amd64` and `linux/arm64`.

```bash
docker run -d --name obiguard-zap-agent \
  -e AGENT_TOKEN=<token from the Attack Surface page in the Obiguard portal> \
  ghcr.io/obiguard/obiguard-zap-agent:1
```

Pin to whatever you're comfortable with: `:1` follows the major version, `:1.2` the minor, `:1.2.0` an exact release, and `ghcr.io/obiguard/obiguard-zap-agent@sha256:...` an exact set of bytes. For something running inside your network, pin at least the exact release, and verify it — see [Verifying what you run](#verifying-what-you-run).

No Docker socket, no privileged access — this container only ever talks outbound to Obiguard and to whatever target its scan plan names.

### Option B: the binary on its own

Nothing to install alongside it. On its first start the agent provisions its own ZAP and Java runtime, then runs every job with those.

```bash
export AGENT_TOKEN=<token from the Attack Surface page in the Obiguard portal>
./obiguard-zap-agent
```

The token is the only thing you have to supply — the agent talks to
Obiguard's hosted relay at `https://zap-agent.obiguard.ai` unless you set
`RELAY_URL` to point somewhere else. The relay it settled on is in the
startup log line, so you can always see which one a running agent is using.

To pay that one-time download up front — at install time, in an image build, or just to check the machine can reach the downloads before you enrol it — run it once with the `provision` subcommand, which needs no token:

```bash
./obiguard-zap-agent provision
```

Already have ZAP on the machine? Put its `zap.sh` on `PATH` (or point `ZAP_CMD` at it) and the agent will use that one and download nothing — it still needs a Java 17+ runtime, and will provision just the JRE if the host has none.

| Env var | Required | Default | Purpose |
|---|---|---|---|
| `RELAY_URL` | no | `https://zap-agent.obiguard.ai` | Where to poll for jobs and upload results. Set it only for a staging or self-hosted relay. |
| `AGENT_TOKEN` | yes | — | Per-org token from the portal's Attack Surface page. Treat it like a password. |
| `WORK_DIR` | no | `/tmp/obiguard-zap-agent` | Scratch space for one job's plan and report at a time. |
| `TOOLCHAIN_DIR` | no | `~/.obiguard-zap-agent/toolchain` | Where the ZAP and JRE the agent provisions are unpacked, and found again on later runs. Keep it on persistent storage, or the download repeats. |
| `ZAP_CMD` | no | — | An existing `zap.sh` to use instead. Set, it's used verbatim and no ZAP is ever downloaded; unset, the agent takes `zap.sh` from `PATH` if there is one and otherwise provisions its own. |
| `ZAP_AUTO_INSTALL` | no | `true` | Whether the agent may download what's missing. `false` turns a missing ZAP or Java into a startup error instead — for hosts that must never fetch anything at runtime. |
| `SCAN_TIMEOUT_SECONDS` | no | `1800` (30 min) | Hard ceiling on one scan run. |

Runs in the foreground and logs to stdout; wrap it with your process manager of choice (systemd, a container restart policy, etc.) for unattended operation.

## Verifying what you run

Every release is built by a public GitHub Actions run from the source in this repo, and signed with [Sigstore](https://www.sigstore.dev/) using that run's identity — there is no signing key to be stolen, and the signature names the workflow that produced the artifact.

Check the image signature before you deploy it:

```bash
cosign verify ghcr.io/obiguard/obiguard-zap-agent:1.2.0 \
  --certificate-identity-regexp '^https://github\.com/obiguard/obiguard-zap-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Check a downloaded binary's build provenance:

```bash
gh attestation verify ./obiguard-zap-agent_linux_amd64 --repo obiguard/obiguard-zap-agent
```

Each image also carries an SBOM and SLSA provenance, so you can see what is in it and which commit built it:

```bash
docker buildx imagetools inspect ghcr.io/obiguard/obiguard-zap-agent:1.2.0
```

To confirm what a running agent actually is:

```bash
obiguard-zap-agent version          # or: docker run --rm <image> version
```

## Releases and versioning

Releases follow [semantic versioning](https://semver.org/) and are tagged `vX.Y.Z`. The `AGENT_TOKEN` protocol this agent speaks to the relay is the compatibility surface a major version covers.

Development happens in a private repository; this repo receives one commit per release rather than the full development history. That's why `git log` here is a release list. See [CONTRIBUTING.md](CONTRIBUTING.md) if you want to send a change.

## Building from source

```bash
go build -o obiguard-zap-agent ./cmd/agent
```

A binary built this way reports its version as `dev` — release builds have the version, commit and build date stamped in at link time.

Minimal dependencies on purpose, so there's as little to audit as possible: Go's standard library plus one small YAML library (to point a scan plan's report output at this agent's own local scratch directory before running it).

## License

Apache 2.0 — see [LICENSE](LICENSE).
