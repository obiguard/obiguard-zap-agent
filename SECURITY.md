# Security model

This document explains, precisely, what this agent can do inside your network and how it handles the sensitive data that passes through it. Read this before you install it.

## Network reach

While running jobs, the agent makes exactly one kind of outbound connection: HTTPS to your configured `RELAY_URL`. The one exception is the first-run toolchain download described below, to `github.com`. It never opens a listening port and never accepts an inbound connection from anywhere, including from Obiguard.

Everything that happens inside your network — the actual scan traffic against your application — is initiated locally, by the ZAP process this agent runs, using your network's own outbound path. Obiguard's servers never connect directly into your network at any point; they only ever hand this agent a plan to execute and receive a report back.

## What the agent installs

ZAP is a Java application, and rather than make you install either, the agent provisions both the first time it starts — unless the host already has them, in which case it uses those and downloads nothing. What it can fetch is fixed at build time in [`internal/toolchain/toolchain.go`](internal/toolchain/toolchain.go):

- **ZAP** — the official cross-platform release, straight from `github.com/zaproxy/zaproxy`.
- **A Java runtime** — an Eclipse Temurin JRE, straight from `github.com/adoptium`.

Each is pinned to an exact version, an exact URL, and the SHA-256 its bytes must hash to. A download that hashes to anything else is deleted, not run. Nothing supplied at runtime — not a job, not a relay response, not an environment variable — can point either download somewhere else; the only things the environment controls are where the result is unpacked (`TOOLCHAIN_DIR`) and whether downloading is permitted at all (`ZAP_AUTO_INSTALL=false` turns it off, making a missing ZAP or Java a startup error instead). Archives are unpacked with entry paths and symlink targets confined to that directory.

If you would rather nothing be fetched at runtime, use this repo's Docker image (ZAP and its JVM are already in it), or install ZAP yourself and set `ZAP_CMD` — with `ZAP_AUTO_INSTALL=false` to make the requirement explicit.

## What a "job" contains

A job is a complete ZAP Automation Framework plan (`plan.yaml`). The plan is built entirely on Obiguard's side — this agent has no logic for choosing targets or constructing requests, so there is no way to make it scan something Obiguard didn't already tell it to.

**The plan contains a plaintext scan credential when the target requires authentication.** Obiguard's Attack Surface feature lets you attach a dedicated, low-privilege test account credential (never a real user's or admin's) to a protected target; that credential is decrypted on Obiguard's side to build the plan, transits to this agent over HTTPS, and is written to a local plan file for the duration of one scan run. If that's not an acceptable exposure for a given credential, don't attach one to a target routed through this agent.

## What's on disk, and for how long

For each job, the agent writes exactly two files to `WORK_DIR` (default `/tmp/obiguard-zap-agent`): the plan (which may contain a credential, as above) and the resulting `report.json`. Both live only inside a job-specific subdirectory, and that entire subdirectory — plan file included — is deleted immediately when the job finishes, whether it succeeded, failed, or timed out. Nothing is logged to disk beyond the agent's own stdout (job IDs and status, never plan or credential contents).

## What the agent will never do

- Accept a job from, or send results to, anything other than the exact `RELAY_URL` you configured.
- Run any command other than `<zap.sh> -cmd -autorun plan.yaml` against the plan it was handed, with that `zap.sh` being the one it resolved or provisioned at startup (see `internal/scan/runner.go`, the entire ZAP-related surface of this codebase) — no ad-hoc command execution of any other kind.
- Make a network connection outside of that one ZAP process's scan traffic, its own poll/report calls to the relay, and the pinned toolchain downloads above.
- Retain a job's plan or report after that job completes.

## Your `AGENT_TOKEN`

This is a bearer credential scoped to your organization — anyone who has it can queue results as your org and read whatever this agent submits. Treat it like any other API secret: don't commit it, don't log it, rotate it from the portal if you suspect it's been exposed.

## How releases are built, and how to check one

Everything published — the binaries on the GitHub release and the images on
GHCR — is built by a public GitHub Actions run from the source in this
repository. Nothing is built on a laptop and uploaded.

- **Signed with Sigstore, keylessly.** The signature is bound to the identity
  of the workflow run that produced the artifact, so there is no long-lived
  signing key anywhere to be stolen, and verification tells you *which
  workflow in which repository* built the thing you're holding.
- **SBOM and SLSA provenance** are attached to each image, so its contents
  and the commit it came from are inspectable without trusting a claim here.
- **The base image is pinned by digest**, not by a moving tag, so a rebuild
  cannot silently change what ZAP or JVM you receive.
- **The toolchain downloads are pinned by SHA-256**, as described above.

The exact `cosign verify`, `gh attestation verify` and
`docker buildx imagetools inspect` commands are in
[README.md](README.md#verifying-what-you-run). If you run this agent inside
a network you care about, run those before you deploy it.

Development happens in a private repository and this one receives a commit
per release, so its history is a release sequence rather than a
change-by-change log. Every published tree is the tree the release was built
from.

## Reporting a vulnerability

If you find a security issue in this agent, please report it privately rather than opening a public issue — contact your Obiguard representative or security@obiguard.com.
