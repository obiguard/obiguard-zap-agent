# Builds the agent binary, then layers it onto ZAP's own official image —
# ZAP's Dockerfile already gives us a working `zap.sh` on PATH plus its
# bundled JRE, so there's no reason to reconstruct that ourselves. The
# result is one image with everything this agent needs: no sibling
# container, no Docker socket, nothing else to run alongside it.

# --platform=$BUILDPLATFORM keeps this stage on the builder's native
# architecture and cross-compiles instead: Go does that for free, whereas
# emulating the toolchain under QEMU to build the arm64 image costs minutes
# for no benefit. TARGETOS/TARGETARCH are supplied by buildx per platform.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Stamped into the binary so `obiguard-zap-agent version` and the startup
# log line identify the exact build. Defaults match what a plain `go build`
# produces, so an ad-hoc local image doesn't claim to be a release.
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/obiguard-zap-agent ./cmd/agent

# ZAP and the JVM it runs on are both already here, so the agent finds
# them on PATH at startup and provisions nothing — the toolchain download
# it does on a bare host never happens inside this image.
#
# Pinned by digest, not by `:latest`. This is a security tool that customers
# run inside their own networks: what ships has to be a decision someone
# made, not whatever the tag happened to point at when CI ran. This digest
# is the multi-arch index, so it still resolves per-platform. Bump it
# deliberately — Dependabot watches it via .github/dependabot.yml.
FROM zaproxy/zap-stable:latest@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
USER root
COPY --from=build /out/obiguard-zap-agent /usr/local/bin/obiguard-zap-agent
# ZAP's own image already runs as a non-root "zap" user with a writable
# home — reuse it rather than adding a new one, and drop back to it before
# running our binary (the agent itself needs no elevated privilege).
USER zap
ENV WORK_DIR=/home/zap/obiguard-zap-agent

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="obiguard-zap-agent" \
      org.opencontainers.image.description="Runs an OWASP ZAP scan inside your own network on Obiguard's behalf." \
      org.opencontainers.image.source="https://github.com/obiguard/obiguard-zap-agent" \
      org.opencontainers.image.documentation="https://github.com/obiguard/obiguard-zap-agent/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Obiguard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENTRYPOINT ["/usr/local/bin/obiguard-zap-agent"]
