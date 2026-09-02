// Package config loads the agent's settings from environment variables. No
// config file, no flags beyond what env vars cover — the whole point of this
// binary is to be something a customer can run with one command line.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DefaultRelayURL is Obiguard's hosted relay — where all but a handful of
// installs should point. It is a default rather than a required setting so
// the common case is `AGENT_TOKEN=... obiguard-zap-agent` and nothing else;
// RELAY_URL still overrides it for staging and self-hosted relays.
const DefaultRelayURL = "https://zap-agent.obiguard.ai"

type Config struct {
	// Where the agent polls for jobs and uploads results — Obiguard's
	// hosted relay. Defaults to DefaultRelayURL; RELAY_URL overrides it.
	// Never a customer's own infrastructure; this agent only ever dials out
	// to Obiguard.
	RelayURL string
	// Per-org bearer token, issued once from the portal at enrollment time.
	AgentToken string
	// Scratch space for one job's plan.yaml (contains a plaintext scan
	// credential) and the resulting report.json. Deleted after every job,
	// win or lose — see cmd/agent/main.go.
	WorkDir string
	// Where ZAP itself comes from — see ToolchainConfig.
	Toolchain ToolchainConfig
	// Hard ceiling on one scan run, mirroring obiguard-zap-service's own
	// MAX_SCAN_DURATION_MS — a stuck ZAP process shouldn't hold this
	// agent's one worker slot forever.
	ScanTimeout time.Duration
}

// ToolchainConfig covers where ZAP and its Java runtime come from. The
// defaults are deliberately zero-setup: with none of these set, the agent
// uses whatever ZAP is already installed, and downloads a pinned one into
// Dir if there isn't one — so an operator installs nothing but this binary.
type ToolchainConfig struct {
	// Where a provisioned ZAP and JRE are unpacked and found again on
	// later runs. Persisting across restarts is what keeps the download a
	// one-time cost.
	Dir string
	// An explicit zap.sh, when the operator wants a specific one. Set,
	// it's used verbatim and nothing is downloaded for ZAP; unset, the
	// agent looks for zap.sh on PATH first and only then provisions its
	// own.
	ZapCmd string
	// Whether the agent may download what's missing. Off makes a missing
	// ZAP or Java a hard startup error instead — for hosts that must never
	// fetch anything at runtime, and for this repo's Docker image, where
	// both are already baked in.
	AutoInstall bool
}

func Load() (Config, error) {
	relayURL := os.Getenv("RELAY_URL")
	if relayURL == "" {
		relayURL = DefaultRelayURL
	}
	token := os.Getenv("AGENT_TOKEN")
	if token == "" {
		return Config{}, fmt.Errorf("AGENT_TOKEN is required — get one from the Attack Surface page in the Obiguard portal")
	}

	workDir := os.Getenv("WORK_DIR")
	if workDir == "" {
		workDir = "/tmp/obiguard-zap-agent"
	}

	scanTimeout := 30 * time.Minute
	if raw := os.Getenv("SCAN_TIMEOUT_SECONDS"); raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("SCAN_TIMEOUT_SECONDS must be a number: %w", err)
		}
		scanTimeout = time.Duration(secs) * time.Second
	}

	return Config{
		RelayURL:    relayURL,
		AgentToken:  token,
		WorkDir:     workDir,
		Toolchain:   LoadToolchain(),
		ScanTimeout: scanTimeout,
	}, nil
}

// LoadToolchain reads just the ZAP-provisioning settings, without the relay
// credentials the agent proper needs — so `obiguard-zap-agent provision`
// can download the toolchain ahead of enrollment, at image-build time or on
// a machine that doesn't have a token yet.
func LoadToolchain() ToolchainConfig {
	dir := os.Getenv("TOOLCHAIN_DIR")
	if dir == "" {
		dir = defaultToolchainDir()
	}
	return ToolchainConfig{
		Dir:         dir,
		ZapCmd:      os.Getenv("ZAP_CMD"),
		AutoInstall: boolEnv("ZAP_AUTO_INSTALL", true),
	}
}

// defaultToolchainDir prefers the user's home directory over WorkDir: the
// toolchain is a few hundred MB that should survive a reboot, and WorkDir
// defaults to /tmp, which on plenty of hosts does not.
func defaultToolchainDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".obiguard-zap-agent", "toolchain")
	}
	return filepath.Join(os.TempDir(), "obiguard-zap-agent", "toolchain")
}

// boolEnv treats anything unparseable as the default rather than failing
// startup — a typo in an optional on/off switch shouldn't stop an agent
// from running, and the value it lands on is the documented one.
func boolEnv(name string, def bool) bool {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return value
}
