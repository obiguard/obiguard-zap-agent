package config

import "testing"

func TestLoad_RequiresRelayURL(t *testing.T) {
	t.Setenv("RELAY_URL", "")
	t.Setenv("AGENT_TOKEN", "token")
	if _, err := Load(); err == nil {
		t.Fatal("expected an error when RELAY_URL is unset")
	}
}

func TestLoad_RequiresAgentToken(t *testing.T) {
	t.Setenv("RELAY_URL", "https://zap-agent.obiguard.ai")
	t.Setenv("AGENT_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected an error when AGENT_TOKEN is unset")
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("RELAY_URL", "https://zap-agent.obiguard.ai")
	t.Setenv("AGENT_TOKEN", "token")
	t.Setenv("WORK_DIR", "")
	t.Setenv("ZAP_CMD", "")
	t.Setenv("SCAN_TIMEOUT_SECONDS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WorkDir != "/tmp/obiguard-zap-agent" {
		t.Errorf("WorkDir = %q, want default", cfg.WorkDir)
	}
	if cfg.Toolchain.ZapCmd != "" {
		t.Errorf("Toolchain.ZapCmd = %q, want empty so the agent resolves ZAP itself", cfg.Toolchain.ZapCmd)
	}
	if !cfg.Toolchain.AutoInstall {
		t.Error("Toolchain.AutoInstall = false, want auto-install on by default")
	}
	if cfg.Toolchain.Dir == "" {
		t.Error("Toolchain.Dir is empty, want a default location to provision into")
	}
	if cfg.ScanTimeout.Minutes() != 30 {
		t.Errorf("ScanTimeout = %v, want 30m default", cfg.ScanTimeout)
	}
}

func TestLoad_InvalidScanTimeout(t *testing.T) {
	t.Setenv("RELAY_URL", "https://zap-agent.obiguard.ai")
	t.Setenv("AGENT_TOKEN", "token")
	t.Setenv("SCAN_TIMEOUT_SECONDS", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a non-numeric SCAN_TIMEOUT_SECONDS")
	}
}

func TestLoadToolchain_Overrides(t *testing.T) {
	t.Setenv("TOOLCHAIN_DIR", "/opt/zap-toolchain")
	t.Setenv("ZAP_CMD", "/usr/local/bin/zap.sh")
	t.Setenv("ZAP_AUTO_INSTALL", "false")

	cfg := LoadToolchain()
	if cfg.Dir != "/opt/zap-toolchain" {
		t.Errorf("Dir = %q, want the TOOLCHAIN_DIR value", cfg.Dir)
	}
	if cfg.ZapCmd != "/usr/local/bin/zap.sh" {
		t.Errorf("ZapCmd = %q, want the ZAP_CMD value", cfg.ZapCmd)
	}
	if cfg.AutoInstall {
		t.Error("AutoInstall = true, want ZAP_AUTO_INSTALL=false to turn it off")
	}
}

// An unparseable on/off switch falls back to the documented default rather
// than failing startup — the agent still runs, just with auto-install on.
func TestLoadToolchain_InvalidAutoInstall(t *testing.T) {
	t.Setenv("ZAP_AUTO_INSTALL", "sometimes")
	if !LoadToolchain().AutoInstall {
		t.Error("AutoInstall = false, want the default to survive an unparseable value")
	}
}
