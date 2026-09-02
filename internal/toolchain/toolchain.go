// Package toolchain makes this agent self-contained: it provisions the two
// things a scan actually needs — ZAP itself, and a Java runtime to run it
// on — into a directory the agent owns, so an operator installs nothing
// but this one binary.
//
// Everything it can download is pinned here at build time: an exact
// version, an exact URL, and the SHA-256 those bytes must hash to. No job,
// no relay response, and no environment variable can redirect a download
// somewhere else — the only thing the environment controls is where the
// result is written, and whether downloading is allowed at all.
//
// An already-installed ZAP always wins: ZAP_CMD, then zap.sh on PATH, then
// whatever this package provisioned previously, and only then a download.
// Same for Java — a usable JAVA_HOME or java on PATH is used as-is.
package toolchain

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ZAP's own cross-platform distribution: the same build, and the same
// bundled add-ons a scan plan relies on (automation, replacer, reports,
// ascanrules), that this repo's Docker image gets from zaproxy/zap-stable.
// It carries no JRE of its own, which is what the Temurin download below
// is for.
const (
	zapVersion       = "2.17.0"
	zapArchiveURL    = "https://github.com/zaproxy/zaproxy/releases/download/v" + zapVersion + "/ZAP_" + zapVersion + "_Crossplatform.zip"
	zapArchiveSHA256 = "94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0"
)

// ZAP 2.17 refuses to start on anything older than Java 17; Temurin 21 is
// the current LTS and what the agent installs when the host has no
// suitable Java of its own.
const (
	minJavaMajor = 17
	jreVersion   = "21.0.12.1+1"
)

// Eclipse Temurin JREs, keyed by GOOS/GOARCH. A platform that isn't here
// can still run the agent — it just has to bring its own Java.
var jreArchives = map[string]archive{
	"linux/amd64": {
		url:    "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz",
		sha256: "2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500",
	},
	"linux/arm64": {
		url:    "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_aarch64_linux_hotspot_21.0.12.1_1.tar.gz",
		sha256: "14be1f35ebdbd1f6e8d57eb911a3ffb74d6d9aa255abc5daf2b1302002cf2cf2",
	},
	"darwin/amd64": {
		url:    "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_mac_hotspot_21.0.12.1_1.tar.gz",
		sha256: "6717ec641fd9ce0bb209ca083ee23b42202ac68cb6fcc5753496e0e4a0f41989",
	},
	"darwin/arm64": {
		url:    "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_aarch64_mac_hotspot_21.0.12.1_1.tar.gz",
		sha256: "dec50fc6f9fcd4fe3ae8cabf5a5fa68f6afc48841f7698e468e9aa5d54beed84",
	},
}

// How long `java -version` gets to answer before that candidate is treated
// as unusable — a wrapper that hangs shouldn't hang agent startup.
const javaProbeTimeout = 30 * time.Second

type Options struct {
	// Dir is where downloaded tools are unpacked and looked for on later
	// runs. Persisting it across restarts is the difference between a
	// one-time download and one per restart.
	Dir string
	// ZapCmd is an explicit ZAP_CMD, empty if unset. When set it's used
	// verbatim and nothing is ever downloaded for ZAP — an operator who
	// named a specific binary gets that binary or an error, not a
	// second, silently-provisioned copy.
	ZapCmd string
	// AutoInstall permits downloading what's missing. Turn it off on a
	// host that must never fetch anything at runtime (this repo's own
	// Docker image already has both tools baked in, so it does).
	AutoInstall bool
}

// Toolchain is everything scan.Run needs to start ZAP: what to execute,
// and the environment to execute it in.
type Toolchain struct {
	// ZapCmd is the resolved zap.sh — an absolute path whenever this
	// package found or installed it, rather than something PATH-dependent.
	ZapCmd string
	// Env is the agent's own environment with JAVA_HOME and PATH pointed
	// at the Java runtime ZAP should use. zap.sh reads JAVA_HOME on Linux
	// and falls back to PATH everywhere else, so both are set.
	Env []string
}

// Ensure resolves (and, if permitted and necessary, downloads) a runnable
// ZAP. It is idempotent and cheap once everything is in place: the
// expensive path only runs when something is genuinely missing, so callers
// can call it again per job rather than only at startup.
func Ensure(ctx context.Context, logger *slog.Logger, opts Options) (Toolchain, error) {
	// ZAP first: an installed one may ship a Java runtime of its own, and
	// that's the one it would have used had a person started it by hand.
	zapCmd, err := ensureZap(ctx, logger, opts)
	if err != nil {
		return Toolchain{}, err
	}
	javaHome, err := ensureJava(ctx, logger, opts, zapCmd)
	if err != nil {
		return Toolchain{}, err
	}
	return Toolchain{ZapCmd: zapCmd, Env: childEnv(javaHome)}, nil
}

func ensureZap(ctx context.Context, logger *slog.Logger, opts Options) (string, error) {
	if opts.ZapCmd != "" {
		path, err := resolveCommand(opts.ZapCmd)
		if err != nil {
			return "", fmt.Errorf("ZAP_CMD is set to %q but that isn't runnable: %w", opts.ZapCmd, err)
		}
		return path, nil
	}
	if path, err := exec.LookPath("zap.sh"); err == nil {
		logger.Info("using the ZAP already installed on this host", "zapCmd", path)
		return path, nil
	}

	installed := filepath.Join(opts.Dir, "zap-"+zapVersion)
	script := filepath.Join(installed, "zap.sh")
	if fileExists(script) {
		return script, ensureExecutable(script)
	}
	if !opts.AutoInstall {
		return "", fmt.Errorf("no zap.sh on PATH, nothing provisioned in %s, and auto-install is off "+
			"(ZAP_AUTO_INSTALL) — either turn auto-install back on or point ZAP_CMD at an existing zap.sh", opts.Dir)
	}

	logger.Info("provisioning ZAP — one time, nothing else to install",
		"version", zapVersion, "dir", installed)
	if err := fetchAndExtract(ctx, logger, archive{zapArchiveURL, zapArchiveSHA256}, installed); err != nil {
		return "", fmt.Errorf("provisioning ZAP %s: %w", zapVersion, err)
	}
	if !fileExists(script) {
		return "", fmt.Errorf("the ZAP %s archive unpacked without a zap.sh at %s", zapVersion, script)
	}
	if err := ensureExecutable(script); err != nil {
		return "", err
	}
	logger.Info("ZAP provisioned", "zapCmd", script)
	return script, nil
}

func ensureJava(ctx context.Context, logger *slog.Logger, opts Options, zapCmd string) (string, error) {
	if home := findJava(ctx, logger, zapCmd); home != "" {
		return home, nil
	}

	installed := filepath.Join(opts.Dir, "jre-"+jreVersion)
	if home, ok := javaHomeIn(installed); ok {
		return home, nil
	}

	dist, ok := jreArchives[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("ZAP needs Java %d or newer and none was found; this agent has no bundled "+
			"Java for %s/%s, so install one and set JAVA_HOME", minJavaMajor, runtime.GOOS, runtime.GOARCH)
	}
	if !opts.AutoInstall {
		return "", fmt.Errorf("ZAP needs Java %d or newer, none was found, and auto-install is off "+
			"(ZAP_AUTO_INSTALL) — install a JRE and set JAVA_HOME, or turn auto-install back on", minJavaMajor)
	}

	logger.Info("provisioning a Java runtime for ZAP — one time, nothing else to install",
		"version", jreVersion, "dir", installed)
	if err := fetchAndExtract(ctx, logger, dist, installed); err != nil {
		return "", fmt.Errorf("provisioning Temurin %s: %w", jreVersion, err)
	}
	home, ok := javaHomeIn(installed)
	if !ok {
		return "", fmt.Errorf("the Temurin %s archive unpacked without a bin/java under %s", jreVersion, installed)
	}
	logger.Info("Java runtime provisioned", "javaHome", home)
	return home, nil
}

// findJava returns the JAVA_HOME of an existing Java new enough for ZAP,
// or "" if there isn't one. Candidates are probed by actually running
// them: macOS ships a /usr/bin/java stub that exists, is executable, and
// does nothing but tell you Java isn't installed — so presence on PATH
// proves nothing, and only a successful -version does.
func findJava(ctx context.Context, logger *slog.Logger, zapCmd string) string {
	var candidates []string
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		candidates = append(candidates, filepath.Join(javaHome, "bin", "java"))
	}
	if path, err := exec.LookPath("java"); err == nil {
		candidates = append(candidates, path)
	}
	candidates = append(candidates, bundledJava(zapCmd)...)

	for _, candidate := range candidates {
		major, err := javaMajorVersion(ctx, candidate)
		if err != nil {
			logger.Debug("ignoring an unusable java", "path", candidate, "error", err)
			continue
		}
		if major < minJavaMajor {
			logger.Info("ignoring a java that's too old for ZAP",
				"path", candidate, "major", major, "minimum", minJavaMajor)
			continue
		}
		// Resolve the symlink first: package managers put java on PATH as
		// a link, and JAVA_HOME has to be the real installation's root
		// (…/bin/java minus /bin/java), not the link's directory.
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		home := filepath.Dir(filepath.Dir(resolved))
		logger.Info("using the Java already installed on this host", "javaHome", home, "major", major)
		return home
	}
	return ""
}

// bundledJava finds the runtime an installed ZAP carries with it, so a
// host where ZAP was installed from a platform package (the macOS app
// bundle keeps a JRE in ../PlugIns) doesn't get a second, redundant one
// downloaded next to it. This is the same location zap.sh itself looks in.
func bundledJava(zapCmd string) []string {
	if zapCmd == "" {
		return nil
	}
	// Resolved, because zap.sh is typically reached through a symlink
	// (/opt/homebrew/bin/zap.sh) and the bundle is relative to the real one.
	resolved, err := filepath.EvalSymlinks(zapCmd)
	if err != nil {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(resolved), "..", "PlugIns", "jre*", "Contents", "Home", "bin", "java"))
	if err != nil {
		return nil
	}
	return matches
}

// javaHomeIn finds the JAVA_HOME inside an unpacked Temurin JRE: bin/java
// on Linux, Contents/Home/bin/java in the macOS bundle layout.
func javaHomeIn(dir string) (string, bool) {
	for _, home := range []string{dir, filepath.Join(dir, "Contents", "Home")} {
		if fileExists(filepath.Join(home, "bin", "java")) {
			return home, true
		}
	}
	return "", false
}

func javaMajorVersion(ctx context.Context, javaPath string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, javaProbeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, javaPath, "-version").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("%s -version failed: %w (%s)", javaPath, err, strings.TrimSpace(string(out)))
	}
	return parseJavaMajor(string(out))
}

// parseJavaMajor pulls the major version out of `java -version` output,
// whose first line looks like `openjdk version "21.0.12" 2026-07-15` —
// or, on a Java 8 that's far too old for ZAP, `"1.8.0_412"`.
func parseJavaMajor(output string) (int, error) {
	start := strings.Index(output, `"`)
	if start < 0 {
		return 0, fmt.Errorf("no version string in %q", strings.TrimSpace(output))
	}
	rest := output[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return 0, fmt.Errorf("no version string in %q", strings.TrimSpace(output))
	}
	version := rest[:end]

	parts := strings.FieldsFunc(version, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
	if len(parts) == 0 {
		return 0, fmt.Errorf("unparseable Java version %q", version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("unparseable Java version %q", version)
	}
	// Pre-9 versions are written 1.8.0_x — the number that matters is the
	// second one.
	if major == 1 && len(parts) > 1 {
		major, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, fmt.Errorf("unparseable Java version %q", version)
		}
	}
	return major, nil
}

// childEnv is the agent's environment with Java pointed at javaHome.
// Replacing rather than appending, so a stale JAVA_HOME inherited from the
// host can't win over the runtime this package just resolved.
func childEnv(javaHome string) []string {
	binDir := filepath.Join(javaHome, "bin")
	path := binDir
	if existing := os.Getenv("PATH"); existing != "" {
		path += string(os.PathListSeparator) + existing
	}

	env := []string{"JAVA_HOME=" + javaHome, "PATH=" + path}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "JAVA_HOME=") || strings.HasPrefix(entry, "PATH=") {
			continue
		}
		env = append(env, entry)
	}
	return env
}

// resolveCommand turns an operator-supplied command into a path, whether
// they gave a bare name to find on PATH or a full path to a script.
func resolveCommand(cmd string) (string, error) {
	if !strings.ContainsRune(cmd, os.PathSeparator) {
		return exec.LookPath(cmd)
	}
	abs, err := filepath.Abs(cmd)
	if err != nil {
		return "", err
	}
	if !fileExists(abs) {
		return "", fmt.Errorf("no such file: %s", abs)
	}
	return abs, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// ensureExecutable fixes up a zap.sh that came out of the archive without
// its executable bit — which is what happens with a zip built on a system
// that records no Unix modes.
func ensureExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o100 != 0 {
		return nil
	}
	if err := os.Chmod(path, info.Mode().Perm()|0o755); err != nil {
		return fmt.Errorf("making %s executable: %w", path, err)
	}
	return nil
}
