package toolchain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseJavaMajor(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   int
		wantOK bool
	}{
		{"current LTS", `openjdk version "21.0.12" 2026-07-15` + "\n", 21, true},
		{"ZAP's minimum", `openjdk version "17.0.17" 2025-10-21` + "\n", 17, true},
		{"early access", `openjdk version "24-ea" 2026-03-17` + "\n", 24, true},
		{"pre-9 numbering", `java version "1.8.0_412"` + "\n", 8, true},
		{"no version at all", "command not found\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseJavaMajor(c.output)
			if c.wantOK && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.wantOK {
				if err == nil {
					t.Fatalf("expected an error, got major %d", got)
				}
				return
			}
			if got != c.want {
				t.Errorf("major = %d, want %d", got, c.want)
			}
		})
	}
}

// fakeJava puts a java on PATH that reports the given version string, and
// isolates PATH to just that — the machine running these tests may well
// have a real java and a real zap.sh, and neither should decide the
// outcome here.
func fakeJava(t *testing.T, version string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "jdk")
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho 'openjdk version \"" + version + "\" 2026-07-15' 1>&2\n"
	if err := os.WriteFile(filepath.Join(binDir, "java"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("JAVA_HOME", "")

	// Resolved, because that's what findJava reports: on macOS a temp dir
	// under /var/folders is really /private/var/folders, and JAVA_HOME has
	// to be the real installation root.
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestEnsure_UsesExplicitZapCmd(t *testing.T) {
	javaHome := fakeJava(t, "21.0.12")

	dir := t.TempDir()
	zapPath := filepath.Join(dir, "my-zap.sh")
	if err := os.WriteFile(zapPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// AutoInstall is on, and yet nothing is downloaded: an operator who
	// named a zap.sh gets that one.
	tc, err := Ensure(context.Background(), testLogger(), Options{
		Dir:         filepath.Join(dir, "toolchain"),
		ZapCmd:      zapPath,
		AutoInstall: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.ZapCmd != zapPath {
		t.Errorf("ZapCmd = %q, want the explicitly configured %q", tc.ZapCmd, zapPath)
	}
	if !hasEnv(tc.Env, "JAVA_HOME="+javaHome) {
		t.Errorf("JAVA_HOME not pointed at the resolved runtime %q: %v", javaHome, tc.Env)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "toolchain")); !os.IsNotExist(statErr) {
		t.Error("nothing should have been provisioned when ZAP_CMD names a working zap.sh")
	}
}

func TestEnsure_ExplicitZapCmdThatIsntThere(t *testing.T) {
	fakeJava(t, "21.0.12")

	_, err := Ensure(context.Background(), testLogger(), Options{
		Dir:         t.TempDir(),
		ZapCmd:      filepath.Join(t.TempDir(), "nope", "zap.sh"),
		AutoInstall: true,
	})
	if err == nil {
		t.Fatal("expected an error rather than a silently downloaded second copy")
	}
	if !strings.Contains(err.Error(), "ZAP_CMD") {
		t.Errorf("error should point at ZAP_CMD, got: %v", err)
	}
}

// A previously provisioned toolchain is reused as-is: the download is a
// one-time cost, not a per-restart one.
func TestEnsure_ReusesProvisionedZap(t *testing.T) {
	fakeJava(t, "21.0.12")

	dir := t.TempDir()
	installed := filepath.Join(dir, "zap-"+zapVersion)
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(installed, "zap.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// AutoInstall off proves nothing was downloaded to get here.
	tc, err := Ensure(context.Background(), testLogger(), Options{Dir: dir, AutoInstall: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.ZapCmd != script {
		t.Errorf("ZapCmd = %q, want the already-provisioned %q", tc.ZapCmd, script)
	}
	info, err := os.Stat(script)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Error("a non-executable zap.sh should have been made executable")
	}
}

func TestEnsure_NothingAvailableAndAutoInstallOff(t *testing.T) {
	fakeJava(t, "21.0.12")

	_, err := Ensure(context.Background(), testLogger(), Options{Dir: t.TempDir(), AutoInstall: false})
	if err == nil {
		t.Fatal("expected an error when there's no ZAP and downloading is off")
	}
	if !strings.Contains(err.Error(), "ZAP_AUTO_INSTALL") {
		t.Errorf("error should name the switch that turns downloading back on, got: %v", err)
	}
}

// The macOS /usr/bin/java stub is on PATH, is executable, and is not a
// Java — so is a genuinely installed Java that predates ZAP's minimum.
// Neither may be accepted, and with downloading off that's an error rather
// than a scan that fails later inside zap.sh.
func TestEnsure_RejectsUnusableJava(t *testing.T) {
	t.Run("too old", func(t *testing.T) {
		fakeJava(t, "1.8.0_412")
		_, err := Ensure(context.Background(), testLogger(), Options{Dir: t.TempDir(), AutoInstall: false})
		if err == nil || !strings.Contains(err.Error(), "Java") {
			t.Fatalf("expected a Java-related error, got: %v", err)
		}
	})

	t.Run("not really there", func(t *testing.T) {
		binDir := t.TempDir()
		stub := "#!/bin/sh\necho 'Unable to locate a Java Runtime.' 1>&2\nexit 1\n"
		if err := os.WriteFile(filepath.Join(binDir, "java"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", binDir)
		t.Setenv("JAVA_HOME", "")

		_, err := Ensure(context.Background(), testLogger(), Options{Dir: t.TempDir(), AutoInstall: false})
		if err == nil || !strings.Contains(err.Error(), "Java") {
			t.Fatalf("expected a Java-related error, got: %v", err)
		}
	})
}

func TestChildEnv_ReplacesInheritedJava(t *testing.T) {
	t.Setenv("JAVA_HOME", "/some/stale/jdk")
	t.Setenv("PATH", "/usr/bin")

	env := childEnv("/opt/jre")

	if !hasEnv(env, "JAVA_HOME=/opt/jre") {
		t.Errorf("stale JAVA_HOME survived: %v", env)
	}
	if count := countPrefix(env, "JAVA_HOME="); count != 1 {
		t.Errorf("JAVA_HOME appears %d times, want exactly one", count)
	}
	wantPath := "PATH=/opt/jre/bin" + string(os.PathListSeparator) + "/usr/bin"
	if !hasEnv(env, wantPath) {
		t.Errorf("PATH not prefixed with the resolved runtime: %v", env)
	}
	if count := countPrefix(env, "PATH="); count != 1 {
		t.Errorf("PATH appears %d times, want exactly one", count)
	}
}

func hasEnv(env []string, entry string) bool {
	for _, e := range env {
		if e == entry {
			return true
		}
	}
	return false
}

func countPrefix(env []string, prefix string) int {
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// A ZAP installed from a platform package brings its own JRE (the macOS
// app bundle keeps one in ../PlugIns). That runtime — the one zap.sh
// itself would pick — is used rather than downloading a second copy.
func TestEnsure_UsesTheJavaBundledWithAnInstalledZap(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "ZAP.app", "Contents")
	zapDir := filepath.Join(appDir, "Java")
	bundledHome := filepath.Join(appDir, "PlugIns", "jre-21-jre", "Contents", "Home")
	if err := os.MkdirAll(zapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundledHome, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	zapPath := filepath.Join(zapDir, "zap.sh")
	if err := os.WriteFile(zapPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	java := "#!/bin/sh\necho 'openjdk version \"21.0.12\" 2026-07-15' 1>&2\n"
	if err := os.WriteFile(filepath.Join(bundledHome, "bin", "java"), []byte(java), 0o755); err != nil {
		t.Fatal(err)
	}

	// Nothing usable on PATH: no java of the host's own, and the ZAP is
	// reached the way a package manager exposes it — by symlink.
	linkDir := t.TempDir()
	if err := os.Symlink(zapPath, filepath.Join(linkDir, "zap.sh")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", linkDir)
	t.Setenv("JAVA_HOME", "")

	// AutoInstall off: reaching a usable toolchain here proves nothing was
	// downloaded to do it.
	tc, err := Ensure(context.Background(), testLogger(), Options{Dir: t.TempDir(), AutoInstall: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantHome, err := filepath.EvalSymlinks(bundledHome)
	if err != nil {
		t.Fatal(err)
	}
	if !hasEnv(tc.Env, "JAVA_HOME="+wantHome) {
		t.Errorf("JAVA_HOME not pointed at ZAP's own bundled runtime %q: %v", wantHome, tc.Env)
	}
}
