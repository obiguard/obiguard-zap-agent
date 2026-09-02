package toolchain

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// serve publishes body at a URL ending in name (the extractor picks its
// unpacker off that suffix) and returns the URL plus the body's digest.
func serve(t *testing.T, name string, body []byte) (string, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	return srv.URL + "/" + name, hex.EncodeToString(sum[:])
}

// zipArchive builds a zip shaped like ZAP's own: everything under one
// top-level directory, with an executable zap.sh at its root.
func zipArchive(t *testing.T, entries map[string]os.FileMode) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, mode := range entries {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(mode)
		f, err := w.CreateHeader(header)
		if err != nil {
			t.Fatalf("building test zip: %v", err)
		}
		if _, err := f.Write([]byte("contents of " + name)); err != nil {
			t.Fatalf("building test zip: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("building test zip: %v", err)
	}
	return buf.Bytes()
}

func TestFetchAndExtract_Zip(t *testing.T) {
	body := zipArchive(t, map[string]os.FileMode{
		"ZAP_9.9.9/zap.sh":              0o755,
		"ZAP_9.9.9/lib/zap-9.9.9.jar":   0o644,
		"ZAP_9.9.9/plugin/reports.zap":  0o644,
		"ZAP_9.9.9/plugin/automation.z": 0o644,
	})
	url, sum := serve(t, "ZAP_9.9.9_Crossplatform.zip", body)

	dest := filepath.Join(t.TempDir(), "zap-9.9.9")
	if err := fetchAndExtract(context.Background(), testLogger(), archive{url, sum}, dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The archive's single top-level directory is stripped: zap.sh sits
	// directly in dest, which is where ensureZap looks for it.
	script := filepath.Join(dest, "zap.sh")
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("zap.sh not where it should be: %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("zap.sh came out non-executable (mode %v)", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dest, "plugin", "reports.zap")); err != nil {
		t.Errorf("add-ons missing from the extracted distribution: %v", err)
	}
}

func TestFetchAndExtract_RejectsBadChecksum(t *testing.T) {
	body := zipArchive(t, map[string]os.FileMode{"ZAP_9.9.9/zap.sh": 0o755})
	url, _ := serve(t, "ZAP_9.9.9_Crossplatform.zip", body)

	dir := t.TempDir()
	dest := filepath.Join(dir, "zap-9.9.9")
	err := fetchAndExtract(context.Background(), testLogger(), archive{
		url:    url,
		sha256: strings.Repeat("0", 64),
	}, dest)
	if err == nil {
		t.Fatal("expected an error when the download doesn't match its pinned digest")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error should name the checksum as the problem, got: %v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("a failed download must not leave anything at the destination")
	}
	// Nor any temporary file or staging directory next to it.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("staging leftovers: %v", entries)
	}
}

func TestFetchAndExtract_RejectsZipSlip(t *testing.T) {
	body := zipArchive(t, map[string]os.FileMode{"../escaped.sh": 0o755})
	url, sum := serve(t, "evil.zip", body)

	dir := t.TempDir()
	err := fetchAndExtract(context.Background(), testLogger(), archive{url, sum}, filepath.Join(dir, "zap"))
	if err == nil {
		t.Fatal("expected an error for an entry that escapes the destination")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "escaped.sh")); statErr == nil {
		t.Fatal("the archive wrote outside its destination directory")
	}
}

// tarGzArchive builds a JRE-shaped tarball: one top-level directory, a
// bin/java inside it, and a relative symlink of the kind the macOS Temurin
// bundle carries.
func tarGzArchive(t *testing.T, symlinkTarget string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	write := func(hdr *tar.Header, body string) {
		t.Helper()
		hdr.Size = int64(len(body))
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("building test tarball: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("building test tarball: %v", err)
		}
	}

	write(&tar.Header{Typeflag: tar.TypeDir, Name: "jdk-21-jre/", Mode: 0o755}, "")
	write(&tar.Header{Typeflag: tar.TypeDir, Name: "jdk-21-jre/bin/", Mode: 0o755}, "")
	write(&tar.Header{Typeflag: tar.TypeReg, Name: "jdk-21-jre/bin/java", Mode: 0o755}, "#!/bin/sh\n")
	write(&tar.Header{Typeflag: tar.TypeSymlink, Name: "jdk-21-jre/bin/java-link", Linkname: symlinkTarget}, "")

	if err := tw.Close(); err != nil {
		t.Fatalf("building test tarball: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("building test tarball: %v", err)
	}
	return buf.Bytes()
}

func TestFetchAndExtract_TarGz(t *testing.T) {
	body := tarGzArchive(t, "java")
	url, sum := serve(t, "OpenJDK21U-jre.tar.gz", body)

	dest := filepath.Join(t.TempDir(), "jre-21")
	if err := fetchAndExtract(context.Background(), testLogger(), archive{url, sum}, dest); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	home, ok := javaHomeIn(dest)
	if !ok {
		t.Fatalf("no java found under %s after extraction", dest)
	}
	if home != dest {
		t.Errorf("javaHome = %q, want the extraction root %q", home, dest)
	}
	if target, err := os.Readlink(filepath.Join(dest, "bin", "java-link")); err != nil || target != "java" {
		t.Errorf("symlink not preserved: target=%q err=%v", target, err)
	}
}

// A symlink is only as safe as where it resolves to — an archive that
// links out of its own directory is refused the same way a traversing
// entry name is.
func TestFetchAndExtract_RejectsEscapingSymlink(t *testing.T) {
	body := tarGzArchive(t, "../../../../etc/passwd")
	url, sum := serve(t, "evil.tar.gz", body)

	dest := filepath.Join(t.TempDir(), "jre-21")
	err := fetchAndExtract(context.Background(), testLogger(), archive{url, sum}, dest)
	if err == nil {
		t.Fatal("expected an error for a symlink pointing outside the destination")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Errorf("error should say the link escapes, got: %v", err)
	}
}
