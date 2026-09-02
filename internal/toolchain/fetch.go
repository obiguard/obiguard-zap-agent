package toolchain

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// How long a single toolchain download gets before it's abandoned. Generous
// on purpose — this is a few hundred MB, once, possibly over a slow
// corporate link — but not unbounded, so a black-holed connection doesn't
// leave the agent hanging forever instead of reporting a job failure.
const downloadTimeout = 30 * time.Minute

// How much has to arrive before the next progress line. Frequent enough
// that an operator watching stdout can see it moving, rare enough that an
// unattended agent's logs don't fill up with it.
const progressEvery = 50 << 20 // 50 MiB

// archive is one pinned download: an exact URL and the SHA-256 it must
// hash to. Nothing at runtime — not a job, not the relay, not an env var —
// can point either of these somewhere else; they're compiled in.
type archive struct {
	url    string
	sha256 string
}

// fetchAndExtract downloads a, verifies it against its recorded digest,
// unpacks it, and puts the result at destDir — all via a staging directory
// alongside destDir so an interrupted run can never leave a half-extracted
// toolchain behind that a later run would mistake for a usable one. The
// archive's single top-level directory is stripped, so destDir ends up
// holding zap.sh (or bin/java) directly rather than one more level down.
func fetchAndExtract(ctx context.Context, logger *slog.Logger, a archive, destDir string) error {
	parent := filepath.Dir(destDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", parent, err)
	}

	tmpArchive, err := os.CreateTemp(parent, ".download-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file: %w", err)
	}
	defer os.Remove(tmpArchive.Name())
	defer tmpArchive.Close()

	if err := download(ctx, logger, a, tmpArchive); err != nil {
		return err
	}

	staging, err := os.MkdirTemp(parent, ".extract-*")
	if err != nil {
		return fmt.Errorf("creating a staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	switch {
	case strings.HasSuffix(a.url, ".zip"):
		err = extractZip(tmpArchive.Name(), staging)
	case strings.HasSuffix(a.url, ".tar.gz"):
		err = extractTarGz(tmpArchive.Name(), staging)
	default:
		err = fmt.Errorf("no extractor for %s", a.url)
	}
	if err != nil {
		return err
	}

	root, err := stripSingleRoot(staging)
	if err != nil {
		return err
	}
	// Nothing else writes here, but a previous run killed between its own
	// rename and this one would have left the destination occupied.
	if err := os.RemoveAll(destDir); err != nil {
		return fmt.Errorf("clearing %s: %w", destDir, err)
	}
	if err := os.Rename(root, destDir); err != nil {
		return fmt.Errorf("moving the extracted files into place: %w", err)
	}
	return nil
}

// download streams a's URL into dst, hashing as it goes and refusing to
// return successfully unless the hash matches what was pinned — so a
// mirror, proxy, or compromised release asset that serves different bytes
// than the ones this agent was built against fails closed.
func download(ctx context.Context, logger *slog.Logger, a archive, dst *os.File) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return err
	}
	// Not http.DefaultClient's zero timeout: the context above bounds the
	// whole transfer, and Go's default transport already honours
	// HTTPS_PROXY/NO_PROXY for networks that require one.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", a.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: unexpected status %d", a.url, resp.StatusCode)
	}

	hasher := sha256.New()
	src := io.TeeReader(&progressReader{
		r:      resp.Body,
		total:  resp.ContentLength,
		logger: logger,
		url:    a.url,
	}, hasher)

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("downloading %s: %w", a.url, err)
	}

	got := hex.EncodeToString(hasher.Sum(nil))
	if got != a.sha256 {
		return fmt.Errorf("%s failed its checksum: got %s, expected %s — refusing to use it", a.url, got, a.sha256)
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return nil
}

// progressReader logs every progressEvery bytes so a multi-hundred-MB
// download doesn't look like a hung process.
type progressReader struct {
	r        io.Reader
	total    int64 // -1 when the server sent no Content-Length
	read     int64
	reported int64
	logger   *slog.Logger
	url      string
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.read-p.reported >= progressEvery {
		p.reported = p.read
		if p.total > 0 {
			p.logger.Info("downloading", "url", p.url,
				"progress", fmt.Sprintf("%d%%", p.read*100/p.total),
				"mb", p.read>>20)
		} else {
			p.logger.Info("downloading", "url", p.url, "mb", p.read>>20)
		}
	}
	return n, err
}

func extractZip(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", archivePath, err)
	}
	defer r.Close()

	for _, f := range r.File {
		path, err := safeJoin(destDir, f.Name)
		if err != nil {
			return err
		}
		mode := f.Mode()
		if mode.IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if mode&os.ModeSymlink != 0 {
			target, err := readZipSymlink(f)
			if err != nil {
				return err
			}
			if err := writeSymlink(destDir, path, target); err != nil {
				return err
			}
			continue
		}
		if !mode.IsRegular() {
			continue // devices, fifos and friends have no business in these archives
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		err = writeFile(path, src, mode.Perm())
		src.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func readZipSymlink(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	target, err := io.ReadAll(io.LimitReader(rc, 4096))
	if err != nil {
		return "", err
	}
	return string(target), nil
}

func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", archivePath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading %s: %w", archivePath, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading %s: %w", archivePath, err)
		}
		path, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFile(path, tr, os.FileMode(hdr.Mode).Perm()); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := writeSymlink(destDir, path, hdr.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			// Hard links are named relative to the archive root, not to the
			// entry holding them.
			target, err := safeJoin(destDir, hdr.Linkname)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.Link(target, path); err != nil {
				return err
			}
		}
	}
}

func writeFile(path string, src io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o644 // archives built on Windows carry no Unix mode at all
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeSymlink refuses any link that would point outside destDir — the
// same containment rule safeJoin applies to entry names, applied to where
// a link resolves to.
func writeSymlink(destDir, path, target string) error {
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(path), target)
	}
	if !within(destDir, resolved) {
		return fmt.Errorf("archive symlink %s points outside the destination directory", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	os.Remove(path)
	return os.Symlink(target, path)
}

// safeJoin resolves an archive entry name inside dir, rejecting anything
// that climbs out of it (the "zip slip" class of archive bug).
func safeJoin(dir, name string) (string, error) {
	path := filepath.Join(dir, filepath.FromSlash(name))
	if !within(dir, path) {
		return "", fmt.Errorf("archive entry %q escapes the destination directory", name)
	}
	return path, nil
}

func within(dir, path string) bool {
	dir = filepath.Clean(dir)
	path = filepath.Clean(path)
	return path == dir || strings.HasPrefix(path, dir+string(os.PathSeparator))
}

// stripSingleRoot returns the directory actually holding the extracted
// files: both distributions wrap everything in one top-level directory
// (ZAP_2.17.0/, jdk-21…-jre/) whose name carries a version this agent
// shouldn't have to care about downstream.
func stripSingleRoot(staging string) (string, error) {
	entries, err := os.ReadDir(staging)
	if err != nil {
		return "", err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(staging, entries[0].Name()), nil
	}
	return staging, nil
}
