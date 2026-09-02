// Package scan is the entire ZAP-related surface of this agent: given a
// plan someone else built, run it with a locally-installed ZAP and hand
// back whatever report comes out. No knowledge of what a plan means, no
// awareness of targets, findings, or credentials beyond "this file might
// have one in it, so don't leave it lying around."
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const reportFileName = "report.json"
const planFileName = "plan.yaml"

// ZAP is the resolved scanner this agent shells out to: what to execute,
// and the environment to execute it in. Both come from
// internal/toolchain, which finds an installed ZAP or provisions one —
// this package never goes looking for either itself.
type ZAP struct {
	// Cmd is the zap.sh to run, normally an absolute path.
	Cmd string
	// Env is the environment for that process, already carrying the
	// JAVA_HOME and PATH that point ZAP at a usable Java runtime. Nil
	// inherits the agent's own environment unchanged.
	Env []string
}

// ErrCancelled distinguishes an externally-cancelled run (ctx cancelled by
// the caller, not by Run's own timeout) from an ordinary failure — so
// main.go can report "the customer stopped this" instead of "it broke."
var ErrCancelled = errors.New("scan cancelled")

// How much of ZAP's tail output to keep for the "exited with an error and
// produced no report" message. Only the tail matters there (the failure is
// at the end), and a runaway scan shouldn't be able to grow this without
// bound just because nothing is reading it.
const retainedOutputBytes = 8 << 10

// lineWriter turns the byte chunks os/exec hands us into whole lines,
// forwarding each to onLine as it completes so an operator sees ZAP's
// progress live rather than in one dump at the end. It also retains a
// bounded tail for error reporting.
//
// Both cmd.Stdout and cmd.Stderr point at one of these, and os/exec copies
// each in its own goroutine, so every field access has to hold the mutex.
type lineWriter struct {
	mu      sync.Mutex
	partial []byte
	tail    []byte
	onLine  func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.tail = append(w.tail, p...)
	if len(w.tail) > retainedOutputBytes {
		w.tail = w.tail[len(w.tail)-retainedOutputBytes:]
	}

	w.partial = append(w.partial, p...)
	for {
		i := bytes.IndexByte(w.partial, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.partial[:i]), "\r")
		w.partial = w.partial[i+1:]
		if w.onLine != nil && strings.TrimSpace(line) != "" {
			w.onLine(line)
		}
	}
	return len(p), nil
}

// flush emits whatever is left when the process exits without a trailing
// newline, so the last line of output is never silently dropped.
func (w *lineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	line := strings.TrimRight(string(w.partial), "\r")
	w.partial = nil
	if w.onLine != nil && strings.TrimSpace(line) != "" {
		w.onLine(line)
	}
}

func (w *lineWriter) retained() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.tail...)
}

// Run writes planYAML into a fresh directory under workDir — rewriting the
// plan's report.reportDir to that real local path first, since the plan
// arrives built for a value that made sense centrally, not for wherever
// this agent happens to keep its scratch space — then runs `<zap.Cmd> -cmd
// -autorun plan.yaml` directly as a native process (no Docker: this agent
// IS the only thing running, whether that's a bare `go run`/binary or this
// repo's own all-in-one Docker image with ZAP already baked in) and
// returns the resulting report.json. The job directory — which briefly
// holds the plan file's plaintext scan credential — is always removed
// before returning, success or failure.
//
// onOutput, if non-nil, is called with each complete line ZAP writes while
// the scan is still running. The plan already asks ZAP for progress output
// (`progressToStdout`), so this is what turns a multi-minute silent block
// into something an operator can watch. Nil is fine — output is still
// retained for error reporting either way.
func Run(
	ctx context.Context,
	workDir, jobID string,
	zap ZAP,
	planYAML string,
	timeout time.Duration,
	onOutput func(string),
) (json.RawMessage, error) {
	jobDir, err := filepath.Abs(filepath.Join(workDir, jobID))
	if err != nil {
		return nil, fmt.Errorf("resolving job dir: %w", err)
	}
	// 0o700, not world/group-writable — unlike the old Docker-sibling
	// setup, nothing here ever needs to be read by a different container
	// user, so there's no reason for this to be any more open than the
	// owning user.
	if err := os.MkdirAll(jobDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating job dir: %w", err)
	}
	defer os.RemoveAll(jobDir)

	rewritten, err := rewriteReportDir(planYAML, jobDir)
	if err != nil {
		return nil, fmt.Errorf("rewriting plan's report directory: %w", err)
	}

	planPath := filepath.Join(jobDir, planFileName)
	if err := os.WriteFile(planPath, []byte(rewritten), 0o600); err != nil {
		return nil, fmt.Errorf("writing plan file: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, zap.Cmd, "-cmd", "-autorun", planPath)
	cmd.Env = zap.Env

	// Streamed rather than CombinedOutput()'d: that buffers everything until
	// the process exits, which for a scan running many minutes means no
	// sign of life until it's already over.
	out := &lineWriter{onLine: onOutput}
	cmd.Stdout = out
	cmd.Stderr = out

	runErr := cmd.Run()
	out.flush()
	output := out.retained()

	if runCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scan timed out after %s", timeout)
	}
	// ctx (the caller's, not runCtx's own timeout) was cancelled — checked
	// before defer cancel() below runs, so this can only mean the caller
	// asked us to stop, never our own cleanup.
	if runCtx.Err() == context.Canceled {
		return nil, ErrCancelled
	}
	if runErr != nil {
		if _, isExitErr := runErr.(*exec.ExitError); !isExitErr {
			// Didn't even start. The agent provisions its own ZAP when the
			// host has none, so by this point that's an explicit ZAP_CMD
			// pointing at something unrunnable, or a provisioned copy that
			// was deleted out from under a running agent. Distinguish it
			// from "ZAP ran and reported a non-fatal warning via its exit
			// code," which report-presence below already tolerates.
			return nil, fmt.Errorf("could not start %q: %w", zap.Cmd, runErr)
		}
	}

	report, readErr := os.ReadFile(filepath.Join(jobDir, reportFileName))
	if readErr != nil {
		// No report at all is the real failure signal — ZAP's automation
		// framework can exit non-zero on non-fatal warnings even when the
		// scan otherwise completed, so a non-nil runErr alone isn't
		// treated as fatal as long as a report came out.
		if runErr != nil {
			return nil, fmt.Errorf("zap exited with an error and produced no report: %w (output: %s)", runErr, truncate(output, 2000))
		}
		return nil, fmt.Errorf("zap produced no report.json: %w", readErr)
	}

	if !json.Valid(report) {
		return nil, fmt.Errorf("report.json was not valid JSON")
	}
	return json.RawMessage(report), nil
}

// rewriteReportDir points the plan's report job at reportDir (an absolute
// local path) instead of whatever placeholder the plan was built with
// centrally — the only thing about the plan that depends on where it
// actually executes.
func rewriteReportDir(planYAML, reportDir string) (string, error) {
	var plan map[string]interface{}
	if err := yaml.Unmarshal([]byte(planYAML), &plan); err != nil {
		return "", fmt.Errorf("parsing plan: %w", err)
	}

	jobs, ok := plan["jobs"].([]interface{})
	if !ok {
		return "", fmt.Errorf("plan has no jobs array")
	}

	found := false
	for _, raw := range jobs {
		job, ok := raw.(map[string]interface{})
		if !ok || job["type"] != "report" {
			continue
		}
		params, ok := job["parameters"].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("report job has no parameters")
		}
		params["reportDir"] = reportDir
		found = true
	}
	if !found {
		return "", fmt.Errorf("plan has no report job")
	}

	out, err := yaml.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("re-serializing plan: %w", err)
	}
	return string(out), nil
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
