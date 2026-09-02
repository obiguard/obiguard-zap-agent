// obiguard-zap-agent runs inside a customer's network so Obiguard's
// centrally-hosted ZAP DAST scanner can test internal-only targets it
// otherwise can't reach. It never accepts inbound connections — it polls
// Obiguard's relay for work, same shape as a CI runner checking for
// pipeline jobs. See README.md for what it does and does not do.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/obiguard/obiguard-zap-agent/internal/config"
	"github.com/obiguard/obiguard-zap-agent/internal/relay"
	"github.com/obiguard/obiguard-zap-agent/internal/scan"
	"github.com/obiguard/obiguard-zap-agent/internal/toolchain"
)

// Stamped in at link time by the release build (see the ldflags in
// .github/workflows/release.yml and the Dockerfile). A plain `go build`
// leaves these alone, so an unreleased binary says so rather than claiming
// a version it isn't — which matters when someone reports a bug against
// whatever they happen to be running.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// How long to back off after a poll error before retrying — a healthy poll
// is naturally paced by the relay's own long-poll window, so this only
// matters when something is actually wrong (bad token, relay unreachable).
const pollErrorBackoff = 10 * time.Second

// How often to ask the relay whether the running job has been cancelled.
// The agent has no persistent connection, so "kill it now" is only ever as
// responsive as this interval — short enough to feel immediate, long
// enough not to hammer the relay across a scan that can run for minutes.
const cancelPollInterval = 3 * time.Second

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Answer "what am I running?" before anything else — no config, no
	// relay token, no toolchain. Accepts the flag spellings as well as the
	// subcommand because someone reaching for a version is as likely to
	// type one as the other.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			printVersion()
			return
		}
	}

	// The other subcommand: pay the toolchain's one-time download now
	// (install time, image build, a smoke test before enrollment) instead
	// of when the first scan job lands. Needs no relay token, so it can
	// run before the agent has one.
	if len(os.Args) > 1 && os.Args[1] == "provision" {
		os.Exit(provision(logger))
	}

	cfg, err := config.Load()
	if err != nil {
		logger.Error("startup failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := relay.New(cfg.RelayURL, cfg.AgentToken)
	tools := &zapResolver{opts: toolchainOptions(cfg.Toolchain)}

	// The version goes in the startup line too: agent logs are often the
	// only thing an operator can hand back when a scan misbehaves, and
	// they're worth little without knowing which build produced them.
	logger.Info("obiguard-zap-agent starting",
		"version", version, "commit", commit,
		"relay", cfg.RelayURL, "workDir", cfg.WorkDir, "toolchainDir", cfg.Toolchain.Dir)

	// Resolve ZAP — downloading it the first time, if this host has none —
	// before polling, so an operator sees the outcome in this agent's own
	// logs straight away. Deliberately not fatal: a host that can't reach
	// the download yet is better off polling and reporting that reason
	// back to the portal per job than crash-looping silently.
	if _, err := tools.get(ctx, logger); err != nil && ctx.Err() == nil {
		logger.Error("ZAP is not ready — will retry when a job arrives", "error", err)
	}

	run(ctx, logger, cfg, client, tools)
	logger.Info("shut down")
}

// printVersion writes the build stamp to stdout as plain text rather than
// through the structured logger — this is output a human or a script asked
// for directly, not a log line about the agent's operation.
func printVersion() {
	fmt.Printf("obiguard-zap-agent %s\ncommit: %s\nbuilt:  %s\n", version, commit, date)
}

// provision runs toolchain.Ensure and exits, reporting what it settled on.
func provision(logger *slog.Logger) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.LoadToolchain()
	logger.Info("provisioning the ZAP toolchain", "toolchainDir", cfg.Dir)

	resolved, err := toolchain.Ensure(ctx, logger, toolchainOptions(cfg))
	if err != nil {
		logger.Error("provisioning failed", "error", err)
		return 1
	}
	logger.Info("toolchain ready", "zapCmd", resolved.ZapCmd)
	return 0
}

func toolchainOptions(cfg config.ToolchainConfig) toolchain.Options {
	return toolchain.Options{
		Dir:         cfg.Dir,
		ZapCmd:      cfg.ZapCmd,
		AutoInstall: cfg.AutoInstall,
	}
}

// zapResolver holds the resolved ZAP for the life of the process, retrying
// resolution per job until it succeeds. toolchain.Ensure is cheap once
// everything is in place, but it still touches the filesystem and runs
// `java -version`, and there's no reason to repeat that for every job once
// it has answered.
type zapResolver struct {
	opts  toolchain.Options
	zap   scan.ZAP
	ready bool
}

func (z *zapResolver) get(ctx context.Context, logger *slog.Logger) (scan.ZAP, error) {
	if z.ready {
		return z.zap, nil
	}
	resolved, err := toolchain.Ensure(ctx, logger, z.opts)
	if err != nil {
		return scan.ZAP{}, err
	}
	z.zap = scan.ZAP{Cmd: resolved.ZapCmd, Env: resolved.Env}
	z.ready = true
	return z.zap, nil
}

func run(ctx context.Context, logger *slog.Logger, cfg config.Config, client *relay.Client, tools *zapResolver) {
	for {
		if ctx.Err() != nil {
			return
		}

		job, err := client.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("poll failed, backing off", "error", err)
			if !sleepOrDone(ctx, pollErrorBackoff) {
				return
			}
			continue
		}
		if job == nil {
			continue // nothing queued — re-poll immediately, the relay already paced this
		}

		logger.Info("job received", "jobId", job.JobID)
		runJob(ctx, logger, cfg, client, tools, job)
	}
}

// runJob runs one job to completion while a concurrent watcher polls the
// relay for a cancel request. jobCtx (not ctx) is what actually runs the
// scan, so the watcher can cut it short by cancelling just that scan
// without tearing down the agent's own process-lifetime context. Every
// call back to the relay in this function after scan.Run returns
// deliberately uses ctx, never jobCtx — jobCtx may already be cancelled by
// then (that's exactly what a cancelled run looks like), and a cancelled
// context can't be used to report anything.
func runJob(ctx context.Context, logger *slog.Logger, cfg config.Config, client *relay.Client, tools *zapResolver, job *relay.Job) {
	// Before anything job-specific: make sure there's a ZAP to run it
	// with. Normally already resolved at startup and free; on a host where
	// that failed, this is the retry, and its error is what the portal
	// shows for the job instead of a bare "it didn't work".
	zap, err := tools.get(ctx, logger)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		logger.Error("job failed", "jobId", job.JobID, "error", err)
		if submitErr := client.SubmitError(ctx, job.JobID, err.Error()); submitErr != nil {
			logger.Error("could not report job failure", "jobId", job.JobID, "error", submitErr)
		}
		return
	}

	jobCtx, cancelJob := context.WithCancel(ctx)
	defer cancelJob()

	tracker := scan.NewProgressTracker(scan.CountPlanJobs(job.PlanYAML))

	watchCtx, stopWatch := context.WithCancel(jobCtx)
	go watchJob(watchCtx, logger, client, job.JobID, tracker, cancelJob)

	// ZAP's own output, line by line as it happens — the plan asks for
	// progress on stdout, so this is what makes a long scan observable from
	// the host running it instead of a silent multi-minute block. The same
	// lines feed the tracker, whose bounded summary (never this raw text) is
	// what gets reported upstream.
	scanLog := logger.With("jobId", job.JobID)
	report, err := scan.Run(jobCtx, cfg.WorkDir, job.JobID, zap, job.PlanYAML, cfg.ScanTimeout,
		func(line string) {
			scanLog.Info("zap", "out", line)
			tracker.Observe(line)
		})
	stopWatch() // job is done one way or another — no need to keep polling

	if errors.Is(err, scan.ErrCancelled) {
		logger.Info("job cancelled", "jobId", job.JobID)
		if submitErr := client.SubmitCancelled(ctx, job.JobID); submitErr != nil {
			logger.Error("could not report job cancellation", "jobId", job.JobID, "error", submitErr)
		}
		return
	}
	if err != nil {
		logger.Error("job failed", "jobId", job.JobID, "error", err)
		if submitErr := client.SubmitError(ctx, job.JobID, err.Error()); submitErr != nil {
			logger.Error("could not report job failure", "jobId", job.JobID, "error", submitErr)
		}
		return
	}

	logger.Info("job completed", "jobId", job.JobID)
	if submitErr := client.SubmitResult(ctx, job.JobID, report); submitErr != nil {
		logger.Error("could not submit job result", "jobId", job.JobID, "error", submitErr)
	}
}

// watchJob reports progress and checks for cancellation on one ticker — a
// single round trip does both, so watching a scan costs no extra requests
// beyond the cancellation poll that already existed, and every report
// doubles as the job heartbeat the relay's stale-job sweep watches.
//
// It cancels cancelJob (stopping the running ZAP subprocess, same as a
// timeout does) the moment the relay reports this job as cancelled. A failed
// round trip is logged and retried on the next tick, never treated as a
// cancellation signal itself — a flaky relay must not be able to kill a scan
// on its own.
func watchJob(
	ctx context.Context,
	logger *slog.Logger,
	client *relay.Client,
	jobID string,
	tracker *scan.ProgressTracker,
	cancelJob context.CancelFunc,
) {
	ticker := time.NewTicker(cancelPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cancelled, err := client.ReportProgress(ctx, jobID, tracker.Snapshot())
			if err != nil {
				logger.Warn("progress report failed, will retry", "jobId", jobID, "error", err)
				continue
			}
			if cancelled {
				logger.Info("cancellation requested by relay, stopping scan", "jobId", jobID)
				cancelJob()
				return
			}
		}
	}
}

// sleepOrDone waits for d, returning false early (without waiting out the
// full duration) if ctx is cancelled first — so a shutdown signal during
// the backoff doesn't add a delay to exiting.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
