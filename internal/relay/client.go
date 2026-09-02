// Package relay is the agent's only network dependency other than the ZAP
// target itself: poll Obiguard's relay for a job, run it, report back.
// Deliberately dumb — the agent doesn't know or care what a "plan" means,
// it just carries opaque YAML in and opaque JSON out.
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// The relay long-polls a queued job for up to ~25s server-side before
// returning 204 — the client timeout has to comfortably exceed that, not
// just cover ordinary network latency.
const pollHTTPTimeout = 40 * time.Second

// Version identifies this agent build to the relay, which surfaces it in the
// customer's portal alongside the hostname — so an operator can tell which
// machine is actually connected, and see when a newly-installed agent has
// taken over from an older one.
const Version = "0.1.0"

type Client struct {
	baseURL    string
	token      string
	hostname   string
	httpClient *http.Client
}

func New(baseURL, token string) *Client {
	// Best-effort: an unresolvable hostname is not worth failing startup for,
	// it just means the portal shows the agent without one.
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	return &Client{
		baseURL:  baseURL,
		token:    token,
		hostname: hostname,
		httpClient: &http.Client{
			Timeout: pollHTTPTimeout,
		},
	}
}

// Job is one unit of work: run this plan, report back what happened.
type Job struct {
	JobID    string `json:"jobId"`
	PlanYAML string `json:"planYaml"`
}

// Poll blocks for up to the relay's own long-poll window and returns the
// next queued job for this agent's org, or (nil, nil) if none was waiting.
func (c *Client) Poll(ctx context.Context) (*Job, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/agent/jobs/poll", nil)
	if err != nil {
		return nil, err
	}
	c.authorize(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("poll: unexpected status %d: %s", resp.StatusCode, body)
	}

	var job Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, fmt.Errorf("poll: decoding response: %w", err)
	}
	return &job, nil
}

// SubmitResult reports a completed job's raw ZAP report. Parsing it into
// findings happens centrally (obiguard-zap-service) — the agent never
// interprets the report's contents.
func (c *Client) SubmitResult(ctx context.Context, jobID string, report json.RawMessage) error {
	return c.postResult(ctx, jobID, map[string]any{"report": report})
}

// SubmitError reports a job that failed to run at all (ZAP not installed or
// not on PATH, exited non-zero with no report, timed out, etc.).
func (c *Client) SubmitError(ctx context.Context, jobID string, errMsg string) error {
	return c.postResult(ctx, jobID, map[string]any{"error": errMsg})
}

// SubmitCancelled confirms a job was stopped because IsCancelled reported
// it, not because it failed. Callers must pass a context that's still
// valid at the point this is called — never the same per-job context that
// was just cancelled to stop the scan, or this call would fail immediately
// too.
func (c *Client) SubmitCancelled(ctx context.Context, jobID string) error {
	return c.postResult(ctx, jobID, map[string]any{"cancelled": true})
}

// ReportProgress sends the current progress for a running job and returns
// whether the relay wants it cancelled — one round trip doing both, on the
// cadence the cancellation check already runs at, so watching a scan costs
// no extra requests and doubles as the job's heartbeat.
//
// Only the bounded fields of Progress are sent; raw scanner output never
// leaves the customer's network. Same error contract as IsCancelled: a
// transient failure must not be read as "cancelled".
func (c *Client) ReportProgress(ctx context.Context, jobID string, progress any) (bool, error) {
	body, err := json.Marshal(map[string]any{"progress": progress})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/agent/jobs/%s/progress", c.baseURL, jobID), bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.authorize(req)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("report progress: unexpected status %d: %s", resp.StatusCode, b)
	}

	var out struct {
		Cancelled bool `json:"cancelled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("report progress: decoding response: %w", err)
	}
	return out.Cancelled, nil
}

// IsCancelled checks whether the relay has recorded a cancel request for
// jobID — meant to be polled periodically while a job is running, not
// called once. A transient error here should not itself stop the scan;
// callers should log and retry on the next tick rather than treating it as
// a positive cancellation signal.
//
// Superseded by ReportProgress, which answers the same question and carries
// progress with it. Kept because the relay still serves this route for
// already-installed agents that predate progress reporting.
func (c *Client) IsCancelled(ctx context.Context, jobID string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/agent/jobs/%s/cancelled", c.baseURL, jobID), nil)
	if err != nil {
		return false, err
	}
	c.authorize(req)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, fmt.Errorf("check cancelled: unexpected status %d: %s", resp.StatusCode, body)
	}

	var out struct {
		Cancelled bool `json:"cancelled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("check cancelled: decoding response: %w", err)
	}
	return out.Cancelled, nil
}

func (c *Client) postResult(ctx context.Context, jobID string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/agent/jobs/%s/results", c.baseURL, jobID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.authorize(req)

	// A fresh, shorter-timeout client for this call — posting a result
	// isn't a long-poll and shouldn't wait anywhere near as long.
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("submit result: unexpected status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// authorize also carries this agent's identity. Sent on every request rather
// than via a separate registration call: the relay records it on the same
// authenticate() that already doubles as the heartbeat, so identity can never
// drift out of sync with liveness.
func (c *Client) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.hostname != "" {
		req.Header.Set("X-Agent-Hostname", c.hostname)
	}
	req.Header.Set("X-Agent-Version", Version)
}
