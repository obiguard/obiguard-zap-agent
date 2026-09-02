package scan

import (
	"fmt"
	"strings"
	"testing"
)

// Verbatim ZAP 2.17 output, captured from a real `zap.sh -cmd -autorun` run
// against a toy target — not invented. The config-echo lines at the top
// matter: "Job requestor set url = …" looks a lot like the markers we parse
// and must not be mistaken for one.
var realZapOutput = []string{
	"Found Java version 17.0.17",
	"Available memory: 24576 MB",
	"Using JVM args: -Xmx6144m",
	"Job requestor set url = http://localhost:18211/",
	"Job requestor set method = GET",
	"Job activeScan set context = default",
	"Job activeScan set policy = Default Policy",
	"Job report set template = traditional-json",
	"Job report set reportDir = /tmp/out",
	"Job report set reportFile = report",
	"Job requestor started",
	"Job requestor requesting URL http://localhost:18211/",
	"Job requestor finished, time taken: 00:00:00",
	"Job activeScan started",
	"Job activeScan finished, time taken: 00:00:24",
	"Job report started",
	"Job report generated report /tmp/out/report.json",
	"Job report finished, time taken: 00:00:00",
	"Automation plan succeeded!",
}

func TestProgressTracker_RealZapRun(t *testing.T) {
	tr := NewProgressTracker(3)
	for _, line := range realZapOutput {
		tr.Observe(line)
	}

	got := tr.Snapshot()
	if !got.PlanFinished {
		t.Error("expected PlanFinished after 'Automation plan succeeded!'")
	}
	if got.PhaseIndex != 3 {
		t.Errorf("PhaseIndex = %d, want 3 (requestor, activeScan, report)", got.PhaseIndex)
	}
	if got.EndpointsSeen != 1 {
		t.Errorf("EndpointsSeen = %d, want 1", got.EndpointsSeen)
	}
	if got.PhaseCount != 3 {
		t.Errorf("PhaseCount = %d, want 3", got.PhaseCount)
	}
}

// The config echoes precede the run and must not advance anything — this is
// the specific way a naive "Job X …" prefix match gets it wrong.
func TestProgressTracker_IgnoresConfigEchoes(t *testing.T) {
	tr := NewProgressTracker(3)
	for _, line := range realZapOutput[:10] {
		tr.Observe(line)
	}
	got := tr.Snapshot()
	if got.PhaseIndex != 0 || got.Phase != "" || got.EndpointsSeen != 0 {
		t.Errorf("config echoes advanced progress: %+v", got)
	}
}

func TestProgressTracker_MidRunPhase(t *testing.T) {
	tr := NewProgressTracker(3)
	for _, line := range realZapOutput[:14] { // through "Job activeScan started"
		tr.Observe(line)
	}
	got := tr.Snapshot()
	if got.Phase != "activeScan" {
		t.Errorf("Phase = %q, want activeScan", got.Phase)
	}
	if got.PhaseIndex != 2 {
		t.Errorf("PhaseIndex = %d, want 2", got.PhaseIndex)
	}
	if got.PlanFinished {
		t.Error("PlanFinished should be false mid-run")
	}
}

func TestProgressTracker_CountsEachRequestedURL(t *testing.T) {
	tr := NewProgressTracker(3)
	tr.Observe("Job requestor started")
	for i := 0; i < 54; i++ {
		tr.Observe("Job requestor requesting URL http://localhost:4001/thing")
	}
	if got := tr.Snapshot().EndpointsSeen; got != 54 {
		t.Errorf("EndpointsSeen = %d, want 54", got)
	}
}

// An unknown job name is not reported onward — the value reaches Obiguard
// and a browser, so it's whitelisted rather than trusted.
func TestProgressTracker_RejectsUnknownPhase(t *testing.T) {
	tr := NewProgressTracker(1)
	tr.Observe("Job <script>alert(1)</script> started")
	if got := tr.Snapshot(); got.Phase != "" || got.PhaseIndex != 0 {
		t.Errorf("unknown phase was accepted: %+v", got)
	}
}

func TestCountPlanJobs(t *testing.T) {
	plan := `
jobs:
  - type: requestor
  - type: activeScan
  - type: report
`
	if got := CountPlanJobs(plan); got != 3 {
		t.Errorf("CountPlanJobs = %d, want 3", got)
	}
	if got := CountPlanJobs("not: [valid"); got != 0 {
		t.Errorf("CountPlanJobs on invalid YAML = %d, want 0", got)
	}
}

// Verbatim ZAP 2.17 lines for a rejected request, captured from a real run
// against a server returning 401 and 404.
func TestProgressTracker_ParsesRejections(t *testing.T) {
	tr := NewProgressTracker(2)
	tr.Observe("Job requestor started")
	tr.Observe("Difference in response code values for message GET http://localhost:18222/locked Expected : 200 Received : 401")
	tr.Observe("Difference in response code values for message POST http://localhost:18222/gone Expected : 200 Received : 404")

	got := tr.Snapshot().Rejections
	if len(got) != 2 {
		t.Fatalf("expected 2 rejections, got %d: %+v", len(got), got)
	}
	if got[0].Method != "GET" || got[0].Status != 401 || got[0].URL != "http://localhost:18222/locked" {
		t.Errorf("first rejection parsed wrong: %+v", got[0])
	}
	if got[1].Method != "POST" || got[1].Status != 404 {
		t.Errorf("second rejection parsed wrong: %+v", got[1])
	}
}

// Distinct URLs, since identical lines are deduped rather than counted —
// the cap exists to bound a scan where genuinely many endpoints fail.
func TestProgressTracker_RejectionsAreCapped(t *testing.T) {
	tr := NewProgressTracker(1)
	for i := 0; i < maxRejections*3; i++ {
		tr.Observe(fmt.Sprintf(
			"Difference in response code values for message GET http://x/path%d Expected : 200 Received : 404", i))
	}
	if got := len(tr.Snapshot().Rejections); got != maxRejections {
		t.Errorf("rejections = %d, want capped at %d", got, maxRejections)
	}
}

func TestParseRejection_RejectsMalformed(t *testing.T) {
	for _, line := range []string{
		"Job requestor started",
		"Difference in response code values for message GET http://x/y Expected : 200",
		"Difference in response code values for message GET http://x/y Expected : 200 Received : abc",
		"Difference in response code values for message GET http://x/y Expected : 200 Received : 99",
		"Difference in response code values for message GET " + strings.Repeat("u", maxURLLen+10) + " Expected : 200 Received : 404",
	} {
		if _, ok := parseRejection(line); ok {
			t.Errorf("accepted malformed line: %q", line)
		}
	}
}

// Snapshot must not alias the tracker's slice — a later append that fits in
// capacity would otherwise mutate a snapshot already handed to the reporter.
func TestSnapshot_DoesNotAliasRejections(t *testing.T) {
	tr := NewProgressTracker(1)
	tr.Observe("Difference in response code values for message GET http://x/1 Expected : 200 Received : 404")
	snap := tr.Snapshot()
	tr.Observe("Difference in response code values for message GET http://x/2 Expected : 200 Received : 500")
	if len(snap.Rejections) != 1 {
		t.Errorf("snapshot changed after later Observe: %+v", snap.Rejections)
	}
}

// ZAP prints each difference-in-response-code warning twice: once inline,
// then again tab-indented in the job's end-of-run summary. Both forms are
// verbatim from a real run.
func TestProgressTracker_DedupesRepeatedRejections(t *testing.T) {
	tr := NewProgressTracker(2)
	tr.Observe("Difference in response code values for message GET http://localhost:18233/locked Expected : 200 Received : 401")
	tr.Observe("Difference in response code values for message GET http://localhost:18233/gone Expected : 200 Received : 404")
	tr.Observe("\tDifference in response code values for message GET http://localhost:18233/locked Expected : 200 Received : 401")
	tr.Observe("\tDifference in response code values for message GET http://localhost:18233/gone Expected : 200 Received : 404")

	got := tr.Snapshot().Rejections
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped rejections, got %d: %+v", len(got), got)
	}
}

// The same URL rejected with two different statuses is two distinct facts
// and must survive dedupe.
func TestProgressTracker_KeepsSameURLDifferentStatus(t *testing.T) {
	tr := NewProgressTracker(1)
	tr.Observe("Difference in response code values for message GET http://x/y Expected : 200 Received : 401")
	tr.Observe("Difference in response code values for message GET http://x/y Expected : 200 Received : 500")
	if got := len(tr.Snapshot().Rejections); got != 2 {
		t.Errorf("rejections = %d, want 2", got)
	}
}

// The plan asks for responseCode 200 only to make ZAP print each endpoint's
// actual status — it is not a claim that 200 is the right answer. A DELETE
// returning 204 or a create returning 201 is the endpoint working correctly
// and must never be reported as a rejection.
func TestParseRejection_TreatsAll2xxAsSuccess(t *testing.T) {
	for _, status := range []int{200, 201, 202, 204, 206} {
		line := fmt.Sprintf(
			"Difference in response code values for message DELETE http://x/thing Expected : 200 Received : %d", status)
		if r, ok := parseRejection(line); ok {
			t.Errorf("status %d reported as a rejection: %+v", status, r)
		}
	}
}

func TestParseRejection_KeepsNon2xx(t *testing.T) {
	for _, status := range []int{301, 302, 401, 403, 404, 429, 500, 503} {
		line := fmt.Sprintf(
			"Difference in response code values for message GET http://x/y Expected : 200 Received : %d", status)
		r, ok := parseRejection(line)
		if !ok || r.Status != status {
			t.Errorf("status %d should still be reported, got ok=%v %+v", status, ok, r)
		}
	}
}
