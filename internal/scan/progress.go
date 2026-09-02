package scan

import (
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Progress is what the agent reports back about a still-running scan.
//
// Deliberately a handful of bounded values and nothing else: the plan this
// agent executes carries a plaintext test credential, and nothing can bound
// what a scanner prints to its own stdout, so raw output must never leave
// the customer's network. Every field here is either an integer or a phase
// name drawn from a fixed set — see knownPhase.
type Progress struct {
	// Which automation job is running: requestor, activeScan or report.
	// Empty before the first job starts and after the plan finishes.
	Phase string `json:"phase"`
	// 1-based position of Phase among the plan's jobs, and how many there
	// are — enough for "step 2 of 3" without inventing a percentage, which
	// ZAP's stdout does not actually provide.
	PhaseIndex int `json:"phaseIndex"`
	PhaseCount int `json:"phaseCount"`
	// How many URLs the requestor job has actually issued. The single most
	// useful number here: a scan that seeds far fewer endpoints than it has
	// targets is misconfigured, and that's invisible until the report lands.
	EndpointsSeen int `json:"endpointsSeen"`
	// True once ZAP reports the whole plan finished.
	PlanFinished bool `json:"planFinished"`
	// Endpoints whose response wasn't the 200 the plan asked for, so an
	// operator can see WHICH ones were rejected and with what status rather
	// than only an aggregate percentage. Capped — see maxRejections.
	Rejections []Rejection `json:"rejections,omitempty"`
}

// Rejection is one endpoint that answered with something other than the
// expected status. Only a method, a URL the customer configured themselves,
// and an integer status — no response bodies or headers, which could carry
// anything.
type Rejection struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// Bounds on what's carried upstream: a scan of hundreds of targets that
// rejects every one shouldn't produce an unbounded payload, and the first
// rejections are the informative ones (they're almost always all the same
// cause).
const (
	maxRejections = 50
	maxURLLen     = 300
)

// ZAP's automation framework prints these markers when the plan sets
// `progressToStdout` (obiguard-zap-service always does). Verified against
// ZAP 2.17 output rather than assumed:
//
//	Job requestor set url = http://…      <- config echo, before the run
//	Job requestor started
//	Job requestor requesting URL http://…
//	Job requestor finished, time taken: 00:00:00
//	Job activeScan started
//	Automation plan succeeded!
const (
	jobPrefix        = "Job "
	startedSuffix    = " started"
	requestingMarker = " requesting URL "
	planFinishedLine = "Automation plan"
	// Emitted per request when the response doesn't match the plan's
	// expected responseCode, in exactly this shape (ZAP 2.17):
	//
	//   Difference in response code values for message GET http://… Expected : 200 Received : 404
	rejectionPrefix = "Difference in response code values for message "
	receivedMarker  = " Received : "
	expectedMarker  = " Expected : "
)

// parseRejection pulls the method, URL and received status out of a
// difference-in-response-code line. Returns ok=false for anything that
// doesn't match the exact shape, rather than guessing.
func parseRejection(line string) (Rejection, bool) {
	rest, found := strings.CutPrefix(line, rejectionPrefix)
	if !found {
		return Rejection{}, false
	}

	// "<METHOD> <url> Expected : 200 Received : 404"
	method, afterMethod, found := strings.Cut(rest, " ")
	if !found || method == "" || len(method) > 10 {
		return Rejection{}, false
	}

	urlPart, afterURL, found := strings.Cut(afterMethod, expectedMarker)
	if !found {
		return Rejection{}, false
	}
	rawURL := strings.TrimSpace(urlPart)
	if rawURL == "" || len(rawURL) > maxURLLen {
		return Rejection{}, false
	}

	_, received, found := strings.Cut(afterURL, receivedMarker)
	if !found {
		return Rejection{}, false
	}
	status, err := strconv.Atoi(strings.TrimSpace(received))
	if err != nil || status < 100 || status > 599 {
		return Rejection{}, false
	}

	// A 2xx is a success, so it is NOT a rejection — the plan asks for 200
	// only because that's the one way to make ZAP print each endpoint's
	// actual status, never as a claim that 200 is the correct answer. A
	// DELETE returning 204, or a create returning 201, is the endpoint
	// working exactly as intended and must not be reported as a problem.
	if status >= 200 && status < 300 {
		return Rejection{}, false
	}

	return Rejection{Method: method, URL: rawURL, Status: status}, true
}

// Only phases the plan can actually contain. ZAP echoes the job name back
// from the plan, so this is not attacker-controlled — but the value is
// forwarded to Obiguard and rendered in a portal, so it's whitelisted
// rather than trusted.
func knownPhase(name string) bool {
	switch name {
	case "requestor", "activeScan", "spider", "spiderAjax", "passiveScan-wait", "report":
		return true
	default:
		return false
	}
}

// ProgressTracker turns the agent's line stream into the latest Progress.
// Observe is called from the scan's output goroutines while Snapshot is read
// by the reporting loop, so it's mutex-guarded.
type ProgressTracker struct {
	mu sync.Mutex
	p  Progress
	// ZAP prints each difference-in-response-code warning twice — once as it
	// happens, then again tab-indented in the job's end-of-run summary — so
	// the same endpoint would otherwise be listed twice. Keyed by
	// method+url+status, since one URL rejected with two different statuses
	// is genuinely two facts.
	seenRejections map[string]bool
}

func NewProgressTracker(phaseCount int) *ProgressTracker {
	return &ProgressTracker{
		p:              Progress{PhaseCount: phaseCount},
		seenRejections: map[string]bool{},
	}
}

// Observe consumes one line of scanner output. Unrecognised lines — the vast
// majority — are ignored rather than reported, which is what keeps free text
// from ever reaching the relay.
func (t *ProgressTracker) Observe(line string) {
	line = strings.TrimSpace(line)

	t.mu.Lock()
	defer t.mu.Unlock()

	if strings.HasPrefix(line, planFinishedLine) {
		t.p.PlanFinished = true
		t.p.Phase = ""
		return
	}

	if r, ok := parseRejection(line); ok {
		key := r.Method + " " + r.URL + " " + strconv.Itoa(r.Status)
		if !t.seenRejections[key] && len(t.p.Rejections) < maxRejections {
			t.seenRejections[key] = true
			t.p.Rejections = append(t.p.Rejections, r)
		}
		return
	}

	if !strings.HasPrefix(line, jobPrefix) {
		return
	}
	rest := line[len(jobPrefix):]

	// "Job requestor requesting URL …" — count seeded endpoints. Checked
	// before the started/finished handling since it shares the prefix.
	if i := strings.Index(rest, requestingMarker); i > 0 {
		if knownPhase(rest[:i]) {
			t.p.EndpointsSeen++
		}
		return
	}

	// "Job <name> started" — note this must not match "Job <name> set url =",
	// which ZAP prints while loading the plan, before anything runs.
	if strings.HasSuffix(rest, startedSuffix) {
		name := strings.TrimSuffix(rest, startedSuffix)
		if knownPhase(name) {
			t.p.Phase = name
			t.p.PhaseIndex++
		}
	}
}

// Snapshot returns a copy safe to hand to the reporting goroutine while the
// scan keeps running. The Rejections slice is copied explicitly: a struct
// copy duplicates only the slice header, so a later append that fit within
// capacity would write into the array a caller is still reading.
func (t *ProgressTracker) Snapshot() Progress {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.p
	if t.p.Rejections != nil {
		out.Rejections = append([]Rejection(nil), t.p.Rejections...)
	}
	return out
}

// CountPlanJobs reports how many jobs the plan contains, so progress can be
// expressed as "step N of M". Returns 0 when the plan can't be read — the
// caller reports that as "unknown" rather than guessing a total.
func CountPlanJobs(planYAML string) int {
	var plan struct {
		Jobs []struct{} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(planYAML), &plan); err != nil {
		return 0
	}
	return len(plan.Jobs)
}
