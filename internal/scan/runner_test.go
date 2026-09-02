package scan

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const samplePlan = `
env:
  contexts:
    - name: default
      urls:
        - https://api.example.com
jobs:
  - type: requestor
    parameters: {}
    requests:
      - url: https://api.example.com/me
        name: t1
        method: GET
  - type: activeScan
    parameters:
      context: default
      policy: Default Policy
  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk
      reportFile: report
      reportTitle: Attack Surface Scan
`

func TestRewriteReportDir(t *testing.T) {
	out, err := rewriteReportDir(samplePlan, "/Users/test/scratch/job-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var plan map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatalf("output isn't valid YAML: %v", err)
	}

	jobs := plan["jobs"].([]interface{})
	var reportDir interface{}
	for _, raw := range jobs {
		job := raw.(map[string]interface{})
		if job["type"] == "report" {
			reportDir = job["parameters"].(map[string]interface{})["reportDir"]
		}
	}
	if reportDir != "/Users/test/scratch/job-123" {
		t.Errorf("reportDir = %v, want the rewritten path", reportDir)
	}

	// Everything else about the plan must survive untouched.
	if !strings.Contains(out, "https://api.example.com/me") {
		t.Errorf("output lost the requestor job's URL: %s", out)
	}
	if !strings.Contains(out, "reportFile: report") {
		t.Errorf("output lost reportFile: %s", out)
	}
}

func TestRewriteReportDir_NoReportJob(t *testing.T) {
	plan := `
jobs:
  - type: requestor
    parameters: {}
`
	if _, err := rewriteReportDir(plan, "/tmp/x"); err == nil {
		t.Fatal("expected an error when the plan has no report job")
	}
}

func TestRewriteReportDir_InvalidYAML(t *testing.T) {
	if _, err := rewriteReportDir("not: valid: yaml: [", "/tmp/x"); err == nil {
		t.Fatal("expected an error for invalid YAML")
	}
}

func TestLineWriter_SplitsAcrossChunkBoundaries(t *testing.T) {
	var got []string
	w := &lineWriter{onLine: func(s string) { got = append(got, s) }}

	// A line deliberately split mid-word across two Writes — os/exec hands
	// over arbitrary chunks, not whole lines.
	w.Write([]byte("Job requestor sta"))
	w.Write([]byte("rted\nActive Scan progress: 45%\npartial tail"))

	if len(got) != 2 {
		t.Fatalf("expected 2 complete lines before flush, got %d: %v", len(got), got)
	}
	if got[0] != "Job requestor started" {
		t.Errorf("first line reassembled wrong: %q", got[0])
	}
	if got[1] != "Active Scan progress: 45%" {
		t.Errorf("second line wrong: %q", got[1])
	}

	// The trailing fragment has no newline — it must still be emitted, or
	// the last line of a run gets silently dropped.
	w.flush()
	if len(got) != 3 || got[2] != "partial tail" {
		t.Errorf("flush did not emit the trailing fragment: %v", got)
	}
}

func TestLineWriter_RetainsBoundedTail(t *testing.T) {
	w := &lineWriter{}
	// Well past the cap — retained output must not grow without bound just
	// because a scan is chatty.
	for i := 0; i < 400; i++ {
		w.Write([]byte(strings.Repeat("x", 100) + "\n"))
	}
	if got := len(w.retained()); got > retainedOutputBytes {
		t.Errorf("retained %d bytes, expected at most %d", got, retainedOutputBytes)
	}
}

func TestLineWriter_SkipsBlankLines(t *testing.T) {
	var got []string
	w := &lineWriter{onLine: func(s string) { got = append(got, s) }}
	w.Write([]byte("\n   \nreal line\n\n"))
	if len(got) != 1 || got[0] != "real line" {
		t.Errorf("expected only the non-blank line, got %v", got)
	}
}
