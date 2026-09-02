# Contributing

Thanks for looking at this. Please read the note on how this repo is
published first — it explains why a merged pull request here won't show up
in the history the way you'd expect.

## How this repo is published

Development happens in a private repository at Obiguard. This public repo
receives **one commit per release**, containing the released tree at that
version. It is not a mirror of the development history, and `main` here is
only ever moved by the release pipeline.

The practical consequences:

- Pull requests are very welcome, but they are not merged here directly. A
  maintainer applies the change to the private source repo with attribution
  to you, and it reaches this repo in the next release. Your PR is then
  closed with a link to the release that contains it.
- Please don't force-push, rebase onto, or branch long-lived work from
  `main` — it is rewritten wholesale at each release.
- The commit history here is intentionally shallow. `git log` shows the
  release sequence, not the change-by-change development.

## Reporting a bug

Open an issue with:

- the output of `obiguard-zap-agent version` (or the image tag and digest),
- the host OS and architecture,
- the agent's own log around the failure — job IDs and status lines are
  safe to share, and the agent never logs plan or credential contents.

## Security issues

Please **do not** open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for how to report one privately.

## Changes we're most likely to take

This agent deliberately has a very small feature set — it runs the scan
plan it is handed and returns the report, and nothing more (see
[README.md](README.md) for what it explicitly does not do). Changes that
keep that surface small are much easier to accept than ones that widen it.
Portability fixes, clearer errors, toolchain and packaging improvements,
and documentation corrections are all straightforwardly useful.

If you're considering something larger, please open an issue to discuss it
before writing the code.

## Before you send a patch

```bash
gofmt -l .
go vet ./...
go test -race ./...
```

CI runs exactly these, plus a multi-architecture image build and CodeQL.
