# Telemetry policy

## TL;DR

MorphKatz sends **zero telemetry**. No usage analytics, no crash
reports, no auto-update checks, no licence heartbeats, no anonymised
counters, no DNS pings, no cloud-side caches — nothing leaves your
machine that you didn't explicitly tell it to.

This is a **frozen commitment**. Any pull request that changes it is
a release-blocker.

## Detail

`morphkatz.exe` performs the following network operations, **all** of
which require an explicit user action:

| Operation | When | User-initiated |
|---|---|---|
| HTTP fetch via `--target <url>` (when implemented) | The user explicitly passes a URL to a YARA-rules pack | ✅ Yes |
| MalwareBazaar corpus download (`scripts/bench/fetch_corpus.ps1`) | The user runs that script with their own MalwareBazaar API key | ✅ Yes |
| YARA-rules pack download (`scripts/bench/fetch_yara_pack.ps1`) | The user runs that script | ✅ Yes |

There are **no other** network operations. In particular,
`morphkatz.exe` does not:

- ❌ Phone home with version/OS/runtime data
- ❌ Send crash dumps to any service
- ❌ Check for updates
- ❌ Validate any licence or activation key
- ❌ Open a TCP listening socket
- ❌ Resolve any hostname other than those you typed
- ❌ Read any environment variable that smells like a tracking ID
  (`AMPLITUDE_KEY`, `SEGMENT_TOKEN`, `MIXPANEL_*`, etc.)
- ❌ Spawn child processes other than verifier binaries you opt into
  (`unicorn-engine`, `MpCmdRun.exe` for the `scan` subcommand, etc.)

You can verify this for yourself with any process / network monitor
of your choice (`procmon`, `Wireshark`, `Sysmon`). PRs that add a
test for this property under
`tests/integration/no_telemetry_test.cpp` are very welcome.

## Hard-coded constraints

This commitment is enforced not just by policy but by code review.
The following constraints **must** hold for any merge to `main`:

1. No imports of analytics SDKs (Sentry, Bugsnag, Crashlytics,
   App Insights, Segment, Amplitude, Mixpanel, etc.) in source files
   under `src/**` or `include/morphkatz/**`.
2. No HTTPS / HTTP client code that runs without an explicit
   command-line flag the user passes.
3. No `WSAStartup`, `socket()`, `connect()`, `WinHttp*`, `WinINet`,
   `libcurl`, or equivalent calls in compiled-in code paths reachable
   from `wmain` *unless* the user has invoked a subcommand that
   advertises network access in its `--help` output.

The CI for `morphkatz_core` should and will eventually grow a static
check that audits the link map for these symbols and fails the
release build if any of them appear in a non-explicit code path. PRs
toward that check are also welcome.

## Reporting violations

If you find any networking behaviour not documented above, please
open a `bug` issue with the label `telemetry` or report it as a
security advisory per [`SECURITY.md`](SECURITY.md). We treat any
undocumented network egress as a **release-blocking defect**.
