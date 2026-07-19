# Technical design

## Overview

NetWhy is organized as a pipeline with a separate inference layer:

```text
target parser
    │
    ▼
system DNS ──► per-address kernel route
    │                    │
    └────────► concurrent TCP probes
                         │
                         ▼
                TLS and HTTP probe
                         │
                         ▼
                deterministic diagnosis
                         │
                  ┌──────┴──────┐
                  ▼             ▼
          outcome-first text  coded JSON v1
```

Probe modules collect facts and do not decide the final cause. The diagnosis module consumes those facts in precedence order. Presentation code does not perform probes or infer state.

## Modules

| Module | Responsibility |
| --- | --- |
| `target` | Parse supported input forms into a normalized scheme, host, port, and optional URL. |
| `probe::dns` | Resolve with the process's system resolver and apply the requested address-family filter. |
| `probe::route` | Run `ip -j route get` for each destination and extract interface, gateway, and preferred source. |
| `probe::tcp` | Connect to all resolved socket addresses concurrently with independent timeouts. |
| `probe::application` | Try TCP-successful addresses in latency order until the application protocol is reachable, validating TLS when required and issuing an HTTP `HEAD`. |
| `diagnosis` | Apply explicit precedence rules and separate observed failures from likely causes. |
| `output` | Render the report without changing its meaning. |

## Ordering and continuation

- DNS must produce at least one usable address before route or TCP probes can run.
- Route inspection and TCP connection are independent evidence. A failed or skipped `ip route` command does not suppress a real connection attempt.
- All resolved addresses are tested concurrently to expose asymmetric IPv4/IPv6 behavior.
- The application probe starts with the fastest address that completed TCP successfully. If that address fails during its fresh connection, TLS, or HTTP exchange, NetWhy tries the next TCP-successful address and retains every attempt.
- TLS and HTTP use a fresh connection. This avoids transferring ownership of probe sockets and makes timing for each stage explicit.
- A valid HTTP status line proves application-protocol reachability. A 4xx or 5xx is a warning, not a network failure.

## Timeouts

`--timeout-ms` applies independently to:

- system DNS resolution;
- each iproute2 route inspection;
- each TCP connection attempt;
- the application probe's fresh TCP connection;
- the TLS handshake;
- the HTTP request/first response line exchange.

DNS uses the system resolver, bounded by the requested operation timeout. Resolver-internal behavior remains platform dependent.

## TLS behavior

- Trust roots come from Mozilla's root program through `webpki-roots`.
- SNI and certificate-name validation use the original hostname, even when connecting to a selected IP address.
- ALPN requests HTTP/1.1 because v0.1 parses a textual HTTP status line.
- Certificate details beyond the validation result are deferred.

This means NetWhy may differ from applications using a private enterprise trust store. Every TLS attempt records `trust_source: "mozilla_webpki_roots"` so this implementation choice is discoverable.

## Proxy behavior

v0.1 records recognized proxy environment variables but connects directly. Proxy URL credentials must be replaced with `<redacted>` before entering the report model. Both output formats include a note explaining that the probes bypassed the proxy.

Recognized names:

- `HTTP_PROXY` and `http_proxy`
- `HTTPS_PROXY` and `https_proxy`
- `ALL_PROXY` and `all_proxy`
- `NO_PROXY` and `no_proxy`

## Status model

Every stage has one of four statuses:

- `pass`: direct evidence that the stage succeeded;
- `warn`: the target is reachable, but an asymmetric or application-level issue exists;
- `fail`: direct evidence that the requested operation failed;
- `skip`: the stage was not applicable or its optional dependency was unavailable.

The top-level status controls the process exit code. `warn` exits successfully so scripts can distinguish reachability from application policy responses using JSON fields.

## Human and agent interfaces

Both formats are projections of the same report and therefore cannot disagree about status, diagnosis, or evidence. Human output puts the conclusion and remediation before detailed evidence, uses textual status markers, and never relies on terminal color. JSON output adds stable document, diagnosis, and error codes so automation does not need to parse prose.

In JSON mode, stdout contains exactly one document. Completed diagnostics conform to `report.schema.json`; invocation and target errors conform to `error.schema.json`. Human usage errors use stderr. The full compatibility rules are specified in [output-contract.md](output-contract.md).

## Error and inference rules

Rules are ordered from the earliest layer to the latest:

1. DNS failure.
2. No successful TCP address, classified as refusal, no route, timeout, or other.
3. Partial IPv4/IPv6 success.
4. Every fresh application connection fails.
5. TLS failure after TCP success.
6. HTTP exchange failure after transport success.
7. HTTP 4xx/5xx warning or partial per-address application success.
8. Full success.

Route-command failure alone cannot be the top-level cause if TCP succeeds.

## Privacy and security

- The binary forbids unsafe Rust.
- No shell is used to invoke iproute2; arguments are passed directly to `ip`.
- Target input is parsed before it reaches an HTTP request.
- Proxy credentials are redacted in memory before serialization.
- Target URL userinfo is rejected. Query strings and fragments are replaced with `REDACTED` in reports while the original query remains available only to the in-memory request builder.
- HTTP status lines are limited to 8 KiB, require CRLF and valid HTTP/1.x syntax, and cannot contain control characters.
- DNS results are capped at 32 unique addresses; route and TCP fan-out is limited to eight concurrent operations.
- JSON does not include unrelated environment variables, resolver files, firewall rules, or process lists.
- Future support bundles must make internal-address redaction configurable and visible.

## Testing strategy

- Pure unit tests for target interpretation and diagnosis precedence.
- Local TCP listeners for successful and refused transport behavior.
- Local HTTP listeners for status parsing.
- A local test TLS server is preferred before v0.1 release.
- Route parsing tests use captured iproute2 JSON, not the test host's routing table.
- JSON reports are validated against `docs/report.schema.json` in CI.
- Public internet checks are manually invoked smoke tests and never gate a release.
- `cargo-llvm-cov` enforces project-wide minimums of 90% lines, 90% regions, and 95% functions, plus an 80% line floor for every measured file. Coverage identifies untested behavior but does not replace assertions or justify artificial tests for unreachable serialization failures.
