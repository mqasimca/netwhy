# Technical design

## Overview

NetWhy is organized as a pipeline with a separate inference layer:

```text
current process, or Linux --pid, --docker, or --podman context
    │
    ▼
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
| `container_context` | Reject remote runtimes, resolve a local Docker or Podman container to its init PID, and bound runtime command time and output. |
| `process_context` | Inspect a selected PID, enter differing Linux mount/network namespaces and root before runtime startup, and capture only supported proxy variables. |
| `target` | Parse supported input forms into a normalized scheme, host, port, optional URL, and complete literal socket address (including an IPv6 scope ID). |
| `probe::dns` | Resolve with the process's system resolver and apply the requested address-family filter. |
| `probe::route` | Run the native platform route lookup for each destination and extract the route fields it exposes. |
| `probe::tcp` | Connect to all resolved socket addresses concurrently with independent timeouts. |
| `probe::application` | Try TCP-successful addresses in latency order until the application protocol is reachable, validating TLS when required and issuing an HTTP `HEAD`. |
| `diagnosis` | Apply explicit precedence rules and separate observed failures from likely causes. |
| `output` | Render the report without changing its meaning. |

## Ordering and continuation

- DNS must produce at least one usable address before route or TCP probes can run.
- Route inspection and TCP connection are independent evidence. A failed or skipped route command does not suppress a real connection attempt.
- All resolved addresses are tested concurrently to expose asymmetric IPv4/IPv6 behavior.
- The application probe starts with the fastest address that completed TCP successfully. If that address fails during its fresh connection, TLS, or HTTP exchange, NetWhy tries the next TCP-successful address and retains every attempt.
- TLS and HTTP use a fresh connection. This avoids transferring ownership of probe sockets and makes timing for each stage explicit.
- A valid HTTP status line proves application-protocol reachability. A 4xx or 5xx is a warning, not a network failure.

## Timeouts

`--timeout-ms` applies independently to:

- system DNS resolution;
- each native route inspection;
- each TCP connection attempt;
- the application probe's fresh TCP connection;
- the TLS handshake;
- the HTTP request/first response line exchange.
- each Docker or Podman locality check and container inspection.

DNS uses the system resolver, bounded by the requested operation timeout. Resolver-internal behavior remains platform dependent.

The system resolver may run `getaddrinfo` on a non-cancellable blocking thread. The CLI owns its
async runtime and performs a non-waiting shutdown after emitting the completed report, so an
abandoned resolver task cannot extend the process lifetime beyond the operation timeout.

## Platform route backends

Linux executes `ip -j route get <DESTINATION>` and parses iproute2 JSON for interface, gateway, and preferred source. Apple Silicon macOS executes `/sbin/route -n get -inet <DESTINATION>` or `/sbin/route -n get -inet6 <DESTINATION>` and parses the native text output for interface and gateway; that command does not expose a preferred source in the same form, so `source` remains absent. Both backends share the same shell-free execution, process-group termination, deadline, output cap, sanitization, and graceful-skip behavior.

## Process and container execution contexts

Without an execution-context option, every probe uses NetWhy's current process context on Linux or macOS. On Linux, `--pid <PID>` selects a process directly. `--docker <CONTAINER>` and `--podman <CONTAINER>` first use the corresponding runtime CLI to resolve a running container's init PID, then follow the same process-context path. The three selectors are mutually exclusive. Apple Silicon macOS accepts the stable CLI grammar but rejects all three selectors with a structured `CONTEXT_UNAVAILABLE` error because Docker Desktop and Podman container PIDs belong to a Linux virtual machine and cannot be interpreted through the macOS host.

Container selection fails closed for remote runtimes. Docker must resolve to a local `unix://` endpoint, whether selected by `DOCKER_HOST` or a Docker context, and Podman must report a non-remote service. Remote container PIDs cannot be interpreted against the local host's `/proc`. Runtime invocations do not use a shell, terminate option parsing before the user-provided container identifier, run in isolated process groups, cap each output stream at 64 KiB, and enforce `--timeout-ms` across process execution and output capture. After the target `/proc` handles have been pinned, NetWhy resolves the container PID again and rejects a concurrent restart.

An isolated rootless Podman container's namespaces are owned from Podman's user namespace. `podman unshare netwhy --podman <CONTAINER> <TARGET>` launches NetWhy with the matching subordinate UID/GID mappings and namespace-local capabilities. A direct invocation outside that user namespace fails safely with `CONTEXT_UNAVAILABLE` when the kernel rejects `setns`.

For every selected PID, startup remains single-threaded while NetWhy:

1. pins the current and selected `/proc` process directories, then opens file descriptors for both network namespaces, mount namespaces, and filesystem roots relative to those directories;
2. compares namespace and root device/inode identities so shared contexts do not require privileged operations;
3. reads `/proc/<PID>/environ` and immediately retains only recognized proxy variables;
4. enters a differing mount namespace, changes to the selected root, and then enters a differing network namespace;
5. creates the Tokio runtime only after all one-way context changes succeed.

Pinning the selected process directory prevents PID exit/reuse from mixing descriptors from different process incarnations. All context descriptors are opened before the first context change, so later path resolution cannot accidentally switch back to the caller's mount tree. The root transition uses `fchdir`, `chroot`, and `chdir("/")` to avoid retaining a working-directory escape. A differing mount or network namespace requires `CAP_SYS_ADMIN`; a differing root requires `CAP_SYS_CHROOT`. Missing PIDs, inaccessible namespace descriptors, and failed context changes produce the structured `CONTEXT_UNAVAILABLE` invocation error. An unreadable proxy environment is non-fatal and is recorded as unavailable in the completed report.

The selected root makes the system resolver consume that process context's resolver files, while the selected network namespace controls routes and sockets. NetWhy changes only its own one-shot CLI process and never writes to or attaches to the target process.

## TLS behavior

- Trust roots come from Mozilla's root program through `webpki-roots`.
- SNI and certificate-name validation use the original hostname, even when connecting to a selected IP address.
- ALPN requests HTTP/1.1 because v0.1 parses a textual HTTP status line.
- Certificate details beyond the validation result are deferred.

This means NetWhy may differ from applications using a private enterprise trust store. Every TLS attempt records `trust_source: "mozilla_webpki_roots"` so this implementation choice is discoverable.

## Proxy behavior

NetWhy records recognized proxy environment variables from its current process or the process selected by `--pid`, but connects directly. Proxy URL credentials must be replaced with `<redacted>` before entering the report model. Both output formats include a note explaining that the probes bypassed the proxy.

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

In JSON mode, stdout contains exactly one document. Completed diagnostics conform to `report.schema.json`; invocation, target, and execution-context errors conform to `error.schema.json`. Human usage errors use stderr. The full compatibility rules are specified in [output-contract.md](output-contract.md).

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
- No shell is used to invoke the Linux or macOS route utility, Docker, or Podman; arguments are passed directly to the executable. Helper processes run in isolated process groups, are terminated as a group at the deadline, and retain no more than 64 KiB per output stream.
- Target input is parsed before it reaches an HTTP request.
- Invalid target diagnostics escape terminal control characters before entering either output format.
- Proxy credentials are redacted in memory before serialization.
- Target URL userinfo is rejected. Query strings and fragments are replaced with `REDACTED` in reports while the original query remains available only to the in-memory request builder.
- HTTP status lines are limited to 8 KiB, require CRLF and valid HTTP/1.x syntax, and cannot contain control characters.
- DNS results are capped at 32 unique addresses; route and TCP fan-out is limited to eight concurrent operations.
- A selected process environment read is capped at 8 MiB; exceeding the cap is recorded as unavailable and does not suppress network probes.
- JSON does not include unrelated environment variables, resolver-file contents, firewall rules, or process lists. Process and container selection read only the resolved PID and retain only supported proxy variables.
- Future support bundles must make internal-address redaction configurable and visible.

## Testing strategy

- Pure unit tests for target interpretation and diagnosis precedence.
- Local TCP listeners for successful and refused transport behavior.
- Local HTTP listeners for status parsing.
- A local rustls server verifies trusted TLS and HTTPS behavior without a public dependency.
- Route parsing tests use captured iproute2 JSON and macOS `route` output, not the test host's routing table.
- Native Apple Silicon CI verifies local diagnosis, the macOS route utility, structured rejection of Linux-only context selectors, release building, and package verification.
- JSON reports are validated against `docs/report.schema.json` in CI.
- Compiled-CLI tests cover validation, all output and exit-code contracts, address-family selection, HTTP/TLS outcomes, broken and unwritable stdout, and selected-process proxy redaction.
- Capability-aware Linux fixtures verify real entry into isolated mount, root, and network contexts and the structured denial path when the target namespace belongs to an unavailable user context. They skip only when unprivileged user namespaces are disabled by the host.
- Public internet checks are manually invoked smoke tests and never gate a release.
- `cargo-llvm-cov` enforces project-wide minimums of 90% lines, 90% regions, and 95% functions, plus an 80% line floor for every measured file. Coverage identifies untested behavior but does not replace assertions or justify artificial tests for unreachable serialization failures.
