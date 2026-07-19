# Product definition

## Problem

When an application cannot connect on Linux or Apple Silicon macOS, users usually have to combine several commands and mentally correlate their output:

- resolver configuration and DNS answers;
- IPv4 and IPv6 routing decisions;
- VPN and tunnel interfaces;
- TCP refusal, timeout, and unreachable errors;
- TLS certificate, name, and protocol failures;
- HTTP response behavior;
- proxy configuration;
- container or process network namespaces.

Each individual tool can be correct while the overall conclusion remains unclear. The result is a slow, expertise-heavy debugging loop and support bundles full of unrelated state.

NetWhy's job is to answer one bounded question:

> From this execution context, why can or cannot I connect to this target?

## Initial users

- Developers diagnosing “works on my machine” failures.
- Linux and Apple Silicon macOS users affected by VPN, DNS, IPv6, or proxy problems.
- Operators performing first-response diagnosis on a server.
- Support engineers who need a small, redacted, machine-readable report.
- Automation that needs to distinguish DNS, route, transport, TLS, and HTTP failures.

## User promises

1. **A result in one command.** A normal diagnosis should not require users to select the underlying tools.
2. **A conclusion backed by evidence.** The report includes per-address results and the selected platform route.
3. **No automatic repair.** NetWhy may suggest commands, but v0.1 never changes the machine.
4. **Stable automation.** JSON is versioned and exit codes have documented meaning.
5. **Graceful degradation.** Missing optional capabilities produce `skip`, not a false failure.

## v0.1 acceptance criteria

The first release is complete when it can correctly report these cases:

- a reachable raw TCP socket;
- a successful public HTTPS endpoint;
- a hostname that cannot be resolved;
- a host that actively refuses the requested TCP port;
- a connection that exceeds the configured timeout;
- TCP success followed by TLS certificate or handshake failure;
- HTTP success and HTTP 4xx/5xx responses;
- dual-stack targets where only one address family works;
- missing iproute2 without losing TCP/TLS/HTTP results;
- valid, coded diagnostic JSON conforming to `docs/report.schema.json`;
- structured invocation and target errors conforming to `docs/error.schema.json`;
- outcome-first human output whose status does not depend on color;
- proxy URLs without exposing embedded credentials.
- target URL credentials rejected and target query/fragment values redacted from reports;
- bounded remote response parsing that cannot inject terminal control characters;
- multiple TCP-successful addresses retried until one application attempt is reachable.

Automated tests must use local listeners wherever possible. Public endpoints are smoke tests, not unit-test dependencies.

## Non-goals for v0.1

- Packet capture or payload inspection.
- Port scanning or host discovery.
- Throughput benchmarking.
- Continuous monitoring or alerting.
- Editing DNS, routes, firewall rules, VPNs, or certificates.
- Claiming that an HTTP status below 400 means the application is healthy.
- Reproducing an application's custom DNS or TLS stack.
- Entering another process or container network namespace.
- Sending requests through configured proxies.

## Diagnosis semantics

NetWhy identifies the earliest failed layer for which it has direct evidence:

1. **DNS failure:** no usable destination address exists.
2. **Route failure:** the kernel reports no route and TCP cannot connect.
3. **TCP refusal:** the destination is reachable but the port is not accepting connections.
4. **TCP timeout:** packets may be dropped by a firewall, broken path, or unreachable service.
5. **Application reconnect failure:** the initial TCP probe succeeds but every fresh application connection fails.
6. **TLS failure:** TCP succeeds but authenticated encryption cannot be established.
7. **HTTP failure:** transport succeeds but no valid HTTP status is received.
8. **HTTP error response:** connectivity succeeds, but the application returns 4xx or 5xx.
9. **Partial family or application-address failure:** one resolved family or endpoint works while another fails.

The wording must distinguish evidence from inference. For example, a timeout supports “traffic is probably being dropped” but cannot prove which firewall or hop is responsible.

## Roadmap

### v0.1 — Local connection explanation

- System DNS, kernel routes, concurrent TCP, TLS, HTTP.
- Deterministic diagnosis.
- Human and JSON output.
- IPv4/IPv6 filtering.

### v0.2 — Execution-context fidelity

- [x] `--pid <PID>` to diagnose inside a process's network and mount namespaces and filesystem root.
- [x] Local Docker and Podman target adapters with remote-runtime rejection and restart detection.
- [x] Resolver and proxy environment captured from the selected process.
- [x] Explicit privilege and capability reporting.
- [x] Capability-aware isolated mount/network namespace integration fixtures.
- [x] Apple Silicon macOS local diagnosis and native route backend.
- [ ] Release qualification across supported Linux and Apple Silicon macOS environments.

The checked items are implemented in the current development tree. They are not a published v0.2 release; the remaining gate is native qualification across the supported Linux and Apple Silicon macOS environments in the [v0.2 release checklist](v0.2-release-checklist.md).

### v0.3 — Deeper Linux path evidence

- nftables verdict tracing where permitted.
- MTU and IPv6 preference diagnostics.
- systemd-resolved detail and per-link DNS evidence.
- NetworkManager and VPN context.

### v0.4 — Comparison and support workflows

- `netwhy report` with configurable redaction.
- `netwhy compare host.json container.json`.
- Stable plugin interface for environment-specific evidence.
- Shell completions and distribution packages.

## Product risks

- **False certainty:** many timeouts have multiple possible causes. Output must label likely causes as inference.
- **Probe mismatch:** an application's resolver, proxy, or TLS configuration may differ from NetWhy's. Reports must state the context and transport used.
- **Sensitive output:** proxy credentials, internal hostnames, and addresses may be confidential. Credentials must be redacted by default.
- **Side effects at the target:** HTTP `HEAD` is defined as safe, but broken servers may mishandle it. The CLI must document that it performs active probes.
- **Platform scope creep:** Linux retains the full execution-context feature set. Apple Silicon macOS is deliberately limited to local diagnosis and native route evidence; other platforms remain unsupported.
