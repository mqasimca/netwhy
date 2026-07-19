# v0.1 release checklist

This checklist turns the acceptance criteria in [product.md](product.md) into executable release gates. All checks must run locally and must not require a public network service.

Run the complete gate from the repository root:

```bash
make verify
```

For focused development, use `make test-unit`, `make test-integration`, or `make test-cli`. `make test` runs all three layers in one Cargo invocation.

## Behavior

- [x] Reachable raw TCP socket reports `pass` and exits 0.
- [x] Refused TCP socket is distinguished from timeout and exits 1.
- [x] TCP timeout evidence produces a timeout diagnosis.
- [x] Successful HTTP response is parsed.
- [x] HTTP 4xx/5xx proves reachability, reports `warn`, and exits 0.
- [x] HTTP response timeout honors `--timeout-ms`.
- [x] DNS and route-helper timeouts honor `--timeout-ms`.
- [x] HTTP status lines are size-limited, CRLF-validated, and control-character safe.
- [x] Informational HTTP responses are followed to the final status.
- [x] Application probing retries another TCP-successful address and retains every attempt.
- [x] Trusted TLS handshake and HTTPS request succeed against a local rustls server.
- [x] TLS-layer failure after TCP success is diagnosed separately.
- [x] IPv4 success with IPv6 failure produces a family-asymmetry warning.
- [x] An explicit address-family mismatch fails at the DNS/address stage.
- [x] Missing iproute2 produces `skip` while a real TCP success remains `pass`.
- [x] Proxy credentials are redacted before reaching report serialization.
- [x] Proxy redaction handles `@` in paths, queries, and fragments.
- [x] Target URL credentials are rejected and target query/fragment values are redacted in reports.
- [x] IPv4, IPv6, URL, hostname, and host-port target forms are parsed.
- [x] Port zero and unsupported schemes are rejected.

## Contracts

- [x] Every integration report validates against `report.schema.json`.
- [x] Exit codes 0, 1, and 2 are exercised through the compiled CLI.
- [x] Human-readable and JSON output are exercised locally.
- [x] Human output is outcome-first and uses text status labels without relying on color.
- [x] JSON reports expose stable diagnosis codes and their represented exit code.
- [x] JSON invocation and target errors validate against `error.schema.json` without stderr noise.
- [x] JSON schema rejects contradictory top-level status, diagnosis, and exit-code combinations.
- [x] JSON reports include effective request options and TLS trust source.
- [x] Route parsing uses captured iproute2 JSON.
- [x] Rust 1.85 minimum-version build passes.
- [x] Stable formatting, tests, and Clippy with denied warnings pass.
- [x] LLVM coverage exceeds 90% lines, 90% regions, and 95% functions.
- [x] Every measured source file exceeds 80% line coverage.
- [x] Release binary builds with the locked dependency graph.
- [x] Cargo package contents and build verification pass.
- [x] Staged install and uninstall work without modifying the user's real prefix.

## Release boundary

The following remain later-version work and do not block v0.1:

- process and container network namespaces;
- proxy-transport probing;
- nftables verdict tracing;
- active MTU diagnosis;
- report comparison;
- distribution-specific packages and public release automation.
