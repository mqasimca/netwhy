# NetWhy

NetWhy is a read-only Linux CLI that explains why a network connection succeeds or fails.

Linux already provides excellent low-level tools for DNS, routes, sockets, TLS, and HTTP. The difficult part is correlating their output. NetWhy follows one connection through those layers and turns the evidence into a concise, deterministic diagnosis.

```text
$ netwhy https://api.example.com

NetWhy 0.1.0
Result: FAIL
Target: https://api.example.com:443
Summary: TCP connects, but the TLS handshake fails.
Likely cause: the certificate name does not match the requested hostname

Next steps:
  1. Check the certificate name, trust chain, system clock, SNI, and supported TLS versions.

Evidence:
  [PASS] DNS   2 addresses in 8 ms
  [PASS] ROUTE 203.0.113.10 · dev enp5s0 · via 192.168.1.1
  [PASS] TCP   203.0.113.10:443 · 24 ms · connected
  [FAIL] TLS   203.0.113.10:443 · certificate is not valid for api.example.com
```

> [!IMPORTANT]
> NetWhy is an unpublished v0.1 development build. The documented v0.1 interface is implemented and tested locally, but no release has been published.

## Principles

- **Explain, do not merely dump:** gather evidence and identify the first failing layer.
- **Read-only locally:** never rewrite routes, firewall rules, resolver settings, or application configuration.
- **Deterministic:** diagnoses come from explicit rules and remain suitable for scripts and incident reports.
- **Useful without root:** basic diagnosis must work as a normal user; privileged features must degrade gracefully.
- **Evidence before advice:** show the observations supporting every conclusion.
- **Privacy-aware:** redact credentials and avoid collecting unrelated system state.

## v0.1 scope

The first release diagnoses a target from the current Linux network namespace:

1. Resolve the hostname with the system resolver.
2. Ask the kernel which route, interface, gateway, and source address it selects.
3. Test every retained address over TCP with bounded concurrency.
4. For HTTPS, validate the TLS handshake and certificate using the requested hostname, retrying another TCP-successful address when necessary.
5. For HTTP or HTTPS, send a `HEAD` request and safely read a bounded response status line.
6. Explain the most likely failure and suggest focused follow-up checks.
7. Produce outcome-first human output or a versioned, coded JSON report.

Container namespaces, firewall verdict tracing, MTU diagnosis, proxy execution, and report comparison are deliberately deferred. See [the product roadmap](docs/product.md).

## Command contract

```text
netwhy [OPTIONS] <TARGET>

Arguments:
  <TARGET>  URL, hostname, IP address, or host:port

Options:
      --json                 Emit a versioned JSON report
      --ipv4                 Test IPv4 addresses only
      --ipv6                 Test IPv6 addresses only
      --timeout-ms <MILLIS>  Per-operation DNS, route, TCP, TLS, and HTTP timeout [default: 3000]
  -h, --help                 Print help
  -V, --version              Print version
```

Target interpretation is intentionally predictable:

| Input | Interpretation |
| --- | --- |
| `https://example.com/health` | HTTPS on the URL's port, defaulting to 443 |
| `http://example.com` | HTTP on the URL's port, defaulting to 80 |
| `example.com` | HTTPS on port 443 |
| `example.com:5432` | Raw TCP on port 5432 |
| `192.0.2.10` | HTTPS on port 443 |
| `[2001:db8::10]:443` | Raw TCP on port 443 |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | The target is reachable. Warnings such as partial IPv6 failure or an HTTP error status may still be present. |
| `1` | Connectivity or the requested application protocol failed. |
| `2` | The invocation was invalid or NetWhy itself could not produce a report. |

## Safety and network behavior

NetWhy does not mutate local configuration. It does perform active DNS, TCP, TLS, and optional HTTP `HEAD` probes, so it is not a passive observer.

The v0.1 application probe connects directly. Proxy-related environment variables are reported with credentials redacted, but are not used to transport the probe. This distinction is displayed in both human and JSON output.

Route inspection uses `ip -j route get` when iproute2 is available. If it is missing, NetWhy skips that evidence and continues with real TCP attempts.

Reports reject target URL credentials, redact target query strings and fragments, and record the effective timeout, address-family selection, application transport, and TLS trust source. DNS evidence is capped at 32 unique addresses to keep resource use predictable.

## Documentation

- [Product definition and roadmap](docs/product.md)
- [Technical design](docs/design.md)
- [Human and agent output contract](docs/output-contract.md)
- [JSON report schema](docs/report.schema.json)
- [JSON error schema](docs/error.schema.json)

## Development

NetWhy requires Rust 1.85 or newer. Stable Rust is recommended.

```bash
cargo build
make test-unit        # library, binary, and CLI parser unit tests
make test-integration # in-process DNS/TCP/TLS/HTTP pipeline tests
make test-cli         # compiled netwhy process, output, schema, and exit-code tests
make test             # the complete automated Rust test suite
```

Run formatting, the complete test suite, and strict Clippy checks with:

```bash
make check
```

The complete offline release gate is one command:

```bash
make verify
```

`make verify` runs `make check`, enforces coverage, tests with Rust 1.85, builds and verifies the Cargo package, and exercises staged installation, `--help`, `--version`, and uninstallation. It requires the Rust 1.85 toolchain and `cargo-llvm-cov`; it does not require a public network service.

Measure coverage with `cargo-llvm-cov`. The checked target requires at least 90% line coverage, 90% region coverage, and 95% function coverage:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
make coverage
```

Generate a browsable report under `target/llvm-cov/html` with `make coverage-html`.

Live smoke tests remain optional because they depend on the current network:

```bash
cargo run -- https://example.com
cargo run -- --json does-not-exist.invalid
```

## Local installation and packaging

Install directly from the working tree with Cargo:

```bash
cargo install --path . --locked
```

Or install the verified release binary under `~/.local/bin`:

```bash
make install
```

`PREFIX` and `DESTDIR` are supported for staged or system packaging:

```bash
make install DESTDIR=/tmp/netwhy-package PREFIX=/usr
make uninstall DESTDIR=/tmp/netwhy-package PREFIX=/usr
```

Build a local Cargo package without requiring a commit:

```bash
make package
```

See the [v0.1 release checklist](docs/release-checklist.md) for the exact verification contract.

## License

MIT
