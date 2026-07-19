# NetWhy

NetWhy is a read-only Linux and Apple Silicon macOS CLI that explains why a network connection succeeds or fails.

Linux and macOS already provide excellent low-level tools for DNS, routes, sockets, TLS, and HTTP. The difficult part is correlating their output. NetWhy follows one connection through those layers and turns the evidence into a concise, deterministic diagnosis.

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

## Platform support

- **Linux:** full local diagnosis plus `--pid`, `--docker`, and `--podman` execution-context selection.
- **Apple Silicon macOS (`aarch64-apple-darwin`):** local DNS, native route, TCP, TLS, and HTTP diagnosis. Linux execution-context selectors return a structured `CONTEXT_UNAVAILABLE` error instead of being ignored.
- **Intel macOS and other operating systems:** unsupported.

## v0.1 scope

The first release diagnoses a target from the current Linux network namespace:

1. Resolve the hostname with the system resolver.
2. Ask the kernel which route, interface, gateway, and source address it selects.
3. Test every retained address over TCP with bounded concurrency.
4. For HTTPS, validate the TLS handshake and certificate using the requested hostname, retrying another TCP-successful address when necessary.
5. For HTTP or HTTPS, send a `HEAD` request and safely read a bounded response status line.
6. Explain the most likely failure and suggest focused follow-up checks.
7. Produce outcome-first human output or a versioned, coded JSON report.

The current development tree implements the v0.2 execution-context features on Linux and local diagnosis on Apple Silicon macOS. Cross-environment release qualification remains before v0.2 can be published. Firewall verdict tracing, MTU diagnosis, proxy execution, and report comparison remain deferred. See [the product roadmap](docs/product.md).

## Command contract

```text
netwhy [OPTIONS] <TARGET>

Arguments:
  <TARGET>  URL, hostname, IP address, or host:port

Options:
      --json                 Emit a versioned JSON report
      --pid <PID>            Diagnose from the network, mount, root, and proxy context of a Linux process
      --docker <CONTAINER>   Diagnose from a running container managed by a local Docker runtime (Linux only)
      --podman <CONTAINER>   Diagnose from a running container managed by a local Podman runtime (Linux only)
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
| `[fe80::1%3]:443` | Raw TCP on port 443 using IPv6 interface scope index 3 |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | The target is reachable. Warnings such as partial IPv6 failure or an HTTP error status may still be present. |
| `1` | Connectivity or the requested application protocol failed. |
| `2` | The invocation or selected execution context was invalid, or NetWhy itself could not produce a report. |

## Safety and network behavior

NetWhy does not mutate local configuration. It does perform active DNS, TCP, TLS, and optional HTTP `HEAD` probes, so it is not a passive observer.

The application probe connects directly. Proxy-related environment variables are reported with credentials redacted, but are not used to transport the probe. This distinction is displayed in both human and JSON output.

`--pid <PID>` selects another Linux process as the execution context. NetWhy opens the target context before changing its own process, enters a differing mount namespace and filesystem root before a differing network namespace, and only then creates the async runtime. Shared namespaces and roots require no capabilities. Entering a differing namespace requires `CAP_SYS_ADMIN`; entering a differing root requires `CAP_SYS_CHROOT`. NetWhy never attaches to or mutates the selected process. If its proxy environment cannot be read, the report records that limitation and continues with the selected resolver and network context.

`--docker <CONTAINER>` and `--podman <CONTAINER>` resolve a running container to its init PID through the corresponding CLI, then use the same pinned process-context path. These options are mutually exclusive with each other and with `--pid`. NetWhy accepts only a demonstrably local Unix-socket Docker context or a non-remote Podman service: a PID reported by a remote runtime belongs to another host and is unsafe to interpret through local `/proc`. Runtime commands are shell-free, time-bounded, and output-bounded. The container PID is checked again after its `/proc` context has been pinned so a concurrent restart fails cleanly instead of mixing contexts.

Rootless Podman owns its container namespaces from Podman's user namespace. Run NetWhy through `podman unshare` so it has the namespace-local capabilities needed to enter an isolated rootless container:

```bash
podman unshare netwhy --podman my-container https://example.com
```

Route inspection uses `ip -j route get` on Linux and `/sbin/route -n get` on Apple Silicon macOS. Linux reports the interface, gateway, and preferred source when available; macOS reports the interface and gateway exposed by its native route utility. Each helper invocation is time-bounded, runs in an isolated process group, and retains at most 64 KiB from each output stream. If the platform route utility is missing, NetWhy skips that evidence and continues with real TCP attempts.

Reports reject target URL credentials, redact target query strings and fragments, and record the effective timeout, address-family selection, application transport, execution context, required capabilities, and TLS trust source. DNS evidence is capped at 32 unique addresses to keep resource use predictable.

## Documentation

- [Product definition and roadmap](docs/product.md)
- [Technical design](docs/design.md)
- [Human and agent output contract](docs/output-contract.md)
- [JSON report schema](docs/report.schema.json)
- [JSON error schema](docs/error.schema.json)

## Development

NetWhy requires Rust 1.85 or newer. Stable Rust is recommended. Supported build targets are Linux and `aarch64-apple-darwin`; Intel macOS is intentionally unsupported.

```bash
cargo build
make test-unit        # library, binary, and CLI parser unit tests
make test-integration # in-process DNS/TCP/TLS/HTTP pipeline tests
make test-cli         # compiled CLI, schema, exit-code, and process-context tests
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

The network-backed RustSec advisory audit is enforced separately in CI and before tagged releases. Run it locally with `cargo audit --file Cargo.lock` after installing `cargo-audit`.

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
cargo run -- --json --pid "$PID" https://example.com
cargo run -- --json --docker my-container https://example.com
cargo run -- --json --podman my-container https://example.com
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

## Creating a release

Set the package version in `Cargo.toml`, update `Cargo.lock`, run `make verify`, and push the release commit. Then create and push a matching tag:

```bash
git tag -a v0.2.0 -m "NetWhy v0.2.0"
git push origin v0.2.0
```

The release workflow requires the tag to exactly match the package version. It runs the complete Linux release gate and native Apple Silicon tests before creating or updating the GitHub Release for that tag with these assets:

- `netwhy-v<VERSION>-x86_64-unknown-linux-gnu.tar.gz` and its SHA-256 checksum;
- `netwhy-v<VERSION>-aarch64-apple-darwin.tar.gz` and its SHA-256 checksum.

Each archive contains the release binary, `README.md`, and `LICENSE`. Rerunning the workflow replaces matching assets, while a prerelease package version such as `0.2.0-rc.1` creates a prerelease.

See the historical [v0.1 release checklist](docs/release-checklist.md) and the current [v0.2 release checklist](docs/v0.2-release-checklist.md) for the exact verification contracts.

## License

MIT
