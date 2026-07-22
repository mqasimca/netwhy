# NetWhy

NetWhy is a read-only Linux and Apple Silicon macOS CLI that explains why a network connection succeeds or fails.

Linux and macOS already provide excellent low-level tools for DNS, routes, sockets, TLS, and HTTP. The difficult part is correlating their output. NetWhy follows one connection through those layers and turns the evidence into a concise, deterministic diagnosis.

```text
$ netwhy https://api.example.com

NetWhy 0.2.0
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
> NetWhy is an unpublished development build. The feature roadmap through v0.4 is implemented in this tree, but native Ubuntu, Fedora/rootless Podman, and Apple Silicon qualification must still be completed before publication.

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

## Current scope

One run correlates the requested execution context and target across these layers:

1. Resolve the hostname with the system resolver.
2. Ask the kernel which route, interface, gateway, source address, MTU, and advertised MSS it selects.
3. Test every retained address over TCP with bounded concurrency.
4. Optionally connect through HTTP, HTTPS, SOCKS5, or SOCKS5H proxy transport.
5. For HTTPS, validate the TLS handshake and certificate using the requested hostname and record bounded peer-certificate metadata.
6. For HTTP or HTTPS, send a `HEAD` request and safely read a bounded response status line.
7. On Linux, collect read-only nftables, path-MTU, address-preference, systemd-resolved, NetworkManager, and VPN evidence when the relevant tools are available.
8. Incorporate explicitly selected, versioned evidence plugins.
9. Explain the most likely failure and suggest focused follow-up checks.
10. Produce outcome-first text, a shareable redacted report, or a structural comparison of two reports.

Linux supports current-process, PID, local Docker, and local Podman contexts. Apple Silicon macOS supports local DNS, route, TCP, TLS, and HTTP diagnosis; Linux-only path collectors and context selectors report a structured skip or error. See [the product roadmap](docs/product.md) for implementation and release-gate status.

## Command contract

```text
netwhy [OPTIONS] <TARGET>

Arguments:
  <TARGET>  URL, hostname, IP address, or host:port

Options:
      --json                    Emit a versioned JSON report
      --pid <PID>               Select a Linux process context
      --docker <CONTAINER>      Select a local Docker container context
      --podman <CONTAINER>      Select a local Podman container context
      --ipv4                    Test IPv4 only
      --ipv6                    Test IPv6 only
      --timeout-ms <MILLIS>     Per-operation timeout [default: 3000]
      --proxy-mode <MODE>       direct or environment [default: direct]
      --proxy-url <URL>         Explicit HTTP(S), SOCKS5, or SOCKS5H proxy
      --plugin <PROGRAM>        Evidence plugin; repeatable up to eight times

netwhy report [OPTIONS] <TARGET> [--redaction standard|strict]
netwhy compare [--json] <LEFT.json> <RIGHT.json>
netwhy completions <bash|elvish|fish|powershell|zsh>
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

NetWhy does not mutate local configuration. It performs active DNS, TCP, optional tracepath, TLS, and HTTP `HEAD` probes, so it is not a passive observer. nftables inspection is static and read-only; NetWhy does not install tracing rules or claim packet-perfect firewall attribution.

An explicitly selected evidence plugin is a separate executable and runs with NetWhy's operating-system privileges and execution context. Only use trusted plugins; NetWhy bounds their runtime and output but cannot make third-party code read-only.

Direct application transport remains the default even when proxy variables exist. `--proxy-mode environment` selects `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY` from the active execution context and honors exact host, domain suffix, port, IP, and CIDR `NO_PROXY` entries. `--proxy-url` selects an explicit proxy and takes precedence over environment selection. HTTP targets use absolute-form requests; HTTPS and raw TCP use HTTP `CONNECT`; HTTPS proxy URLs authenticate the proxy connection with TLS. SOCKS5 resolves the target locally, while SOCKS5H delegates target DNS to the proxy. `--ipv4` and `--ipv6` filter proxy endpoints and local SOCKS5 target DNS; a hostname with remote-resolving HTTP(S) or SOCKS5H transport is rejected when a family flag is set because the requested family cannot be guaranteed. Embedded HTTP Basic and SOCKS username/password credentials are supported and never serialized.

`--pid <PID>` selects another Linux process as the execution context. NetWhy opens the target context before changing its own process, enters a differing mount namespace and filesystem root before a differing network namespace, and only then creates the async runtime. Shared namespaces and roots require no capabilities. Entering a differing namespace requires `CAP_SYS_ADMIN`; entering a differing root requires `CAP_SYS_CHROOT`. NetWhy never attaches to or mutates the selected process. If its proxy environment cannot be read, the report records that limitation and continues with the selected resolver and network context.

`--docker <CONTAINER>` and `--podman <CONTAINER>` resolve a running container to its init PID through the corresponding CLI, then use the same pinned process-context path. These options are mutually exclusive with each other and with `--pid`. NetWhy accepts only a demonstrably local Unix-socket Docker context or a non-remote Podman service: a PID reported by a remote runtime belongs to another host and is unsafe to interpret through local `/proc`. Runtime commands are shell-free, time-bounded, and output-bounded. The container PID is checked again after its `/proc` context has been pinned so a concurrent restart fails cleanly instead of mixing contexts.

Rootless Podman owns its container namespaces from Podman's user namespace. Run NetWhy through `podman unshare` so it has the namespace-local capabilities needed to enter an isolated rootless container:

```bash
podman unshare netwhy --podman my-container https://example.com
```

Route inspection uses `ip -j route get` on Linux and `/sbin/route -n get` on Apple Silicon macOS. Linux additionally uses bounded `nft`, `tracepath`, `resolvectl`, and `nmcli` commands when installed. Every helper is shell-free, time-bounded, runs in an isolated process group, and has bounded output. Missing tools produce explicit `skip` evidence without suppressing network probes.

Reports reject target URL credentials, redact target query strings and fragments, and record the effective timeout, address-family selection, application transport, execution context, required capabilities, and TLS trust source. `netwhy report --redaction strict` additionally applies deterministic pseudonyms to target, address, interface, process/container, certificate-identity, resolver, firewall, and plugin fields. DNS evidence is capped at 32 unique addresses to keep resource use predictable.

## Documentation

- [Product definition and roadmap](docs/product.md)
- [Technical design](docs/design.md)
- [Human and agent output contract](docs/output-contract.md)
- [JSON report schema](docs/report.schema.json)
- [JSON error schema](docs/error.schema.json)
- [JSON comparison schema](docs/compare.schema.json)
- [Evidence plugin protocol](docs/plugin-protocol.md)
- [Evidence plugin schema](docs/plugin.schema.json)

## Development

NetWhy requires Rust 1.85 or newer. Stable Rust is recommended. Supported build targets are Linux and `aarch64-apple-darwin`; Intel macOS is intentionally unsupported.

```bash
cargo build
make test-unit        # library, binary, and CLI parser unit tests
make test-integration # in-process direct/proxy DNS/TCP/TLS/HTTP pipeline tests
make test-cli         # compiled commands, schemas, plugins, exit codes, and contexts
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

`make verify` runs `make check`, enforces coverage, tests with Rust 1.85, builds and verifies the Cargo package, validates Debian/RPM/Homebrew packaging templates, and exercises staged installation, `--help`, `--version`, and uninstallation. It requires the Rust 1.85 toolchain and `cargo-llvm-cov`; it does not require a public network service.

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
cargo run -- --proxy-mode environment https://example.com
cargo run -- report --redaction strict https://example.com
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

Tagged Linux releases also build Debian and RPM packages; Apple Silicon releases include a generated Homebrew formula. `make test-packaging` validates normal and prerelease template substitution without requiring package-builder tools.

Generate a completion file with, for example, `netwhy completions zsh` or `netwhy completions bash`. Install the output using the completion directory documented by your shell or package manager.

## Creating a release

Set the package version in `Cargo.toml`, update `Cargo.lock`, run `make verify`, and push the release commit. Then create and push a matching tag:

```bash
git tag -a v0.2.0 -m "NetWhy v0.2.0"
git push origin v0.2.0
```

The release workflow requires the tag to exactly match the package version. It runs the complete Linux release gate and native Apple Silicon tests before creating or updating the GitHub Release for that tag with these assets:

- `netwhy-v<VERSION>-x86_64-unknown-linux-gnu.tar.gz` and its SHA-256 checksum;
- `netwhy-v<VERSION>-aarch64-apple-darwin.tar.gz` and its SHA-256 checksum;
- an amd64 Debian package, x86_64 RPM, and package checksum file;
- `netwhy.rb`, a Homebrew formula for the Apple Silicon archive.

Each archive contains the release binary, `README.md`, and `LICENSE`. Rerunning the workflow replaces matching assets, while a prerelease package version such as `0.2.0-rc.1` creates a prerelease.

See the historical [v0.1 release checklist](docs/release-checklist.md) and the current [v0.2 release checklist](docs/v0.2-release-checklist.md) for the exact verification contracts.

## License

MIT
