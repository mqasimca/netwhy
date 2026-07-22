# Output contract

NetWhy has two presentation modes built from the same diagnostic report. Human output is optimized for terminal reading and incident logs. JSON output is optimized for programs and AI agents. Neither format changes the diagnosis or exit code.

## Human output

The default format is plain text with no ANSI color, so it remains readable when copied into a ticket, prompt, log, or terminal with limited capabilities.

Information appears in decision order:

1. final result, target, and concise summary;
2. likely cause, explicitly labeled as an inference;
3. numbered next steps;
4. observed evidence from DNS, route, TCP, proxy, TLS, HTTP, Linux path collectors, and plugins;
5. context notes and total duration.

Every evidence line starts with a textual status such as `[PASS]`, `[WARN]`, `[FAIL]`, or `[SKIP]`. Meaning never depends on color or a Unicode symbol.

Human invocation errors are written to stderr and exit with code 2. Successful diagnostic output and target failures are written to stdout because both are complete reports.

## JSON output

`--json` writes exactly one JSON value to stdout and does not mix prose into that stream. A completed probe conforms to [report.schema.json](report.schema.json). `netwhy compare --json` conforms to [compare.schema.json](compare.schema.json). An invalid invocation or target conforms to [error.schema.json](error.schema.json).

All JSON documents contain:

- `schema_version`: version of that document's schema;
- `kind`: `diagnostic_report`, `comparison_report`, or `error`;
- `tool`: producer name and version;
- `overall`: final status;
- `exit_code`: the process exit code represented by the document.

A diagnostic report also contains `request` with the effective timeout, address-family selection, direct or proxy application transport, proxy selection mode, redaction policy, and execution context. `request.execution_context.source` is `current_process`, `process`, `docker`, or `podman`. Selected contexts include `target_pid`; Docker and Podman contexts also include `target_container`. The object records whether the network namespace, mount namespace, and root were shared or entered, where proxy variables came from, and which Linux capabilities were needed.

Application evidence is emitted as `application_attempts`, ordered by probe preference. Failed attempts remain visible when a later address succeeds. Every attempt separates its fresh TCP `connect` evidence from optional TLS and HTTP evidence.

`proxy_transport` identifies direct, environment-selected, or active proxy transport, whether `NO_PROXY` bypassed environment selection, the credential-redacted selected URL, ordered proxy endpoint attempts, and any HTTP `CONNECT` status. `path_evidence` contains the five stable Linux collector sections: `firewall`, `mtu`, `address_preference`, `resolver`, and `network_manager`. Unsupported platforms and missing optional tools retain those sections with `skip` status. `plugins` preserves command-line order and embeds each plugin's versioned result.

Successful TLS evidence includes the negotiated version and cipher plus a bounded description of the presented peer certificates: DER size, SHA-256 fingerprint, identity, issuer, serial, validity interval, and subject alternative names. This is observed certificate metadata, not a replacement for the handshake's validation result.

Stable `error_kind` values let agents classify evidence without parsing prose:

- DNS: `address_family_mismatch`, `resolver_error`, `timeout`, or `no_addresses`;
- route: `tool_missing`, `tool_failed`, `parse_error`, `timeout`, or `no_route`;
- TCP and application reconnects: `connection_refused`, `connection_reset`, `connection_aborted`, `not_connected`, `address_in_use`, `address_unavailable`, `timeout`, `permission_denied`, `network_unreachable`, `host_unreachable`, or `other`.
- proxy preparation additionally uses `not_configured`, `invalid_config`, `resolver_error`, or `no_addresses`; plugin isolation uses `tool_missing`, `tool_failed`, `timeout`, `output_truncated`, or `protocol_error`.

| Code | Meaning |
| --- | --- |
| `CONNECTIVITY_OK` | Every applicable requested layer succeeded. |
| `DNS_RESOLUTION_FAILED` | No usable destination address was resolved. |
| `TCP_CONNECTION_REFUSED` | The host rejected the TCP connection. |
| `NO_ROUTE` | Routing evidence and connection attempts show no usable path. |
| `TCP_TIMEOUT` | Every TCP attempt exceeded its deadline. |
| `TCP_CONNECT_FAILED` | TCP failed without a more specific classification. |
| `ADDRESS_FAMILY_PARTIAL` | One resolved IP family works and the other fails. |
| `APPLICATION_ADDRESS_PARTIAL` | The application protocol failed on one address before succeeding on another. |
| `APPLICATION_CONNECT_FAILED` | Initial TCP probing worked, but every fresh application connection failed. |
| `PROXY_CONNECTION_FAILED` | The selected proxy could not be prepared, reached, authenticated, or used for the required tunnel. |
| `TLS_HANDSHAKE_FAILED` | TCP worked but TLS did not. |
| `HTTP_EXCHANGE_FAILED` | Transport worked but no valid HTTP response arrived. |
| `HTTP_ERROR_STATUS` | The server returned HTTP 4xx or 5xx; connectivity still works. |

Error documents use stable `error.code` values:

| Code | Meaning |
| --- | --- |
| `INVALID_INVOCATION` | Command-line arguments are missing, unknown, conflicting, or invalid. |
| `INVALID_TARGET` | The target syntax or scheme is unsupported. |
| `CONTEXT_UNAVAILABLE` | The selected process or container disappeared, its context could not be inspected, its runtime was remote, required namespace/root capabilities were unavailable, or a Linux-only context selector was requested on macOS. |
| `OUTPUT_ERROR` | NetWhy could not write or serialize its result. |

Messages, summaries, hints, and suggestions are for display and may improve within a schema version. Consumers must branch on codes and statuses, not English text.

## Shareable reports and redaction

`netwhy report <TARGET>` always emits diagnostic JSON. `--redaction standard` is the default and applies the normal credential and target query/fragment protections. `--redaction strict` additionally pseudonymizes internal hosts, socket addresses, interfaces, process/container identity, proxy values, firewall/resolver/NetworkManager identities, and certificate identity. It replaces plugin payloads and free-form errors. The selected policy is explicit at `request.redaction`.

Strict pseudonyms are deterministic within and across reports so two reports can still be compared, but they are not cryptographic anonymization and must not be treated as permission to publish arbitrary reports. IPv4 and IPv6 replacements use documentation-only ranges. Ports, protocol status, timing, MTU values, and diagnosis codes remain available because they are required to troubleshoot the path.

## Report comparison

`netwhy compare LEFT RIGHT` accepts regular diagnostic report files with structurally identifiable schema versions 1 through the current version and refuses inputs with a missing report envelope/identity, a future schema, invalid JSON, unreadable data, or more than 8 MiB. Reads are capped while data is consumed, so a file that grows is still bounded. It recursively compares objects in sorted-key order and arrays by index. Volatile generation time, producer version, and every per-stage `duration_ms` or `handshake_ms` field are ignored. At most 256 differences are emitted; `truncated` states whether more existed.

Each change uses a JSON Pointer `path`, the left and right JSON values, and `low`, `medium`, or `high` significance. Comparison differences are informational: both equal and different valid reports exit 0, with `pass` or `warn` respectively. Input or output errors exit 2.

## Schema compatibility

Diagnostic and error documents currently use schema version 2. Comparison and plugin documents use protocol/schema version 1. Within a schema version, fields declared required remain present and enum/code meanings remain stable. Adding required fields, removing fields, or changing field meaning requires a new schema version. Consumers should reject unsupported future versions and ignore prose for control flow.

Error documents include `error.retryable`. It is `true` only for `OUTPUT_ERROR`; invocation, target, and execution-context errors require corrected input, runtime selection, or permissions.

`--help` and `--version` are metadata commands and remain plain text even when `--json` is also present. All diagnostic runs and invocation errors honor JSON mode.

## Exit codes

| Code | JSON status | Meaning |
| --- | --- | --- |
| `0` | `pass` or `warn` | The target is reachable; inspect warnings for application or partial-family issues. |
| `1` | `fail` | Connectivity or the requested application protocol failed. |
| `2` | `fail` | The invocation or selected process context was invalid, or NetWhy could not produce its requested output. |

For completed reports, the process status and JSON `exit_code` must be identical. If stdout itself cannot be written, NetWhy makes a best-effort structured error on stderr because the requested output stream is unavailable.
