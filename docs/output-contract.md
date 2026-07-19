# Output contract

NetWhy has two presentation modes built from the same diagnostic report. Human output is optimized for terminal reading and incident logs. JSON output is optimized for programs and AI agents. Neither format changes the diagnosis or exit code.

## Human output

The default format is plain text with no ANSI color, so it remains readable when copied into a ticket, prompt, log, or terminal with limited capabilities.

Information appears in decision order:

1. final result, target, and concise summary;
2. likely cause, explicitly labeled as an inference;
3. numbered next steps;
4. observed evidence from DNS, route, TCP, TLS, and HTTP;
5. context notes and total duration.

Every evidence line starts with a textual status such as `[PASS]`, `[WARN]`, `[FAIL]`, or `[SKIP]`. Meaning never depends on color or a Unicode symbol.

Human invocation errors are written to stderr and exit with code 2. Successful diagnostic output and target failures are written to stdout because both are complete reports.

## JSON output

`--json` writes exactly one JSON value to stdout and does not mix prose into that stream. A completed probe conforms to [report.schema.json](report.schema.json). An invalid invocation or target conforms to [error.schema.json](error.schema.json).

All JSON documents contain:

- `schema_version`: version of that document's schema;
- `kind`: `diagnostic_report` or `error`;
- `tool`: producer name and version;
- `overall`: final status;
- `exit_code`: the process exit code represented by the document.

A diagnostic report also contains `request` with the effective timeout, address-family selection, direct transport, proxy behavior, and execution context. `request.execution_context.source` is `current_process`, `process`, `docker`, or `podman`. Selected contexts include `target_pid`; Docker and Podman contexts also include `target_container`. The object records whether the network namespace, mount namespace, and root were shared or entered, where proxy variables came from, and which Linux capabilities were needed. Its `diagnosis.code` is a stable programmatic classification. v0.1 defines:

Application evidence is emitted as `application_attempts`, ordered by probe preference. Failed attempts remain visible when a later address succeeds. Every attempt separates its fresh TCP `connect` evidence from optional TLS and HTTP evidence.

Stable `error_kind` values let agents classify evidence without parsing prose:

- DNS: `address_family_mismatch`, `resolver_error`, `timeout`, or `no_addresses`;
- route: `tool_missing`, `tool_failed`, `parse_error`, `timeout`, or `no_route`;
- TCP and application reconnects: `connection_refused`, `connection_reset`, `connection_aborted`, `not_connected`, `address_in_use`, `address_unavailable`, `timeout`, `permission_denied`, `network_unreachable`, `host_unreachable`, or `other`.

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
| `TLS_HANDSHAKE_FAILED` | TCP worked but TLS did not. |
| `HTTP_EXCHANGE_FAILED` | Transport worked but no valid HTTP response arrived. |
| `HTTP_ERROR_STATUS` | The server returned HTTP 4xx or 5xx; connectivity still works. |

Error documents use stable `error.code` values:

| Code | Meaning |
| --- | --- |
| `INVALID_INVOCATION` | Command-line arguments are missing, unknown, conflicting, or invalid. |
| `INVALID_TARGET` | The target syntax or scheme is unsupported. |
| `CONTEXT_UNAVAILABLE` | The selected process or container disappeared, its context could not be inspected, its runtime was remote, or required namespace/root capabilities were unavailable. |
| `OUTPUT_ERROR` | NetWhy could not write or serialize its result. |

Messages, summaries, hints, and suggestions are for display and may improve within a schema version. Consumers must branch on codes and statuses, not English text.

Error documents include `error.retryable`. It is `true` only for `OUTPUT_ERROR`; invocation, target, and execution-context errors require corrected input, runtime selection, or permissions.

`--help` and `--version` are metadata commands and remain plain text even when `--json` is also present. All diagnostic runs and invocation errors honor JSON mode.

## Exit codes

| Code | JSON status | Meaning |
| --- | --- | --- |
| `0` | `pass` or `warn` | The target is reachable; inspect warnings for application or partial-family issues. |
| `1` | `fail` | Connectivity or the requested application protocol failed. |
| `2` | `fail` | The invocation or selected process context was invalid, or NetWhy could not produce its requested output. |

For completed reports, the process status and JSON `exit_code` must be identical. If stdout itself cannot be written, NetWhy makes a best-effort structured error on stderr because the requested output stream is unavailable.
