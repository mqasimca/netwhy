# Evidence plugin protocol

NetWhy plugins add environment-specific observations without changing the core diagnostic pipeline. A plugin is never auto-discovered: the user must select each executable with `--plugin <PROGRAM>`, up to eight per run.

Plugins are trusted native executables, not a sandbox. They inherit NetWhy's operating-system privileges and selected execution context and can perform arbitrary side effects. Select only code you trust; the protocol bounds execution and output but does not enforce read-only behavior inside a plugin.

## Invocation

NetWhy executes the program directly, without a shell:

```text
PROGRAM netwhy-probe \
  --protocol-version 1 \
  --scheme <tcp|http|https> \
  --host <normalized-host> \
  --port <1-65535> \
  --timeout-ms <operation-timeout>
```

The plugin should treat every argument as untrusted input. The host does not contain target URL userinfo, query, or fragment data. NetWhy does not pass its environment report, proxy credentials, resolved addresses, or other collected evidence to the plugin.

Each plugin receives the configured per-operation deadline. stdout and stderr are drained concurrently and capped at 256 KiB each. The process runs in an isolated process group; NetWhy terminates the group on timeout. Plugins execute concurrently, while report order remains the same as command-line order.

## Successful response

Exit 0 after writing exactly one UTF-8 JSON object to stdout. The document must conform to [plugin.schema.json](plugin.schema.json):

```json
{
  "protocol_version": 1,
  "name": "cloud-route",
  "status": "warn",
  "summary": "The target region differs from the active account region.",
  "evidence": {
    "active_region": "ca-central-1"
  }
}
```

Required fields:

- `protocol_version`: integer `1`;
- `name`: non-whitespace string of at most 128 Unicode characters;
- `status`: `pass`, `warn`, `fail`, or `skip`;
- `summary`: string of at most 4096 Unicode characters.

`evidence` is optional and defaults to `{}`. `error_kind` and `error` are optional plugin-defined strings. Unknown top-level fields are rejected. All nested strings are sanitized before they enter terminal or JSON output.

Plugin `warn` and `fail` statuses are retained as evidence and added to diagnosis notes; they do not override NetWhy's core connectivity exit code. This keeps third-party policy from silently changing the stable network diagnosis.

## Failure isolation

A missing executable, unsuccessful exit, timeout, oversized output, malformed JSON, unknown field, unsupported version, or invalid status becomes a `skip` plugin result. Other plugins and all built-in probes continue. NetWhy uses one of these host-defined `error_kind` values:

- `tool_missing`
- `tool_failed`
- `timeout`
- `output_truncated`
- `protocol_error`

On unsuccessful exit, bounded stderr supplies the sanitized error detail. Plugins must not write secrets to either output stream: standard reports preserve plugin evidence and errors. Use `netwhy report --redaction strict` when sharing a report; strict mode replaces plugin identity, summary, payload, error kind, and error text.

## Compatibility

Protocol version 1 is strict. A future incompatible invocation or response changes `--protocol-version` and `protocol_version` together. Plugins should reject versions they do not implement and should not infer compatibility from the NetWhy package version.
