use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use serde_json::Value;
use tokio::task::JoinSet;

use crate::{
    command::{BoundedCommandError, run_bounded},
    model::{PLUGIN_SCHEMA_VERSION, PluginResult, Status},
    sanitize_report_text,
    target::Target,
};

const MAX_PLUGINS: usize = 8;
const MAX_PLUGIN_OUTPUT: usize = 256 * 1024;
const MAX_PLUGIN_NAME_CHARS: usize = 128;
const MAX_PLUGIN_SUMMARY_CHARS: usize = 4 * 1024;

pub(crate) fn validate_programs(programs: &[PathBuf]) -> anyhow::Result<()> {
    if programs.len() > MAX_PLUGINS {
        anyhow::bail!("at most {MAX_PLUGINS} --plugin options may be used");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginDocument {
    protocol_version: u8,
    name: String,
    status: String,
    summary: String,
    #[serde(default = "empty_object")]
    evidence: Value,
    #[serde(default)]
    error_kind: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

pub async fn collect(
    programs: &[PathBuf],
    target: &Target,
    operation_timeout: Duration,
) -> anyhow::Result<Vec<PluginResult>> {
    validate_programs(programs)?;
    let mut tasks = JoinSet::new();
    for (index, program) in programs.iter().cloned().enumerate() {
        let arguments = plugin_arguments(target, operation_timeout);
        tasks.spawn(async move {
            (
                index,
                invoke_plugin(program, arguments, operation_timeout).await,
            )
        });
    }
    let mut results = std::iter::repeat_with(|| None)
        .take(programs.len())
        .collect::<Vec<_>>();
    while let Some(result) = tasks.join_next().await {
        if let Ok((index, evidence)) = result {
            results[index] = Some(evidence);
        }
    }
    Ok(results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.unwrap_or_else(|| {
                failed_plugin(
                    &programs[index],
                    "tool_failed",
                    "plugin task stopped before producing evidence",
                )
            })
        })
        .collect())
}

fn plugin_arguments(target: &Target, operation_timeout: Duration) -> Vec<OsString> {
    vec![
        OsString::from("netwhy-probe"),
        OsString::from("--protocol-version"),
        OsString::from(PLUGIN_SCHEMA_VERSION.to_string()),
        OsString::from("--scheme"),
        OsString::from(&target.scheme),
        OsString::from("--host"),
        OsString::from(&target.host),
        OsString::from("--port"),
        OsString::from(target.port.to_string()),
        OsString::from("--timeout-ms"),
        OsString::from(operation_timeout.as_millis().to_string()),
    ]
}

async fn invoke_plugin(
    program: PathBuf,
    arguments: Vec<OsString>,
    operation_timeout: Duration,
) -> PluginResult {
    let output = run_bounded(
        program.as_os_str(),
        arguments,
        operation_timeout,
        MAX_PLUGIN_OUTPUT,
    )
    .await;
    let output = match output {
        Ok(output) => output,
        Err(BoundedCommandError::Io(error)) => {
            return failed_plugin(
                &program,
                if error.kind() == io::ErrorKind::NotFound {
                    "tool_missing"
                } else {
                    "tool_failed"
                },
                &error.to_string(),
            );
        }
        Err(BoundedCommandError::Timeout) => {
            return failed_plugin(&program, "timeout", "plugin timed out");
        }
    };
    if output.stdout.truncated || output.stderr.truncated {
        return failed_plugin(
            &program,
            "output_truncated",
            "plugin output exceeded the 256 KiB safety limit",
        );
    }
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr.bytes)
            .trim()
            .to_owned();
        return failed_plugin(
            &program,
            "tool_failed",
            if error.is_empty() {
                "plugin exited unsuccessfully"
            } else {
                &error
            },
        );
    }
    match parse_plugin_document(&output.stdout.bytes) {
        Ok(result) => result,
        Err(error) => failed_plugin(&program, "protocol_error", &error),
    }
}

fn parse_plugin_document(bytes: &[u8]) -> Result<PluginResult, String> {
    let document: PluginDocument =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid plugin JSON: {error}"))?;
    if document.protocol_version != PLUGIN_SCHEMA_VERSION {
        return Err(format!(
            "unsupported plugin protocol version {}; expected {}",
            document.protocol_version, PLUGIN_SCHEMA_VERSION
        ));
    }
    if document.name.trim().is_empty() || document.name.chars().count() > MAX_PLUGIN_NAME_CHARS {
        return Err(format!(
            "plugin name must contain 1 to {MAX_PLUGIN_NAME_CHARS} characters"
        ));
    }
    if document.summary.chars().count() > MAX_PLUGIN_SUMMARY_CHARS {
        return Err(format!(
            "plugin summary exceeded the {MAX_PLUGIN_SUMMARY_CHARS}-character limit"
        ));
    }
    let status = match document.status.as_str() {
        "pass" => Status::Pass,
        "warn" => Status::Warn,
        "fail" => Status::Fail,
        "skip" => Status::Skip,
        _ => return Err("plugin status must be pass, warn, fail, or skip".to_owned()),
    };
    let mut evidence = document.evidence;
    sanitize_json(&mut evidence);
    Ok(PluginResult {
        protocol_version: document.protocol_version,
        name: bounded_report_text(&document.name, MAX_PLUGIN_NAME_CHARS),
        status,
        summary: bounded_report_text(&document.summary, MAX_PLUGIN_SUMMARY_CHARS),
        evidence,
        error_kind: document.error_kind.map(sanitize_report_text),
        error: document.error.map(sanitize_report_text),
    })
}

fn bounded_report_text(value: &str, max_characters: usize) -> String {
    sanitize_report_text(value)
        .chars()
        .take(max_characters)
        .collect()
}

fn sanitize_json(value: &mut Value) {
    match value {
        Value::String(text) => *text = sanitize_report_text(&*text),
        Value::Array(values) => values.iter_mut().for_each(sanitize_json),
        Value::Object(values) => values.values_mut().for_each(sanitize_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn failed_plugin(program: &Path, kind: &str, error: &str) -> PluginResult {
    let name = program
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| bounded_report_text(name, MAX_PLUGIN_NAME_CHARS))
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "plugin".to_owned());
    PluginResult {
        protocol_version: PLUGIN_SCHEMA_VERSION,
        name,
        status: Status::Skip,
        summary: "Plugin evidence was unavailable.".to_owned(),
        evidence: empty_object(),
        error_kind: Some(kind.to_owned()),
        error: Some(sanitize_report_text(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf, time::Duration};

    use serde_json::Value;

    use super::{collect, failed_plugin, invoke_plugin, parse_plugin_document, plugin_arguments};
    use crate::{model::Status, target::Target};

    #[test]
    fn accepts_and_sanitizes_the_versioned_plugin_protocol() {
        let result = parse_plugin_document(
            br#"{"protocol_version":1,"name":"cloud","status":"warn","summary":"route\u001b[2J","evidence":{"region":"east\nforged"}}"#,
        )
        .unwrap();

        assert_eq!(result.status, Status::Warn);
        assert_eq!(result.summary, "route\\u{1b}[2J");
        assert_eq!(result.evidence["region"], "east\\nforged");
    }

    #[test]
    fn rejects_unknown_versions_statuses_and_fields() {
        for document in [
            br#"{"protocol_version":2,"name":"x","status":"pass","summary":"ok"}"#.as_slice(),
            br#"{"protocol_version":1,"name":"x","status":"maybe","summary":"ok"}"#.as_slice(),
            br#"{"protocol_version":1,"name":"x","status":"pass","summary":"ok","unknown":true}"#
                .as_slice(),
        ] {
            assert!(parse_plugin_document(document).is_err());
        }
    }

    #[test]
    fn accepted_documents_match_the_published_plugin_schema() {
        let document: Value = serde_json::from_str(
            r#"{"protocol_version":1,"name":"cloud","status":"pass","summary":"ok","evidence":{"region":"east"}}"#,
        )
        .unwrap();
        let schema: Value =
            serde_json::from_str(include_str!("../docs/plugin.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        let errors = validator
            .iter_errors(&document)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "schema errors: {errors:#?}");

        let unicode_name = "é".repeat(128);
        let unicode_document = serde_json::json!({
            "protocol_version": 1,
            "name": unicode_name,
            "status": "pass",
            "summary": "ok"
        });
        assert!(validator.is_valid(&unicode_document));
        assert!(!validator.is_valid(&serde_json::json!({
            "protocol_version": 1,
            "name": "   ",
            "status": "pass",
            "summary": "ok"
        })));
    }

    #[test]
    fn parses_every_status_default_evidence_and_nested_json_types() {
        for (status, expected) in [
            ("pass", Status::Pass),
            ("warn", Status::Warn),
            ("fail", Status::Fail),
            ("skip", Status::Skip),
        ] {
            let document = format!(
                r#"{{"protocol_version":1,"name":"x","status":"{status}","summary":"ok","evidence":[null,true,42,"line\n",{{"nested":"value"}}]}}"#
            );
            assert_eq!(
                parse_plugin_document(document.as_bytes()).unwrap().status,
                expected
            );
        }
        let defaulted = parse_plugin_document(
            br#"{"protocol_version":1,"name":"x","status":"pass","summary":"ok"}"#,
        )
        .unwrap();
        assert_eq!(defaulted.evidence, serde_json::json!({}));

        let unicode_name = "é".repeat(128);
        let unicode_document = serde_json::json!({
            "protocol_version": 1,
            "name": unicode_name,
            "status": "pass",
            "summary": "ok"
        });
        let unicode_result =
            parse_plugin_document(serde_json::to_string(&unicode_document).unwrap().as_bytes())
                .unwrap();
        assert_eq!(unicode_result.name.chars().count(), 128);

        for invalid in [
            format!(
                r#"{{"protocol_version":1,"name":"{}","status":"pass","summary":"ok"}}"#,
                "x".repeat(129)
            ),
            format!(
                r#"{{"protocol_version":1,"name":"x","status":"pass","summary":"{}"}}"#,
                "x".repeat(4097)
            ),
            r#"{"protocol_version":1,"name":" ","status":"pass","summary":"ok"}"#.to_owned(),
        ] {
            assert!(parse_plugin_document(invalid.as_bytes()).is_err());
        }
        assert!(parse_plugin_document(b"not json").is_err());
    }

    #[tokio::test]
    async fn isolates_process_failures_timeouts_truncation_and_protocol_errors() {
        let timeout = Duration::from_millis(50);
        let missing =
            invoke_plugin(PathBuf::from("/netwhy-missing-plugin"), Vec::new(), timeout).await;
        assert_eq!(missing.error_kind.as_deref(), Some("tool_missing"));

        for (script, expected) in [
            ("exit 7", "tool_failed"),
            ("printf 'bad error' >&2; exit 7", "tool_failed"),
            ("sleep 1", "timeout"),
            ("yes x | head -c 300000", "output_truncated"),
            ("printf 'not-json'", "protocol_error"),
        ] {
            let result = invoke_plugin(
                PathBuf::from("/bin/sh"),
                [OsString::from("-c"), OsString::from(script)].to_vec(),
                timeout,
            )
            .await;
            assert_eq!(result.error_kind.as_deref(), Some(expected), "{script}");
            assert_eq!(result.status, Status::Skip);
        }

        let fallback = failed_plugin(std::path::Path::new("/"), "tool_failed", "bad\nerror");
        assert_eq!(fallback.name, "plugin");
        assert_eq!(fallback.error.as_deref(), Some("bad\\nerror"));

        let long_name = format!("/tmp/{}", "x".repeat(200));
        let bounded = failed_plugin(
            std::path::Path::new(&long_name),
            "tool_failed",
            "unavailable",
        );
        assert_eq!(bounded.name.chars().count(), 128);
        let schema: Value =
            serde_json::from_str(include_str!("../docs/plugin.schema.json")).unwrap();
        assert!(
            jsonschema::validator_for(&schema)
                .unwrap()
                .is_valid(&serde_json::to_value(&bounded).unwrap())
        );
    }

    #[tokio::test]
    async fn collect_preserves_order_and_builds_the_versioned_invocation() {
        let target = Target::parse("https://example.test:8443/").unwrap();
        let arguments = plugin_arguments(&target, Duration::from_millis(250));
        assert_eq!(arguments[0], "netwhy-probe");
        assert!(arguments.iter().any(|argument| argument == "8443"));

        let results = collect(
            &[PathBuf::from("/bin/echo"), PathBuf::from("/bin/false")],
            &target,
            Duration::from_millis(250),
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "echo");
        assert_eq!(results[0].error_kind.as_deref(), Some("protocol_error"));
        assert_eq!(results[1].name, "false");
        assert_eq!(results[1].error_kind.as_deref(), Some("tool_failed"));
    }
}
