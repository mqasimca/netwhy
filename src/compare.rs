use std::{fmt::Write as _, fs::File, io::Read, path::Path};

use anyhow::{Context, Result, bail};
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};
use serde_json::Value;

use crate::{
    model::{
        COMPARISON_SCHEMA_VERSION, ComparisonChange, ComparisonInput, ComparisonReport,
        SCHEMA_VERSION, Status, ToolInfo,
    },
    sanitize_report_text,
};

const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHANGES: usize = 256;

/// Compare two bounded `NetWhy` diagnostic report files.
///
/// # Errors
///
/// Returns an error when either file cannot be read, exceeds the size limit, is invalid JSON,
/// or does not contain a supported `NetWhy` diagnostic report envelope.
pub fn compare_files(left: &Path, right: &Path) -> Result<ComparisonReport> {
    let left_value = read_report(left)?;
    let right_value = read_report(right)?;
    let left_input = describe_input(left, &left_value)?;
    let right_input = describe_input(right, &right_value)?;
    let mut changes = Vec::new();
    let mut truncated = false;
    diff_values("", &left_value, &right_value, &mut changes, &mut truncated);
    let significant = changes
        .iter()
        .filter(|change| change.significance == "high")
        .count();
    let summary = if changes.is_empty() {
        "The reports are equivalent across all compared fields.".to_owned()
    } else {
        format!(
            "Found {} difference{} ({} high-significance).",
            changes.len(),
            if changes.len() == 1 { "" } else { "s" },
            significant
        )
    };
    Ok(ComparisonReport {
        schema_version: COMPARISON_SCHEMA_VERSION,
        kind: "comparison_report".to_owned(),
        tool: ToolInfo::current(),
        left: left_input,
        right: right_input,
        overall: if changes.is_empty() {
            Status::Pass
        } else {
            Status::Warn
        },
        exit_code: 0,
        changes,
        truncated,
        summary,
    })
}

fn read_report(path: &Path) -> Result<Value> {
    let path_metadata = path
        .metadata()
        .with_context(|| format!("could not inspect report {}", path.display()))?;
    if !path_metadata.is_file() {
        bail!("report {} is not a regular file", path.display());
    }
    if path_metadata.len() > MAX_REPORT_BYTES as u64 {
        bail!(
            "report {} exceeds the {} MiB safety limit",
            path.display(),
            MAX_REPORT_BYTES / (1024 * 1024)
        );
    }
    let file = File::from(
        open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .with_context(|| format!("could not open report {}", path.display()))?,
    );
    if !file
        .metadata()
        .with_context(|| format!("could not inspect open report {}", path.display()))?
        .is_file()
    {
        bail!("report {} is not a regular file", path.display());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(path_metadata.len())
            .unwrap_or(MAX_REPORT_BYTES)
            .min(MAX_REPORT_BYTES),
    );
    file.take((MAX_REPORT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read report {}", path.display()))?;
    if bytes.len() > MAX_REPORT_BYTES {
        bail!(
            "report {} exceeds the {} MiB safety limit",
            path.display(),
            MAX_REPORT_BYTES / (1024 * 1024)
        );
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("report {} is not valid JSON", path.display()))
}

fn describe_input(path: &Path, value: &Value) -> Result<ComparisonInput> {
    if value.get("kind").and_then(Value::as_str) != Some("diagnostic_report") {
        bail!("{} is not a NetWhy diagnostic report", path.display());
    }
    let report_schema_version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .with_context(|| format!("{} has no numeric schema_version", path.display()))?;
    if !(1..=u64::from(SCHEMA_VERSION)).contains(&report_schema_version) {
        bail!(
            "{} uses unsupported report schema version {}; supported versions are 1 through {}",
            path.display(),
            report_schema_version,
            SCHEMA_VERSION
        );
    }
    let target = value
        .pointer("/target/original")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/target/host").and_then(Value::as_str))
        .with_context(|| format!("{} has no target identity", path.display()))?;
    let execution_context = value
        .pointer("/request/execution_context/source")
        .and_then(Value::as_str)
        .with_context(|| format!("{} has no execution context", path.display()))?;
    Ok(ComparisonInput {
        path: sanitize_report_text(path.display().to_string()),
        report_schema_version,
        target: sanitize_report_text(target),
        execution_context: sanitize_report_text(execution_context),
    })
}

fn diff_values(
    path: &str,
    left: &Value,
    right: &Value,
    changes: &mut Vec<ComparisonChange>,
    truncated: &mut bool,
) {
    if is_volatile_path(path) {
        return;
    }
    if left == right {
        return;
    }
    if changes.len() >= MAX_CHANGES {
        *truncated = true;
        return;
    }
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let mut keys = left.keys().chain(right.keys()).collect::<Vec<_>>();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                let child_path = format!("{path}/{}", escape_pointer(key));
                match (left.get(key), right.get(key)) {
                    (Some(left), Some(right)) => {
                        diff_values(&child_path, left, right, changes, truncated);
                    }
                    (left, right) => push_change(
                        &child_path,
                        left.cloned().unwrap_or(Value::Null),
                        right.cloned().unwrap_or(Value::Null),
                        changes,
                        truncated,
                    ),
                }
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            for index in 0..left.len().max(right.len()) {
                let child_path = format!("{path}/{index}");
                match (left.get(index), right.get(index)) {
                    (Some(left), Some(right)) => {
                        diff_values(&child_path, left, right, changes, truncated);
                    }
                    (left, right) => push_change(
                        &child_path,
                        left.cloned().unwrap_or(Value::Null),
                        right.cloned().unwrap_or(Value::Null),
                        changes,
                        truncated,
                    ),
                }
            }
        }
        _ => push_change(path, left.clone(), right.clone(), changes, truncated),
    }
}

fn is_volatile_path(path: &str) -> bool {
    path == "/generated_at_unix_ms"
        || path == "/tool/version"
        || path
            .rsplit('/')
            .next()
            .is_some_and(|field| matches!(field, "duration_ms" | "handshake_ms"))
}

fn push_change(
    path: &str,
    left: Value,
    right: Value,
    changes: &mut Vec<ComparisonChange>,
    truncated: &mut bool,
) {
    if is_volatile_path(path) {
        return;
    }
    if changes.len() >= MAX_CHANGES {
        *truncated = true;
        return;
    }
    changes.push(ComparisonChange {
        path: if path.is_empty() { "/" } else { path }.to_owned(),
        significance: significance(path).to_owned(),
        left,
        right,
    });
}

fn significance(path: &str) -> &'static str {
    if path == "/overall"
        || path == "/exit_code"
        || path.starts_with("/diagnosis/code")
        || path.ends_with("/status")
        || path.ends_with("/error_kind")
    {
        "high"
    } else if path.starts_with("/dns")
        || path.starts_with("/routes")
        || path.starts_with("/tcp")
        || path.starts_with("/application_attempts")
        || path.starts_with("/path_evidence")
        || path.starts_with("/proxy_transport")
        || path.starts_with("/plugins")
    {
        "medium"
    } else {
        "low"
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[must_use]
pub fn render_human(report: &ComparisonReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "NetWhy {} comparison", report.tool.version);
    let _ = writeln!(
        output,
        "Result: {}",
        if report.overall == Status::Pass {
            "PASS"
        } else {
            "WARN"
        }
    );
    let _ = writeln!(output, "Summary: {}", report.summary);
    let _ = writeln!(
        output,
        "Left: {} ({})",
        report.left.target, report.left.execution_context
    );
    let _ = writeln!(
        output,
        "Right: {} ({})",
        report.right.target, report.right.execution_context
    );
    if !report.changes.is_empty() {
        let _ = writeln!(output, "\nDifferences:");
        for change in &report.changes {
            let _ = writeln!(
                output,
                "  [{}] {}: {} -> {}",
                change.significance.to_ascii_uppercase(),
                change.path,
                compact_value(&change.left),
                compact_value(&change.right)
            );
        }
    }
    if report.truncated {
        let _ = writeln!(
            output,
            "\nOnly the first {MAX_CHANGES} differences are shown."
        );
    }
    output
}

fn compact_value(value: &Value) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_else(|_| "<unavailable>".to_owned());
    let sanitized = sanitize_report_text(serialized);
    if sanitized.chars().count() <= 160 {
        sanitized
    } else {
        format!("{}...", sanitized.chars().take(160).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use super::{
        MAX_CHANGES, MAX_REPORT_BYTES, compare_files, describe_input, diff_values, render_human,
        significance,
    };

    fn temporary_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("netwhy-{}-{nonce}-{name}", std::process::id()))
    }

    fn report(overall: &str) -> serde_json::Value {
        json!({
            "schema_version": 2,
            "kind": "diagnostic_report",
            "target": {"original": "example.test"},
            "request": {"execution_context": {"source": "current_process"}},
            "overall": overall,
            "message": "x".repeat(200)
        })
    }

    #[test]
    fn produces_deterministic_structural_differences() {
        let left = json!({"overall":"pass","dns":{"addresses":["192.0.2.1"]}});
        let right = json!({"overall":"fail","dns":{"addresses":["192.0.2.2"],"error":"x"}});
        let mut changes = Vec::new();
        let mut truncated = false;

        diff_values("", &left, &right, &mut changes, &mut truncated);

        assert!(!truncated);
        assert_eq!(changes[0].path, "/dns/addresses/0");
        assert_eq!(changes[1].path, "/dns/error");
        assert_eq!(changes[2].path, "/overall");
        assert_eq!(changes[2].significance, "high");
    }

    #[test]
    fn classifies_protocol_evidence_as_material() {
        assert_eq!(significance("/application_attempts/0/tls/status"), "high");
        assert_eq!(significance("/routes/0/gateway"), "medium");
        assert_eq!(significance("/request/timeout_ms"), "low");
    }

    #[test]
    fn ignores_volatile_fields_before_applying_the_change_limit() {
        let left = json!({
            "generated_at_unix_ms": 1,
            "duration_ms": 2,
            "tool": {"version": "old"},
            "tcp": [{"duration_ms": 3}],
            "application_attempts": [{
                "connect": {"duration_ms": 4},
                "tls": {"handshake_ms": 5},
                "http": {"duration_ms": 6}
            }],
            "plugins": [{}],
            "diagnosis": {"summary": "same"}
        });
        let right = json!({
            "generated_at_unix_ms": 100,
            "duration_ms": 200,
            "tool": {"version": "new"},
            "tcp": [{"duration_ms": 300}],
            "application_attempts": [{
                "connect": {"duration_ms": 400},
                "tls": {"handshake_ms": 500},
                "http": {"duration_ms": 600}
            }],
            "plugins": [{"duration_ms": 700}],
            "diagnosis": {"summary": "same"}
        });
        let mut changes = Vec::new();
        let mut truncated = false;

        diff_values("", &left, &right, &mut changes, &mut truncated);

        assert!(changes.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn caps_large_comparisons_deterministically() {
        let left = (0..(MAX_CHANGES + 20))
            .map(|index| (format!("field-{index:03}"), json!(index)))
            .collect::<serde_json::Map<_, _>>();
        let right = (0..(MAX_CHANGES + 20))
            .map(|index| (format!("field-{index:03}"), json!(index + 1)))
            .collect::<serde_json::Map<_, _>>();
        let mut changes = Vec::new();
        let mut truncated = false;

        diff_values(
            "",
            &serde_json::Value::Object(left),
            &serde_json::Value::Object(right),
            &mut changes,
            &mut truncated,
        );

        assert_eq!(changes.len(), MAX_CHANGES);
        assert!(truncated);
        assert_eq!(changes[0].path, "/field-000");
        assert_eq!(changes[MAX_CHANGES - 1].path, "/field-255");
    }

    #[test]
    fn rejects_future_report_schema_versions() {
        let value = json!({
            "schema_version": 255,
            "kind": "diagnostic_report",
            "target": {"original": "example.test"},
            "request": {"execution_context": {"source": "current_process"}}
        });

        let error = describe_input(Path::new("future.json"), &value).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unsupported report schema version")
        );
    }

    #[test]
    fn compares_files_renders_results_and_bounds_invalid_inputs() {
        let left = temporary_path("left.json");
        let right = temporary_path("right.json");
        fs::write(&left, serde_json::to_vec(&report("pass")).unwrap()).unwrap();
        fs::write(&right, serde_json::to_vec(&report("fail")).unwrap()).unwrap();

        let comparison = compare_files(&left, &right).unwrap();
        assert_eq!(comparison.changes.len(), 1);
        let rendered = render_human(&comparison);
        assert!(rendered.contains("[HIGH] /overall"));

        fs::write(&right, b"not json").unwrap();
        assert!(
            compare_files(&left, &right)
                .unwrap_err()
                .to_string()
                .contains("valid JSON")
        );

        for invalid in [
            json!({}),
            json!({"kind":"diagnostic_report"}),
            json!({"kind":"diagnostic_report","schema_version":2}),
            json!({
                "kind":"diagnostic_report", "schema_version":2,
                "target":{"host":"example.test"}
            }),
        ] {
            fs::write(&right, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(compare_files(&left, &right).is_err());
        }

        let oversized = temporary_path("oversized.json");
        let file = File::create(&oversized).unwrap();
        file.set_len((MAX_REPORT_BYTES + 1) as u64).unwrap();
        assert!(
            compare_files(&left, &oversized)
                .unwrap_err()
                .to_string()
                .contains("safety limit")
        );
        assert!(compare_files(&temporary_path("missing.json"), &left).is_err());

        let directory = temporary_path("directory");
        fs::create_dir(&directory).unwrap();
        assert!(
            compare_files(&left, &directory)
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );

        fs::remove_file(left).unwrap();
        fs::remove_file(right).unwrap();
        fs::remove_file(oversized).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
