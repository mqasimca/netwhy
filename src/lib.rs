pub mod cli;
mod diagnosis;
mod model;
pub mod output;
mod probe;
mod target;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cli::Cli;
use model::{
    AddressFamilySelection, ProxyVariable, RequestInfo, SCHEMA_VERSION, TargetReport, ToolInfo,
};
pub use model::{DiagnosisCode, DiagnosticReport, ErrorCode, ErrorReport, Status};
use target::Target;

/// Run every diagnostic stage and return a serializable report.
///
/// # Errors
///
/// Returns an error when the target is empty, malformed, or uses an unsupported scheme.
pub async fn diagnose(cli: &Cli) -> Result<DiagnosticReport> {
    let started = Instant::now();
    let target = Target::parse(&cli.target)?;
    let timeout = Duration::from_millis(cli.timeout_ms);

    let dns = probe::dns::resolve(&target, cli.ipv4, cli.ipv6, timeout).await;
    let routes = probe::route::inspect_all(&dns.addresses, timeout).await;
    let tcp = probe::tcp::connect_all(&dns.addresses, timeout).await;
    let application_attempts = probe::application::probe(&target, &tcp, timeout).await;
    let proxies = proxy_variables();

    let mut report = DiagnosticReport {
        schema_version: SCHEMA_VERSION,
        kind: "diagnostic_report".to_owned(),
        tool: ToolInfo::current(),
        generated_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        duration_ms: started.elapsed().as_millis(),
        request: RequestInfo {
            timeout_ms: cli.timeout_ms,
            address_family: if cli.ipv4 {
                AddressFamilySelection::Ipv4
            } else if cli.ipv6 {
                AddressFamilySelection::Ipv6
            } else {
                AddressFamilySelection::Any
            },
            application_transport: "direct".to_owned(),
            proxy_mode: "detect_only".to_owned(),
        },
        target: TargetReport::from(&target),
        dns,
        routes,
        tcp,
        application_attempts,
        proxies,
        diagnosis: model::Diagnosis::default(),
        overall: Status::Skip,
        exit_code: 2,
    };

    diagnosis::explain(&mut report);
    Ok(report)
}

fn proxy_variables() -> Vec<ProxyVariable> {
    const NAMES: [&str; 8] = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ];

    NAMES
        .into_iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.is_empty())
                .map(|value| ProxyVariable {
                    name: name.to_owned(),
                    value: redact_proxy_value(name, &value),
                })
        })
        .collect()
}

fn redact_proxy_value(name: &str, value: &str) -> String {
    if name.eq_ignore_ascii_case("no_proxy") {
        return sanitize_report_text(value);
    }

    let authority_start = value.find("://").map_or(0, |index| index + 3);
    let authority_end = value[authority_start..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |index| authority_start + index);
    let redacted = value[authority_start..authority_end]
        .rfind('@')
        .map_or_else(
            || value.to_owned(),
            |index| {
                let at = authority_start + index;
                format!(
                    "{}<redacted>@{}",
                    &value[..authority_start],
                    &value[at + 1..]
                )
            },
        );
    sanitize_report_text(&redacted)
}

pub(crate) fn sanitize_report_text(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            sanitized.extend(character.escape_default());
        } else {
            sanitized.push(character);
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::redact_proxy_value;

    #[test]
    fn redacts_proxy_credentials() {
        assert_eq!(
            redact_proxy_value("HTTPS_PROXY", "http://alice:secret@proxy.example:8080"),
            "http://<redacted>@proxy.example:8080"
        );
        assert_eq!(
            redact_proxy_value("ALL_PROXY", "alice:secret@proxy.example:1080"),
            "<redacted>@proxy.example:1080"
        );
        assert_eq!(
            redact_proxy_value(
                "HTTPS_PROXY",
                "http://alice:secret@proxy.example/path@tag?next=@later"
            ),
            "http://<redacted>@proxy.example/path@tag?next=@later"
        );
        assert_eq!(
            redact_proxy_value("HTTPS_PROXY", "http://proxy.example/path@tag"),
            "http://proxy.example/path@tag"
        );
        assert_eq!(
            redact_proxy_value("HTTPS_PROXY", "http://proxy.example/\nforged"),
            "http://proxy.example/\\nforged"
        );
    }

    #[test]
    fn leaves_no_proxy_unchanged() {
        assert_eq!(
            redact_proxy_value("NO_PROXY", "localhost,.example.com"),
            "localhost,.example.com"
        );
    }
}
