#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
compile_error!("NetWhy supports Linux and Apple Silicon macOS targets");

pub mod cli;
mod command;
pub mod compare;
mod diagnosis;
mod model;
pub mod output;
mod plugin;
mod probe;
mod proxy;
pub mod redaction;
mod target;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cli::{Cli, ProxyMode};
use model::{
    AddressFamilySelection, ProxyVariable, RequestInfo, SCHEMA_VERSION, TargetReport, ToolInfo,
};
pub use model::{
    CapabilityStatus, ComparisonReport, ContextRelation, DiagnosisCode, DiagnosticReport,
    ErrorCode, ErrorReport, ExecutionContextInfo, ExecutionContextSource, ProxyEnvironmentStatus,
    Status,
};
use target::Target;

/// Validate diagnostic options that require checks beyond Clap's field-level parsing.
///
/// # Errors
///
/// Returns an error for an invalid explicit proxy URL or too many plugin programs.
pub fn validate_options(cli: &Cli) -> Result<()> {
    plugin::validate_programs(&cli.plugin)?;
    proxy::validate_args(&cli.diagnostic)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DiagnosticContext {
    execution: ExecutionContextInfo,
    proxies: Vec<ProxyVariable>,
    proxy_environment: Vec<(String, String)>,
}

impl DiagnosticContext {
    #[must_use]
    pub fn current() -> Self {
        let proxy_environment = proxy_environment_from_lookup(|name| std::env::var(name).ok());
        Self {
            execution: ExecutionContextInfo::current(),
            proxies: report_proxy_variables(&proxy_environment),
            proxy_environment,
        }
    }

    #[must_use]
    pub fn selected_process(
        execution: ExecutionContextInfo,
        environment: &[(String, String)],
    ) -> Self {
        let proxy_environment = proxy_environment_from_lookup(|name| {
            environment
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.clone())
        });
        Self {
            execution,
            proxies: report_proxy_variables(&proxy_environment),
            proxy_environment,
        }
    }

    /// Build a context from the NUL-delimited contents of `/proc/<pid>/environ`.
    /// Only recognized proxy variables are retained.
    #[must_use]
    pub fn selected_process_environ(execution: ExecutionContextInfo, environment: &[u8]) -> Self {
        let proxy_environment = proxy_environment_from_lookup(|name| {
            environment.split(|byte| *byte == 0).find_map(|entry| {
                let separator = entry.iter().position(|byte| *byte == b'=')?;
                let (candidate, value) = entry.split_at(separator);
                let value = value.get(1..)?;
                (candidate == name.as_bytes())
                    .then(|| std::str::from_utf8(value).ok().map(ToOwned::to_owned))?
            })
        });
        Self {
            execution,
            proxies: report_proxy_variables(&proxy_environment),
            proxy_environment,
        }
    }

    #[must_use]
    pub const fn execution(&self) -> &ExecutionContextInfo {
        &self.execution
    }
}

/// Run every diagnostic stage and return a serializable report.
///
/// # Errors
///
/// Returns an error when the target is empty, malformed, or uses an unsupported scheme.
pub async fn diagnose(cli: &Cli) -> Result<DiagnosticReport> {
    Box::pin(diagnose_with_context(cli, DiagnosticContext::current())).await
}

/// Run every diagnostic stage using an explicitly selected execution context.
///
/// # Errors
///
/// Returns an error when the target is empty, malformed, or uses an unsupported scheme.
pub async fn diagnose_with_context(
    cli: &Cli,
    context: DiagnosticContext,
) -> Result<DiagnosticReport> {
    let started = Instant::now();
    validate_options(cli)?;
    let target = Target::parse(&cli.target)?;
    let timeout = Duration::from_millis(cli.timeout_ms);

    let dns = probe::dns::resolve(&target, cli.ipv4, cli.ipv6, timeout).await;
    let (routes, tcp, proxy_plan) = tokio::join!(
        probe::route::inspect_all(&dns.addresses, timeout),
        probe::tcp::connect_all(&dns.addresses, timeout),
        proxy::plan(
            &cli.diagnostic,
            &target,
            &context.proxy_environment,
            timeout
        ),
    );
    let proxy_plan = proxy_plan?;
    let application_future = async {
        match &proxy_plan {
            proxy::ProxyPlan::Direct(_) => (
                probe::application::probe(&target, &tcp, timeout).await,
                None,
            ),
            proxy::ProxyPlan::Proxy(proxy) => {
                let (attempts, evidence) =
                    probe::application::probe_via_proxy(&target, proxy, timeout).await;
                (attempts, Some(evidence))
            }
            proxy::ProxyPlan::Unavailable(_) => (Vec::new(), None),
        }
    };
    let (path_evidence, plugins, (application_attempts, proxy_probe)) = tokio::join!(
        probe::path::collect(&dns.addresses, &routes, timeout),
        plugin::collect(&cli.plugin, &target, timeout),
        application_future,
    );
    let plugins = plugins?;
    let proxy_transport = proxy_probe.unwrap_or_else(|| match proxy_plan {
        proxy::ProxyPlan::Direct(evidence) | proxy::ProxyPlan::Unavailable(evidence) => evidence,
        proxy::ProxyPlan::Proxy(_) => unreachable!("proxy probing returns evidence"),
    });
    let application_transport = if proxy_transport.mode == "proxy" {
        "proxy"
    } else {
        "direct"
    };
    let proxy_mode = if cli.proxy_url.is_some() {
        "explicit"
    } else if cli.proxy_mode == ProxyMode::Environment {
        "environment"
    } else {
        "direct"
    };
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
            application_transport: application_transport.to_owned(),
            proxy_mode: proxy_mode.to_owned(),
            redaction: "standard".to_owned(),
            execution_context: context.execution,
        },
        target: TargetReport::from(&target),
        dns,
        routes,
        tcp,
        application_attempts,
        proxies: context.proxies,
        proxy_transport,
        path_evidence,
        plugins,
        diagnosis: model::Diagnosis::default(),
        overall: Status::Skip,
        exit_code: 2,
    };

    diagnosis::explain(&mut report);
    Ok(report)
}

fn proxy_environment_from_lookup(
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Vec<(String, String)> {
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
            lookup(name)
                .filter(|value| !value.is_empty())
                .map(|value| (name.to_owned(), value))
        })
        .collect()
}

fn report_proxy_variables(environment: &[(String, String)]) -> Vec<ProxyVariable> {
    environment
        .iter()
        .map(|(name, value)| ProxyVariable {
            name: name.clone(),
            value: redact_proxy_value(name, value),
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

/// Escapes control characters before untrusted text is included in diagnostics.
#[must_use]
pub fn sanitize_report_text(value: impl AsRef<str>) -> String {
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
    use super::{DiagnosticContext, ExecutionContextInfo, redact_proxy_value};

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

    #[test]
    fn process_environment_retains_only_supported_redacted_proxy_values() {
        let context = DiagnosticContext::selected_process_environ(
            ExecutionContextInfo::current(),
            b"DATABASE_PASSWORD=secret\0HTTPS_PROXY=http://alice:secret@proxy.example:8080\0NO_PROXY=localhost,service=a\0",
        );

        assert_eq!(context.proxies.len(), 2);
        assert_eq!(context.proxies[0].name, "HTTPS_PROXY");
        assert_eq!(
            context.proxies[0].value,
            "http://<redacted>@proxy.example:8080"
        );
        assert_eq!(context.proxies[1].name, "NO_PROXY");
        assert_eq!(context.proxies[1].value, "localhost,service=a");
    }

    #[test]
    fn process_environment_ignores_empty_and_non_utf8_proxy_values() {
        let context = DiagnosticContext::selected_process_environ(
            ExecutionContextInfo::current(),
            b"HTTPS_PROXY=\xff\0HTTP_PROXY=\0http_proxy=http://proxy.example\0",
        );

        assert_eq!(context.proxies.len(), 1);
        assert_eq!(context.proxies[0].name, "http_proxy");
        assert_eq!(context.proxies[0].value, "http://proxy.example");
    }
}
