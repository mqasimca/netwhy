use std::fmt::Write as _;

use crate::{
    model::{
        AddressFamilySelection, CapabilityStatus, ContextRelation, DiagnosticReport,
        ExecutionContextInfo, ExecutionContextSource, ProxyEnvironmentStatus, Status,
    },
    sanitize_report_text,
};

#[must_use]
pub fn render_human(report: &DiagnosticReport) -> String {
    let mut output = String::new();

    let _ = writeln!(output, "NetWhy {}", report.tool.version);
    let _ = writeln!(output, "Result: {}", status_name(report.overall));
    let _ = writeln!(
        output,
        "Target: {}",
        sanitize_report_text(&report.target.original)
    );
    let _ = writeln!(output, "Interpreted as: {}", endpoint(report));
    let _ = writeln!(output, "Summary: {}", report.diagnosis.summary);

    if let Some(cause) = &report.diagnosis.likely_cause {
        let _ = writeln!(
            output,
            "Likely cause (inference): {}",
            sanitize_report_text(cause)
        );
    }

    if !report.diagnosis.suggestions.is_empty() {
        let _ = writeln!(output, "\nNext steps:");
        for (index, suggestion) in report.diagnosis.suggestions.iter().enumerate() {
            let _ = writeln!(
                output,
                "  {}. {}",
                index + 1,
                sanitize_report_text(suggestion)
            );
        }
    }

    let _ = writeln!(output, "\nEvidence:");
    write_dns(&mut output, report);
    write_routes(&mut output, report);
    write_tcp(&mut output, report);
    write_application(&mut output, report);

    let _ = writeln!(output, "\nContext:");
    let _ = writeln!(
        output,
        "  Request: timeout {} ms · address family {} · transport {} · proxy mode {}",
        report.request.timeout_ms,
        address_family_name(report.request.address_family),
        report.request.application_transport,
        report.request.proxy_mode
    );
    write_execution_context(&mut output, report);
    for proxy in &report.proxies {
        let _ = writeln!(
            output,
            "  Proxy environment: {}={}",
            proxy.name,
            sanitize_report_text(&proxy.value)
        );
    }
    for note in &report.diagnosis.notes {
        let _ = writeln!(output, "  {}", sanitize_report_text(note));
    }

    let _ = writeln!(output, "\nCompleted in {} ms", report.duration_ms);
    output
}

fn write_execution_context(output: &mut String, report: &DiagnosticReport) {
    let context = &report.request.execution_context;
    let _ = write!(output, "  Execution context: ");
    match context.source {
        ExecutionContextSource::CurrentProcess => {
            let _ = write!(output, "current process");
        }
        ExecutionContextSource::Process => {
            let _ = write!(output, "process");
            if let Some(pid) = context.target_pid {
                let _ = write!(output, " {pid}");
            }
        }
        ExecutionContextSource::Docker => write_container_context(output, context, "Docker"),
        ExecutionContextSource::Podman => write_container_context(output, context, "Podman"),
    }
    let _ = write!(
        output,
        " · network {} · mount {} · root {} · proxy environment {}",
        context_relation_name(context.network_namespace),
        context_relation_name(context.mount_namespace),
        context_relation_name(context.filesystem_root),
        proxy_environment_name(context.proxy_environment)
    );
    match context.capability_status {
        CapabilityStatus::NotRequired => {
            let _ = writeln!(output, " · capabilities not required");
        }
        CapabilityStatus::Available => {
            let _ = writeln!(
                output,
                " · capabilities available ({})",
                context.required_capabilities.join(", ")
            );
        }
    }
}

fn write_container_context(output: &mut String, context: &ExecutionContextInfo, runtime: &str) {
    let _ = write!(output, "{runtime} container");
    if let Some(container) = &context.target_container {
        let _ = write!(output, " {}", sanitize_report_text(container));
    }
    if let Some(pid) = context.target_pid {
        let _ = write!(output, " (process {pid})");
    }
}

const fn context_relation_name(relation: ContextRelation) -> &'static str {
    match relation {
        ContextRelation::Current => "current",
        ContextRelation::Shared => "shared",
        ContextRelation::Entered => "entered",
    }
}

const fn proxy_environment_name(status: ProxyEnvironmentStatus) -> &'static str {
    match status {
        ProxyEnvironmentStatus::CurrentProcess => "current process",
        ProxyEnvironmentStatus::SelectedProcess => "selected process",
        ProxyEnvironmentStatus::Unavailable => "unavailable",
    }
}

fn write_dns(output: &mut String, report: &DiagnosticReport) {
    let _ = writeln!(
        output,
        "  [{}] DNS   {} address{} in {} ms",
        status_name(report.dns.status),
        report.dns.addresses.len(),
        plural(report.dns.addresses.len()),
        report.dns.duration_ms
    );
    if let Some(error) = &report.dns.error {
        let _ = writeln!(
            output,
            "             Error: {}",
            sanitize_report_text(error)
        );
    }
    for address in &report.dns.addresses {
        let _ = writeln!(output, "             {address}");
    }
}

fn write_routes(output: &mut String, report: &DiagnosticReport) {
    if report.routes.is_empty() {
        let _ = writeln!(output, "  [SKIP] ROUTE No resolved destination to inspect");
        return;
    }

    for route in &report.routes {
        let mut details = Vec::new();
        if let Some(interface) = &route.interface {
            details.push(format!("dev {}", sanitize_report_text(interface)));
        }
        if let Some(gateway) = &route.gateway {
            details.push(format!("via {}", sanitize_report_text(gateway)));
        }
        if let Some(source) = &route.source {
            details.push(format!("src {}", sanitize_report_text(source)));
        }
        if let Some(error) = &route.error {
            details.push(format!("error: {}", sanitize_report_text(error)));
        }
        let detail = if details.is_empty() {
            "no route details".to_owned()
        } else {
            details.join(" · ")
        };
        let _ = writeln!(
            output,
            "  [{}] ROUTE {} · {detail}",
            status_name(route.status),
            route.address.ip()
        );
    }
}

fn write_tcp(output: &mut String, report: &DiagnosticReport) {
    if report.tcp.is_empty() {
        let _ = writeln!(output, "  [SKIP] TCP   No resolved address to test");
        return;
    }

    for tcp in &report.tcp {
        let detail = sanitize_report_text(tcp.error.as_deref().unwrap_or("connected"));
        let _ = writeln!(
            output,
            "  [{}] TCP   {} · {} ms · {detail}",
            status_name(tcp.status),
            tcp.address,
            tcp.duration_ms
        );
    }
}

fn write_application(output: &mut String, report: &DiagnosticReport) {
    for application in &report.application_attempts {
        let connect_detail =
            sanitize_report_text(application.connect.error.as_deref().unwrap_or("connected"));
        let _ = writeln!(
            output,
            "  [{}] APP   {} · {} ms · {connect_detail}",
            status_name(application.connect.status),
            application.address,
            application.connect.duration_ms
        );

        if let Some(tls) = &application.tls {
            let detail = if tls.status == Status::Pass {
                [tls.version.as_deref(), tls.cipher_suite.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(sanitize_report_text)
                    .collect::<Vec<_>>()
                    .join(" · ")
            } else {
                sanitize_report_text(tls.error.as_deref().unwrap_or("handshake failed"))
            };
            let _ = writeln!(
                output,
                "  [{}] TLS   {} · handshake {} ms · trust {} · {detail}",
                status_name(tls.status),
                application.address,
                tls.handshake_ms,
                tls.trust_source
            );
        }

        if let Some(http) = &application.http {
            let detail = sanitize_report_text(
                http.status_line
                    .as_deref()
                    .or(http.error.as_deref())
                    .unwrap_or("no response"),
            );
            let _ = writeln!(
                output,
                "  [{}] HTTP  {} · {} ms · {detail}",
                status_name(http.status),
                application.address,
                http.duration_ms
            );
        }
    }
}

const fn address_family_name(selection: AddressFamilySelection) -> &'static str {
    match selection {
        AddressFamilySelection::Any => "any",
        AddressFamilySelection::Ipv4 => "IPv4",
        AddressFamilySelection::Ipv6 => "IPv6",
    }
}

fn endpoint(report: &DiagnosticReport) -> String {
    let host = if report.target.host.contains(':') {
        format!("[{}]", report.target.host)
    } else {
        report.target.host.clone()
    };
    format!("{}://{host}:{}", report.target.scheme, report.target.port)
}

const fn status_name(status: Status) -> &'static str {
    match status {
        Status::Pass => "PASS",
        Status::Warn => "WARN",
        Status::Fail => "FAIL",
        Status::Skip => "SKIP",
    }
}

const fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "es" }
}

#[cfg(test)]
mod tests {
    use super::render_human;
    use crate::model::{
        AddressFamily, AddressFamilySelection, ApplicationConnectResult, ApplicationReport,
        CapabilityStatus, ContextRelation, Diagnosis, DiagnosisCode, DiagnosticReport, DnsResult,
        ExecutionContextInfo, ExecutionContextSource, HttpResult, ProxyEnvironmentStatus,
        ProxyVariable, RequestInfo, RouteResult, Status, TargetReport, TcpResult, TlsResult,
        ToolInfo,
    };

    #[test]
    fn renders_rich_application_evidence_and_context() {
        let report = rich_report();

        let output = render_human(&report);

        assert!(output.starts_with("NetWhy 0.1.0\nResult: WARN\n"));
        assert!(output.contains("Interpreted as: https://[2001:db8::1]:8443"));
        assert!(output.contains("Likely cause (inference): partial connectivity"));
        assert!(output.contains("  1. Inspect the failing family."));
        assert!(output.contains("[PASS] DNS   2 addresses"));
        assert!(output.contains("dev wg0 · via 192.0.2.1 · src 192.0.2.2"));
        assert!(output.contains("[SKIP] ROUTE 192.0.2.10 · no route details"));
        assert!(output.contains("[PASS] TCP"));
        assert!(output.contains("[FAIL] TCP"));
        assert!(output.contains("[PASS] TLS"));
        assert!(output.contains("TLSv1_3 · TLS_AES_256_GCM_SHA384"));
        assert!(output.contains("[WARN] HTTP"));
        assert!(output.contains("Proxy environment: HTTPS_PROXY=http://proxy.test:8080"));
        assert!(output.contains(
            "Execution context: current process · network current · mount current · root current · proxy environment current process · capabilities not required"
        ));
        assert!(output.contains("Tunnel route selected."));
    }

    #[test]
    fn renders_selected_process_context_and_capabilities() {
        let mut report = rich_report();
        report.request.execution_context = ExecutionContextInfo {
            source: ExecutionContextSource::Process,
            target_pid: Some(42),
            target_container: None,
            network_namespace: ContextRelation::Entered,
            mount_namespace: ContextRelation::Shared,
            filesystem_root: ContextRelation::Entered,
            proxy_environment: ProxyEnvironmentStatus::SelectedProcess,
            proxy_error: None,
            required_capabilities: vec!["CAP_SYS_ADMIN".to_owned(), "CAP_SYS_CHROOT".to_owned()],
            capability_status: CapabilityStatus::Available,
        };

        let output = render_human(&report);

        assert!(output.contains(
            "Execution context: process 42 · network entered · mount shared · root entered · proxy environment selected process · capabilities available (CAP_SYS_ADMIN, CAP_SYS_CHROOT)"
        ));
    }

    #[test]
    fn renders_docker_and_podman_contexts() {
        for (source, runtime) in [
            (ExecutionContextSource::Docker, "Docker"),
            (ExecutionContextSource::Podman, "Podman"),
        ] {
            let mut report = rich_report();
            report.request.execution_context.source = source;
            report.request.execution_context.target_pid = Some(42);
            report.request.execution_context.target_container = Some("web\ncontainer".to_owned());

            let output = render_human(&report);

            assert!(output.contains(&format!(
                "Execution context: {runtime} container web\\ncontainer (process 42)"
            )));
        }
    }

    #[test]
    fn renders_skipped_transport_and_failed_application_details() {
        let mut report = rich_report();
        report.overall = Status::Fail;
        report.dns.status = Status::Fail;
        report.dns.addresses.clear();
        report.dns.error = Some("name not found".to_owned());
        report.routes.clear();
        report.tcp.clear();
        report.proxies.clear();
        report.diagnosis.likely_cause = None;
        report.diagnosis.suggestions.clear();
        report.diagnosis.notes.clear();
        let application = report.application_attempts.first_mut().unwrap();
        let tls = application.tls.as_mut().unwrap();
        tls.status = Status::Fail;
        tls.version = None;
        tls.cipher_suite = None;
        tls.error = None;
        let http = application.http.as_mut().unwrap();
        http.status = Status::Fail;
        http.status_line = None;
        http.error = Some("connection closed".to_owned());

        let output = render_human(&report);

        assert!(output.contains("[FAIL] DNS   0 addresses"));
        assert!(output.contains("Error: name not found"));
        assert!(output.contains("[SKIP] ROUTE No resolved destination"));
        assert!(output.contains("[SKIP] TCP   No resolved address"));
        assert!(output.contains("[FAIL] TLS"));
        assert!(output.contains("handshake failed"));
        assert!(output.contains("[FAIL] HTTP"));
        assert!(output.contains("connection closed"));
        assert!(!output.contains("Next steps:"));
        assert!(output.contains("Request: timeout 3000 ms"));
    }

    #[test]
    fn escapes_control_characters_in_human_output() {
        let mut report = rich_report();
        report.application_attempts[0]
            .http
            .as_mut()
            .unwrap()
            .status_line = Some("HTTP/1.1 200 OK\u{1b}[2J".to_owned());
        report.proxies[0].value = "http://proxy.test/\nforged".to_owned();

        let output = render_human(&report);

        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("\\u{1b}[2J"));
        assert!(output.contains("proxy.test/\\nforged"));
    }

    #[test]
    fn renders_unavailable_context_and_fallback_evidence() {
        let mut report = rich_report();
        report.target.host = "example.com".to_owned();
        report.request.execution_context.proxy_environment = ProxyEnvironmentStatus::Unavailable;
        report.routes[0].interface = None;
        report.routes[0].gateway = None;
        report.routes[0].source = None;
        report.routes[0].error = Some("permission denied".to_owned());
        let http = report.application_attempts[0].http.as_mut().unwrap();
        http.status_line = None;
        http.error = None;

        let output = render_human(&report);

        assert!(output.contains("Interpreted as: https://example.com:8443"));
        assert!(output.contains("proxy environment unavailable"));
        assert!(output.contains("error: permission denied"));
        assert!(output.contains("no response"));
    }

    #[test]
    fn renders_each_explicit_address_family_selection() {
        let mut report = rich_report();

        report.request.address_family = AddressFamilySelection::Ipv4;
        assert!(render_human(&report).contains("address family IPv4"));

        report.request.address_family = AddressFamilySelection::Ipv6;
        assert!(render_human(&report).contains("address family IPv6"));
    }

    fn rich_report() -> DiagnosticReport {
        let ipv6 = "[2001:db8::1]:8443".parse().unwrap();
        let ipv4 = "192.0.2.10:8443".parse().unwrap();
        DiagnosticReport {
            schema_version: 1,
            kind: "diagnostic_report".to_owned(),
            tool: ToolInfo::current(),
            generated_at_unix_ms: 0,
            duration_ms: 12,
            request: request_info(),
            target: TargetReport {
                original: "https://[2001:db8::1]:8443/health".to_owned(),
                scheme: "https".to_owned(),
                host: "2001:db8::1".to_owned(),
                port: 8443,
                url: Some("https://[2001:db8::1]:8443/health".to_owned()),
            },
            dns: DnsResult {
                status: Status::Pass,
                duration_ms: 2,
                addresses: vec![ipv6, ipv4],
                truncated: false,
                error_kind: None,
                error: None,
            },
            routes: vec![
                RouteResult {
                    status: Status::Pass,
                    address: ipv6,
                    interface: Some("wg0".to_owned()),
                    gateway: Some("192.0.2.1".to_owned()),
                    source: Some("192.0.2.2".to_owned()),
                    error_kind: None,
                    error: None,
                },
                RouteResult {
                    status: Status::Skip,
                    address: ipv4,
                    interface: None,
                    gateway: None,
                    source: None,
                    error_kind: None,
                    error: None,
                },
            ],
            tcp: vec![
                TcpResult {
                    status: Status::Pass,
                    address: ipv6,
                    family: AddressFamily::Ipv6,
                    duration_ms: 3,
                    error_kind: None,
                    error: None,
                },
                TcpResult {
                    status: Status::Fail,
                    address: ipv4,
                    family: AddressFamily::Ipv4,
                    duration_ms: 4,
                    error_kind: Some("timeout".to_owned()),
                    error: Some("timed out".to_owned()),
                },
            ],
            application_attempts: vec![ApplicationReport {
                status: Status::Warn,
                protocol: "https".to_owned(),
                address: ipv6,
                connect: successful_connect(3),
                tls: Some(TlsResult {
                    status: Status::Pass,
                    handshake_ms: 4,
                    trust_source: "mozilla_webpki_roots".to_owned(),
                    version: Some("TLSv1_3".to_owned()),
                    cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_owned()),
                    error: None,
                }),
                http: Some(HttpResult {
                    status: Status::Warn,
                    duration_ms: 5,
                    status_code: Some(503),
                    status_line: Some("HTTP/1.1 503 Service Unavailable".to_owned()),
                    error: None,
                }),
            }],
            proxies: vec![ProxyVariable {
                name: "HTTPS_PROXY".to_owned(),
                value: "http://proxy.test:8080".to_owned(),
            }],
            diagnosis: Diagnosis {
                code: DiagnosisCode::AddressFamilyPartial,
                summary: "IPv6 works, but IPv4 connectivity fails.".to_owned(),
                likely_cause: Some("partial connectivity".to_owned()),
                suggestions: vec!["Inspect the failing family.".to_owned()],
                notes: vec!["Tunnel route selected.".to_owned()],
            },
            overall: Status::Warn,
            exit_code: 0,
        }
    }

    fn request_info() -> RequestInfo {
        RequestInfo {
            timeout_ms: 3_000,
            address_family: AddressFamilySelection::Any,
            application_transport: "direct".to_owned(),
            proxy_mode: "detect_only".to_owned(),
            execution_context: ExecutionContextInfo::current(),
        }
    }

    fn successful_connect(duration_ms: u128) -> ApplicationConnectResult {
        ApplicationConnectResult {
            status: Status::Pass,
            duration_ms,
            error_kind: None,
            error: None,
        }
    }
}
