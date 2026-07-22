use std::fmt::Write as _;

use crate::{
    model::{
        AddressFamilySelection, CapabilityStatus, ContextRelation, DiagnosticReport,
        ExecutionContextInfo, ExecutionContextSource, PathEvidence, ProxyEnvironmentStatus, Status,
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
    write_proxy(&mut output, report);
    write_path_evidence(&mut output, report);
    write_plugins(&mut output, report);

    let _ = writeln!(output, "\nContext:");
    let _ = writeln!(
        output,
        "  Request: timeout {} ms · address family {} · transport {} · proxy mode {} · redaction {}",
        report.request.timeout_ms,
        address_family_name(report.request.address_family),
        report.request.application_transport,
        report.request.proxy_mode,
        report.request.redaction
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
        if let Some(mtu) = route.mtu {
            details.push(format!("mtu {mtu}"));
        }
        if let Some(advmss) = route.advmss {
            details.push(format!("advmss {advmss}"));
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
            if let Some(certificate) = tls.peer_certificates.first() {
                let _ = writeln!(
                    output,
                    "             Certificate: sha256 {} · {} bytes · subject {} · valid {}..{} · chain {}",
                    certificate.sha256,
                    certificate.der_bytes,
                    sanitize_report_text(certificate.subject.as_deref().unwrap_or("unavailable")),
                    certificate
                        .not_before_unix
                        .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                    certificate
                        .not_after_unix
                        .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                    tls.peer_certificates.len()
                );
            }
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

fn write_proxy(output: &mut String, report: &DiagnosticReport) {
    let proxy = &report.proxy_transport;
    if proxy.mode == "direct" && proxy.selected_proxy.is_none() {
        return;
    }
    let mut detail = proxy
        .selected_proxy
        .as_deref()
        .map_or_else(|| proxy.mode.clone(), sanitize_report_text);
    if proxy.bypassed {
        detail.push_str(" · bypassed by NO_PROXY");
    }
    if let Some(error) = &proxy.error {
        detail.push_str(" · error: ");
        detail.push_str(&sanitize_report_text(error));
    }
    let _ = writeln!(output, "  [{}] PROXY {detail}", status_name(proxy.status));
    for attempt in &proxy.attempts {
        let mut detail = attempt
            .error
            .as_deref()
            .map_or_else(|| "connected".to_owned(), sanitize_report_text);
        if let Some(status) = attempt.tunnel_status {
            let _ = write!(detail, " · CONNECT HTTP {status}");
        }
        let _ = writeln!(
            output,
            "             [{}] {} · {} ms · {detail}",
            status_name(attempt.status),
            attempt.address,
            attempt.duration_ms
        );
    }
}

fn write_path_evidence(output: &mut String, report: &DiagnosticReport) {
    let path = &report.path_evidence;
    write_firewall_and_mtu(output, path);
    write_preference_and_system_context(output, path);
}

fn write_firewall_and_mtu(output: &mut String, path: &PathEvidence) {
    let firewall_detail = path.firewall.error.as_deref().map_or_else(
        || {
            format!(
                "{} rules · {} relevant verdicts{}",
                path.firewall.inspected_rules,
                path.firewall.matches.len(),
                if path.firewall.incomplete {
                    " · partial predicate coverage"
                } else {
                    ""
                }
            )
        },
        sanitize_report_text,
    );
    let _ = writeln!(
        output,
        "  [{}] NFT   {firewall_detail}",
        status_name(path.firewall.status)
    );
    for mtu in &path.mtu {
        let detail = mtu.error.as_deref().map_or_else(
            || {
                format!(
                    "route {} · discovered {}",
                    mtu.route_mtu
                        .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                    mtu.discovered_pmtu
                        .map_or_else(|| "unknown".to_owned(), |value| value.to_string())
                )
            },
            sanitize_report_text,
        );
        let _ = writeln!(
            output,
            "  [{}] MTU   {} · {detail}",
            status_name(mtu.status),
            mtu.address.ip()
        );
    }
}

fn write_preference_and_system_context(output: &mut String, path: &PathEvidence) {
    let preference = &path.address_preference;
    let order = preference
        .resolver_order
        .iter()
        .map(|family| match family {
            crate::model::AddressFamily::Ipv4 => "IPv4",
            crate::model::AddressFamily::Ipv6 => "IPv6",
        })
        .collect::<Vec<_>>()
        .join(" then ");
    let _ = writeln!(
        output,
        "  [{}] PREF  {} · {}",
        status_name(preference.status),
        if order.is_empty() {
            "no addresses"
        } else {
            &order
        },
        preference.policy_source
    );
    let resolver = &path.resolver;
    let resolver_detail = resolver.error.as_deref().map_or_else(
        || {
            format!(
                "{} · {} global servers · {} links",
                resolver.manager,
                resolver.global_servers.len(),
                resolver.links.len()
            )
        },
        sanitize_report_text,
    );
    let _ = writeln!(
        output,
        "  [{}] DNSCFG {resolver_detail}",
        status_name(resolver.status)
    );
    let manager = &path.network_manager;
    let manager_detail = manager.error.as_deref().map_or_else(
        || {
            format!(
                "{} active connection{} · VPN {}",
                manager.active_connections.len(),
                if manager.active_connections.len() == 1 {
                    ""
                } else {
                    "s"
                },
                if manager.vpn_active {
                    "active"
                } else {
                    "not detected"
                }
            )
        },
        sanitize_report_text,
    );
    let _ = writeln!(
        output,
        "  [{}] NM    {manager_detail}",
        status_name(manager.status)
    );
}

fn write_plugins(output: &mut String, report: &DiagnosticReport) {
    for plugin in &report.plugins {
        let mut detail = sanitize_report_text(&plugin.summary);
        if let Some(error) = &plugin.error {
            detail.push_str(" · error: ");
            detail.push_str(&sanitize_report_text(error));
        }
        let _ = writeln!(
            output,
            "  [{}] PLUGIN {} · {detail}",
            status_name(plugin.status),
            sanitize_report_text(&plugin.name)
        );
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
        CapabilityStatus, CertificateInfo, ContextRelation, Diagnosis, DiagnosisCode,
        DiagnosticReport, DnsResult, ExecutionContextInfo, ExecutionContextSource, HttpResult,
        MtuResult, PluginResult, ProxyConnectResult, ProxyEnvironmentStatus,
        ProxyTransportEvidence, ProxyVariable, RequestInfo, RouteResult, Status, TargetReport,
        TcpResult, TlsResult, ToolInfo,
    };

    #[test]
    fn renders_rich_application_evidence_and_context() {
        let report = rich_report();

        let output = render_human(&report);

        assert!(output.starts_with(&format!(
            "NetWhy {}\nResult: WARN\n",
            env!("CARGO_PKG_VERSION")
        )));
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
        assert!(output.contains("Certificate: sha256 abcdef · 1024 bytes"));
        assert!(output.contains("[WARN] HTTP"));
        assert!(output.contains("[PASS] PROXY http://proxy.test:8080"));
        assert!(output.contains("CONNECT HTTP 200"));
        assert!(output.contains("[PASS] NFT"));
        assert!(output.contains("[PASS] MTU"));
        assert!(output.contains("[PASS] PREF"));
        assert!(output.contains("[PASS] DNSCFG"));
        assert!(output.contains("[PASS] NM"));
        assert!(output.contains("[PASS] PLUGIN sample · extra evidence"));
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
        let application = &mut report.application_attempts[0];
        let certificate = &mut application.tls.as_mut().unwrap().peer_certificates[0];
        certificate.subject = None;
        certificate.not_before_unix = None;
        certificate.not_after_unix = None;
        let http = application.http.as_mut().unwrap();
        http.status_line = None;
        http.error = None;
        report.proxy_transport.mode = "environment".to_owned();
        report.proxy_transport.selected_proxy = None;
        report.proxy_transport.bypassed = true;
        report.proxy_transport.error = Some("proxy unavailable".to_owned());
        report.proxy_transport.attempts[0].error = Some("connection refused".to_owned());
        report.proxy_transport.attempts[0].tunnel_status = None;
        report.path_evidence.mtu[0].route_mtu = None;
        report.path_evidence.mtu[0].discovered_pmtu = None;

        let output = render_human(&report);

        assert!(output.contains("Interpreted as: https://example.com:8443"));
        assert!(output.contains("proxy environment unavailable"));
        assert!(output.contains("error: permission denied"));
        assert!(output.contains("no response"));
        assert!(output.contains("subject unavailable · valid unknown..unknown"));
        assert!(output.contains("environment · bypassed by NO_PROXY · error: proxy unavailable"));
        assert!(output.contains("connection refused"));
        assert!(output.contains("route unknown · discovered unknown"));
    }

    #[test]
    fn renders_each_explicit_address_family_selection() {
        let mut report = rich_report();

        report.request.address_family = AddressFamilySelection::Ipv4;
        assert!(render_human(&report).contains("address family IPv4"));

        report.request.address_family = AddressFamilySelection::Ipv6;
        assert!(render_human(&report).contains("address family IPv6"));
    }

    #[allow(clippy::too_many_lines)]
    fn rich_report() -> DiagnosticReport {
        let ipv6 = "[2001:db8::1]:8443".parse().unwrap();
        let ipv4 = "192.0.2.10:8443".parse().unwrap();
        let mut report = DiagnosticReport {
            schema_version: crate::model::SCHEMA_VERSION,
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
                    mtu: Some(1420),
                    advmss: Some(1380),
                    error_kind: None,
                    error: None,
                },
                RouteResult {
                    status: Status::Skip,
                    address: ipv4,
                    interface: None,
                    gateway: None,
                    source: None,
                    mtu: None,
                    advmss: None,
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
                    peer_certificates: vec![CertificateInfo {
                        position: 0,
                        der_bytes: 1024,
                        sha256: "abcdef".to_owned(),
                        subject: Some("CN=example.test".to_owned()),
                        issuer: Some("CN=Test CA".to_owned()),
                        serial_number: Some("01".to_owned()),
                        not_before_unix: Some(1_700_000_000),
                        not_after_unix: Some(1_800_000_000),
                        dns_names: vec!["example.test".to_owned()],
                        ip_addresses: Vec::new(),
                    }],
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
            proxy_transport: ProxyTransportEvidence {
                status: Status::Pass,
                mode: "proxy".to_owned(),
                selected_proxy: Some("http://proxy.test:8080".to_owned()),
                bypassed: false,
                attempts: vec![ProxyConnectResult {
                    status: Status::Pass,
                    address: "192.0.2.20:8080".parse().unwrap(),
                    duration_ms: 1,
                    tunnel_status: Some(200),
                    error_kind: None,
                    error: None,
                }],
                error_kind: None,
                error: None,
            },
            path_evidence: crate::model::PathEvidence::default(),
            plugins: vec![PluginResult {
                protocol_version: 1,
                name: "sample".to_owned(),
                status: Status::Pass,
                summary: "extra evidence".to_owned(),
                evidence: serde_json::json!({"answer": 42}),
                error_kind: None,
                error: None,
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
        };
        report.path_evidence.firewall.status = Status::Pass;
        report.path_evidence.firewall.inspected_rules = 2;
        report.path_evidence.firewall.incomplete = true;
        report.path_evidence.mtu.push(MtuResult {
            status: Status::Pass,
            address: ipv6,
            route_mtu: Some(1420),
            discovered_pmtu: Some(1420),
            error_kind: None,
            error: None,
        });
        report.path_evidence.address_preference.status = Status::Pass;
        report.path_evidence.address_preference.resolver_order =
            vec![AddressFamily::Ipv6, AddressFamily::Ipv4];
        report.path_evidence.address_preference.policy_source = "system defaults".to_owned();
        report.path_evidence.resolver.status = Status::Pass;
        report.path_evidence.resolver.manager = "systemd-resolved".to_owned();
        report.path_evidence.resolver.global_servers = vec!["192.0.2.53".to_owned()];
        report.path_evidence.network_manager.status = Status::Pass;
        report.path_evidence.network_manager.vpn_active = true;
        report
    }

    fn request_info() -> RequestInfo {
        RequestInfo {
            timeout_ms: 3_000,
            address_family: AddressFamilySelection::Any,
            application_transport: "direct".to_owned(),
            proxy_mode: "direct".to_owned(),
            redaction: "standard".to_owned(),
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
