use crate::model::{AddressFamily, DiagnosisCode, DiagnosticReport, Status};

pub fn explain(report: &mut DiagnosticReport) {
    let mut suggestions = Vec::new();
    let notes = context_notes(report);

    if report.dns.status == Status::Fail {
        diagnose_dns_failure(report, &mut suggestions);
        finish(report, suggestions, notes);
        return;
    }

    let successful = report
        .tcp
        .iter()
        .filter(|result| result.status == Status::Pass)
        .count();
    if successful == 0 {
        diagnose_tcp_failure(report, &mut suggestions);
        finish(report, suggestions, notes);
        return;
    }

    let partial_family_failure = diagnose_family_asymmetry(report, &mut suggestions);
    let application_failed = !report.application_attempts.is_empty()
        && report
            .application_attempts
            .iter()
            .all(|application| application.status == Status::Fail);
    if application_failed {
        diagnose_application_failure(report, &mut suggestions);
        finish(report, suggestions, notes);
        return;
    }

    if diagnose_http_error(report, &mut suggestions) {
        finish(report, suggestions, notes);
        return;
    }

    let partial_application_failure = report
        .application_attempts
        .iter()
        .any(|application| application.status == Status::Fail)
        && report
            .application_attempts
            .iter()
            .any(|application| application.status != Status::Fail);
    if partial_application_failure {
        report.overall = Status::Warn;
        report.diagnosis.code = DiagnosisCode::ApplicationAddressPartial;
        set_summary(
            report,
            "The application protocol succeeded on one address after failing on another.",
        );
        report.diagnosis.likely_cause = Some(
            "the resolved addresses do not provide equivalent application behavior".to_owned(),
        );
        suggestions.push(
            "Compare the per-address application attempts and check load balancer or dual-stack configuration."
                .to_owned(),
        );
    } else if partial_family_failure {
        report.overall = Status::Warn;
    } else {
        report.overall = Status::Pass;
        report.diagnosis.code = DiagnosisCode::ConnectivityOk;
        let summary = if report.application_attempts.is_empty() {
            "DNS, routing, and TCP connectivity succeeded."
        } else {
            "DNS, routing, TCP, and the application protocol all succeeded."
        };
        set_summary(report, summary);
    }
    finish(report, suggestions, notes);
}

fn context_notes(report: &DiagnosticReport) -> Vec<String> {
    let mut notes = Vec::new();
    if !report.proxies.is_empty() {
        notes.push(
            "Proxy environment variables are set; this version tests the target directly and bypasses HTTP proxies."
                .to_owned(),
        );
    }
    if report.dns.truncated {
        notes.push(
            "DNS returned more than 32 unique addresses; probes were capped at the first 32."
                .to_owned(),
        );
    }

    let interfaces = report
        .routes
        .iter()
        .filter_map(|route| route.interface.as_deref())
        .filter(|interface| is_tunnel(interface))
        .collect::<Vec<_>>();
    if !interfaces.is_empty() {
        notes.push(format!(
            "The selected route uses a tunnel or VPN interface: {}.",
            interfaces.join(", ")
        ));
    }
    notes
}

fn diagnose_dns_failure(report: &mut DiagnosticReport, suggestions: &mut Vec<String>) {
    report.overall = Status::Fail;
    report.diagnosis.code = DiagnosisCode::DnsResolutionFailed;
    set_summary(report, "DNS resolution failed.");
    report.diagnosis.likely_cause = Some(
        report
            .dns
            .error
            .clone()
            .unwrap_or_else(|| "the system resolver returned no usable address".to_owned()),
    );
    suggestions.push("Inspect `resolvectl status` and `/etc/resolv.conf`.".to_owned());
    suggestions.push(
        "Try the hostname with `getent ahosts <host>` to confirm system resolver behavior."
            .to_owned(),
    );
}

fn diagnose_tcp_failure(report: &mut DiagnosticReport, suggestions: &mut Vec<String>) {
    report.overall = Status::Fail;
    let all_refused = all_tcp_errors(report, &["connection_refused"]);
    let has_no_route = all_tcp_errors(report, &["network_unreachable", "host_unreachable"])
        || (!report.routes.is_empty()
            && report
                .routes
                .iter()
                .all(|route| route.error_kind.as_deref() == Some("no_route")));

    if all_refused {
        report.diagnosis.code = DiagnosisCode::TcpConnectionRefused;
        set_summary(
            report,
            "The host is reachable, but the TCP port refused the connection.",
        );
        report.diagnosis.likely_cause = Some(
            "nothing is listening on the target port, or a firewall is actively rejecting it"
                .to_owned(),
        );
        suggestions.push(
            "Verify the host and port, then check listening sockets with `ss -lntp`.".to_owned(),
        );
    } else if has_no_route {
        report.diagnosis.code = DiagnosisCode::NoRoute;
        set_summary(report, "No usable network route reached the target.");
        report.diagnosis.likely_cause = Some(
            "a missing route, disconnected interface, or VPN policy is preventing delivery"
                .to_owned(),
        );
        suggestions
            .push("Inspect `ip route`, `ip -6 route`, and active VPN interfaces.".to_owned());
    } else if all_tcp_errors(report, &["timeout"]) {
        report.diagnosis.code = DiagnosisCode::TcpTimeout;
        set_summary(report, "Every TCP connection attempt timed out.");
        report.diagnosis.likely_cause = Some(
            "traffic is probably being dropped by a firewall, broken route, or unreachable service"
                .to_owned(),
        );
        suggestions.push(
            "Check local firewall rules, VPN routing, and the remote service's allowlist."
                .to_owned(),
        );
    } else {
        report.diagnosis.code = DiagnosisCode::TcpConnectFailed;
        set_summary(report, "Every TCP connection attempt failed.");
        report.diagnosis.likely_cause = report.tcp.iter().find_map(|result| result.error.clone());
        suggestions.push(
            "Review the per-address errors to identify the failing network layer.".to_owned(),
        );
    }
}

fn diagnose_family_asymmetry(report: &mut DiagnosticReport, suggestions: &mut Vec<String>) -> bool {
    match (
        family_state(report, AddressFamily::Ipv4),
        family_state(report, AddressFamily::Ipv6),
    ) {
        (Some(true), Some(false)) => {
            report.diagnosis.code = DiagnosisCode::AddressFamilyPartial;
            set_summary(report, "IPv4 works, but IPv6 connectivity fails.");
            report.diagnosis.likely_cause = Some(
                "the IPv6 route, VPN policy, or upstream IPv6 connectivity is broken".to_owned(),
            );
            suggestions.push(
                "Compare with `netwhy --ipv4 <target>` and inspect `ip -6 route`.".to_owned(),
            );
            true
        }
        (Some(false), Some(true)) => {
            report.diagnosis.code = DiagnosisCode::AddressFamilyPartial;
            set_summary(report, "IPv6 works, but IPv4 connectivity fails.");
            report.diagnosis.likely_cause = Some(
                "the IPv4 route, NAT, firewall policy, or upstream IPv4 connectivity is broken"
                    .to_owned(),
            );
            suggestions
                .push("Compare with `netwhy --ipv6 <target>` and inspect `ip route`.".to_owned());
            true
        }
        _ => false,
    }
}

fn diagnose_application_failure(report: &mut DiagnosticReport, suggestions: &mut Vec<String>) {
    report.overall = Status::Fail;
    let (connect_failed, tls_failed, cause) = {
        let application = selected_application(report).expect("checked by caller");
        let connect_failed = application.connect.status == Status::Fail;
        let tls_failed = application
            .tls
            .as_ref()
            .is_some_and(|tls| tls.status == Status::Fail);
        let cause = if connect_failed {
            application.connect.error.clone()
        } else if tls_failed {
            application.tls.as_ref().and_then(|tls| tls.error.clone())
        } else {
            application
                .http
                .as_ref()
                .and_then(|http| http.error.clone())
        };
        (connect_failed, tls_failed, cause)
    };

    if connect_failed {
        report.diagnosis.code = DiagnosisCode::ApplicationConnectFailed;
        set_summary(
            report,
            "The initial TCP probe succeeded, but every application reconnect failed.",
        );
        report.diagnosis.likely_cause = cause;
        suggestions.push(
            "Check whether the service is intermittent, rate-limited, or closing connections between probes."
                .to_owned(),
        );
    } else if tls_failed {
        report.diagnosis.code = DiagnosisCode::TlsHandshakeFailed;
        set_summary(report, "TCP connects, but the TLS handshake fails.");
        report.diagnosis.likely_cause = cause;
        suggestions.push(
            "Check the certificate name, trust chain, system clock, SNI, and supported TLS versions."
                .to_owned(),
        );
    } else {
        report.diagnosis.code = DiagnosisCode::HttpExchangeFailed;
        set_summary(
            report,
            "The transport connects, but the HTTP exchange fails.",
        );
        report.diagnosis.likely_cause = cause;
        suggestions.push("Confirm that the port serves HTTP and accepts HEAD requests.".to_owned());
    }
}

fn diagnose_http_error(report: &mut DiagnosticReport, suggestions: &mut Vec<String>) -> bool {
    let code = report
        .application_attempts
        .iter()
        .find(|application| application.status != Status::Fail)
        .and_then(|application| application.http.as_ref())
        .and_then(|http| http.status_code);
    let Some(code) = code.filter(|code| *code >= 400) else {
        return false;
    };

    report.overall = Status::Warn;
    report.diagnosis.code = DiagnosisCode::HttpErrorStatus;
    report.diagnosis.summary =
        format!("Network connectivity works; the server returned HTTP {code}.");
    report.diagnosis.likely_cause = Some(
        if code >= 500 {
            "the remote application or its upstream dependency is failing"
        } else {
            "the endpoint rejected the request, often because of authentication, authorization, or path rules"
        }
        .to_owned(),
    );
    suggestions
        .push("Use an application-authenticated request to verify endpoint behavior.".to_owned());
    true
}

fn finish(report: &mut DiagnosticReport, suggestions: Vec<String>, notes: Vec<String>) {
    report.diagnosis.suggestions = suggestions;
    report.diagnosis.notes = notes;
    report.exit_code = u8::from(report.overall.is_failure());
}

fn set_summary(report: &mut DiagnosticReport, summary: &str) {
    summary.clone_into(&mut report.diagnosis.summary);
}

fn all_tcp_errors(report: &DiagnosticReport, kinds: &[&str]) -> bool {
    !report.tcp.is_empty()
        && report.tcp.iter().all(|result| {
            result
                .error_kind
                .as_deref()
                .is_some_and(|kind| kinds.contains(&kind))
        })
}

fn selected_application(report: &DiagnosticReport) -> Option<&crate::model::ApplicationReport> {
    report
        .application_attempts
        .iter()
        .find(|application| application.status != Status::Fail)
        .or_else(|| report.application_attempts.first())
}

/// Returns `None` when the family was not resolved, otherwise whether any address connected.
fn family_state(report: &DiagnosticReport, family: AddressFamily) -> Option<bool> {
    let family_results = report
        .tcp
        .iter()
        .filter(|result| result.family == family)
        .collect::<Vec<_>>();
    (!family_results.is_empty()).then(|| {
        family_results
            .iter()
            .any(|result| result.status == Status::Pass)
    })
}

fn is_tunnel(interface: &str) -> bool {
    ["wg", "tun", "tap", "tailscale", "zt", "vpn"]
        .iter()
        .any(|prefix| interface.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::explain;
    use crate::model::{
        AddressFamily, AddressFamilySelection, ApplicationConnectResult, ApplicationReport,
        Diagnosis, DiagnosisCode, DiagnosticReport, DnsResult, HttpResult, ProxyVariable,
        RequestInfo, RouteResult, Status, TargetReport, TcpResult, ToolInfo,
    };

    #[test]
    fn explains_tcp_timeout() {
        let address = "192.0.2.1:443".parse().unwrap();
        let mut report = report_with_tcp(vec![failed_tcp(address, AddressFamily::Ipv4)]);

        explain(&mut report);

        assert_eq!(report.overall, Status::Fail);
        assert_eq!(report.diagnosis.code, DiagnosisCode::TcpTimeout);
        assert_eq!(report.exit_code, 1);
        assert!(report.diagnosis.summary.contains("timed out"));
    }

    #[test]
    fn warns_when_only_ipv4_works() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();
        let mut report = report_with_tcp(vec![
            TcpResult {
                status: Status::Pass,
                address: ipv4,
                family: AddressFamily::Ipv4,
                duration_ms: 1,
                error_kind: None,
                error: None,
            },
            failed_tcp(ipv6, AddressFamily::Ipv6),
        ]);

        explain(&mut report);

        assert_eq!(report.overall, Status::Warn);
        assert_eq!(report.diagnosis.code, DiagnosisCode::AddressFamilyPartial);
        assert_eq!(report.exit_code, 0);
        assert!(report.diagnosis.summary.contains("IPv4 works"));
    }

    #[test]
    fn explains_dns_failure_with_proxy_and_tunnel_context() {
        let address = "192.0.2.1:443".parse().unwrap();
        let mut report = report_with_tcp(vec![passed_tcp(address, AddressFamily::Ipv4)]);
        report.dns.status = Status::Fail;
        report.dns.addresses.clear();
        report.routes[0].interface = Some("wg0".to_owned());
        report.proxies.push(ProxyVariable {
            name: "HTTPS_PROXY".to_owned(),
            value: "http://proxy.test:8080".to_owned(),
        });

        explain(&mut report);

        assert_eq!(report.diagnosis.code, DiagnosisCode::DnsResolutionFailed);
        assert_eq!(report.exit_code, 1);
        assert!(
            report
                .diagnosis
                .likely_cause
                .as_deref()
                .is_some_and(|cause| cause.contains("no usable address"))
        );
        assert_eq!(report.diagnosis.notes.len(), 2);
    }

    #[test]
    fn explains_failed_route_as_no_route() {
        let address = "192.0.2.1:443".parse().unwrap();
        let mut report = report_with_tcp(vec![failed_tcp_with(
            address,
            AddressFamily::Ipv4,
            "connection_reset",
        )]);
        report.routes[0].status = Status::Fail;
        report.routes[0].error_kind = Some("no_route".to_owned());

        explain(&mut report);

        assert_eq!(report.diagnosis.code, DiagnosisCode::NoRoute);
        assert!(report.diagnosis.summary.contains("No usable network route"));
    }

    #[test]
    fn explains_unclassified_tcp_failure() {
        let address = "192.0.2.1:443".parse().unwrap();
        let mut report = report_with_tcp(vec![failed_tcp_with(
            address,
            AddressFamily::Ipv4,
            "connection_reset",
        )]);

        explain(&mut report);

        assert_eq!(report.diagnosis.code, DiagnosisCode::TcpConnectFailed);
        assert_eq!(report.diagnosis.likely_cause.as_deref(), Some("failed"));
    }

    #[test]
    fn mixed_tcp_errors_do_not_claim_every_attempt_timed_out() {
        let first = "192.0.2.1:443".parse().unwrap();
        let second = "192.0.2.2:443".parse().unwrap();
        let mut report = report_with_tcp(vec![
            failed_tcp(first, AddressFamily::Ipv4),
            failed_tcp_with(second, AddressFamily::Ipv4, "connection_reset"),
        ]);

        explain(&mut report);

        assert_eq!(report.diagnosis.code, DiagnosisCode::TcpConnectFailed);
        assert!(!report.diagnosis.summary.contains("timed out"));
    }

    #[test]
    fn route_tool_failure_does_not_become_no_route() {
        let address = "192.0.2.1:443".parse().unwrap();
        let mut report = report_with_tcp(vec![failed_tcp_with(
            address,
            AddressFamily::Ipv4,
            "connection_reset",
        )]);
        report.routes[0].status = Status::Skip;
        report.routes[0].error_kind = Some("tool_failed".to_owned());

        explain(&mut report);

        assert_eq!(report.diagnosis.code, DiagnosisCode::TcpConnectFailed);
    }

    #[test]
    fn warns_when_only_ipv6_works() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();
        let mut report = report_with_tcp(vec![
            failed_tcp(ipv4, AddressFamily::Ipv4),
            passed_tcp(ipv6, AddressFamily::Ipv6),
        ]);

        explain(&mut report);

        assert_eq!(report.overall, Status::Warn);
        assert_eq!(report.diagnosis.code, DiagnosisCode::AddressFamilyPartial);
        assert!(report.diagnosis.summary.contains("IPv6 works"));
    }

    #[test]
    fn classifies_http_client_error_as_reachable() {
        let address = "192.0.2.1:80".parse().unwrap();
        let mut report = report_with_tcp(vec![passed_tcp(address, AddressFamily::Ipv4)]);
        report.application_attempts = vec![ApplicationReport {
            status: Status::Warn,
            protocol: "http".to_owned(),
            address,
            connect: ApplicationConnectResult {
                status: Status::Pass,
                duration_ms: 1,
                error_kind: None,
                error: None,
            },
            tls: None,
            http: Some(HttpResult {
                status: Status::Warn,
                duration_ms: 1,
                status_code: Some(404),
                status_line: Some("HTTP/1.1 404 Not Found".to_owned()),
                error: None,
            }),
        }];

        explain(&mut report);

        assert_eq!(report.overall, Status::Warn);
        assert_eq!(report.diagnosis.code, DiagnosisCode::HttpErrorStatus);
        assert!(
            report
                .diagnosis
                .likely_cause
                .as_deref()
                .is_some_and(|cause| cause.contains("rejected"))
        );
    }

    #[test]
    fn distinguishes_application_reconnect_failure_from_tls() {
        let address = "192.0.2.1:443".parse().unwrap();
        let mut report = report_with_tcp(vec![passed_tcp(address, AddressFamily::Ipv4)]);
        report.application_attempts = vec![ApplicationReport {
            status: Status::Fail,
            protocol: "https".to_owned(),
            address,
            connect: ApplicationConnectResult {
                status: Status::Fail,
                duration_ms: 1,
                error_kind: Some("connection_refused".to_owned()),
                error: Some("connection refused".to_owned()),
            },
            tls: None,
            http: None,
        }];

        explain(&mut report);

        assert_eq!(
            report.diagnosis.code,
            DiagnosisCode::ApplicationConnectFailed
        );
        assert!(report.diagnosis.summary.contains("application reconnect"));
    }

    #[test]
    fn warns_when_application_succeeds_after_an_address_failure() {
        let first = "192.0.2.1:80".parse().unwrap();
        let second = "192.0.2.2:80".parse().unwrap();
        let mut report = report_with_tcp(vec![
            passed_tcp(first, AddressFamily::Ipv4),
            passed_tcp(second, AddressFamily::Ipv4),
        ]);
        report.application_attempts = vec![
            ApplicationReport {
                status: Status::Fail,
                protocol: "http".to_owned(),
                address: first,
                connect: ApplicationConnectResult {
                    status: Status::Fail,
                    duration_ms: 1,
                    error_kind: Some("connection_reset".to_owned()),
                    error: Some("reset".to_owned()),
                },
                tls: None,
                http: None,
            },
            ApplicationReport {
                status: Status::Pass,
                protocol: "http".to_owned(),
                address: second,
                connect: ApplicationConnectResult {
                    status: Status::Pass,
                    duration_ms: 1,
                    error_kind: None,
                    error: None,
                },
                tls: None,
                http: Some(HttpResult {
                    status: Status::Pass,
                    duration_ms: 1,
                    status_code: Some(200),
                    status_line: Some("HTTP/1.1 200 OK".to_owned()),
                    error: None,
                }),
            },
        ];

        explain(&mut report);

        assert_eq!(report.overall, Status::Warn);
        assert_eq!(
            report.diagnosis.code,
            DiagnosisCode::ApplicationAddressPartial
        );
    }

    fn report_with_tcp(tcp: Vec<TcpResult>) -> DiagnosticReport {
        let addresses = tcp.iter().map(|result| result.address).collect::<Vec<_>>();
        let routes = addresses
            .iter()
            .copied()
            .map(|address| RouteResult {
                status: Status::Pass,
                address,
                interface: Some("eth0".to_owned()),
                gateway: None,
                source: None,
                error_kind: None,
                error: None,
            })
            .collect();
        DiagnosticReport {
            schema_version: 1,
            kind: "diagnostic_report".to_owned(),
            tool: ToolInfo::current(),
            generated_at_unix_ms: 0,
            duration_ms: 0,
            request: RequestInfo {
                timeout_ms: 3_000,
                address_family: AddressFamilySelection::Any,
                application_transport: "direct".to_owned(),
                proxy_mode: "detect_only".to_owned(),
            },
            target: TargetReport {
                original: "example.test".to_owned(),
                scheme: "tcp".to_owned(),
                host: "example.test".to_owned(),
                port: 443,
                url: None,
            },
            dns: DnsResult {
                status: Status::Pass,
                duration_ms: 0,
                addresses,
                truncated: false,
                error_kind: None,
                error: None,
            },
            routes,
            tcp,
            application_attempts: Vec::new(),
            proxies: Vec::new(),
            diagnosis: Diagnosis::default(),
            overall: Status::Skip,
            exit_code: 2,
        }
    }

    fn failed_tcp(address: SocketAddr, family: AddressFamily) -> TcpResult {
        failed_tcp_with(address, family, "timeout")
    }

    fn failed_tcp_with(address: SocketAddr, family: AddressFamily, error_kind: &str) -> TcpResult {
        TcpResult {
            status: Status::Fail,
            address,
            family,
            duration_ms: 10,
            error_kind: Some(error_kind.to_owned()),
            error: Some("failed".to_owned()),
        }
    }

    fn passed_tcp(address: SocketAddr, family: AddressFamily) -> TcpResult {
        TcpResult {
            status: Status::Pass,
            address,
            family,
            duration_ms: 1,
            error_kind: None,
            error: None,
        }
    }
}
