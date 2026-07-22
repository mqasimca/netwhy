use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde_json::json;

use crate::{cli::RedactionLevel, model::DiagnosticReport};

pub fn apply(report: &mut DiagnosticReport, level: RedactionLevel) {
    match level {
        RedactionLevel::Standard => "standard",
        RedactionLevel::Strict => "strict",
    }
    .clone_into(&mut report.request.redaction);
    if level == RedactionLevel::Standard {
        return;
    }

    redact_report_identity(report);
    redact_network_evidence(report);
    redact_proxy_evidence(report);
    redact_path_evidence(report);
    redact_plugins_and_diagnosis(report);
}

fn redact_report_identity(report: &mut DiagnosticReport) {
    let redacted_host = pseudonym("host", &report.target.host);
    report.target.host = format!("{redacted_host}.redacted");
    report.target.original = format!(
        "{}://{}:{}",
        report.target.scheme, report.target.host, report.target.port
    );
    if report.target.url.is_some() {
        report.target.url = Some(format!(
            "{}://{}:{}/REDACTED",
            report.target.scheme, report.target.host, report.target.port
        ));
    }
    if let Some(container) = report.request.execution_context.target_container.as_mut() {
        *container = pseudonym("container", container);
    }
    if report.request.execution_context.target_pid.is_some() {
        report.request.execution_context.target_pid = Some(1);
    }
    redact_optional_error(&mut report.request.execution_context.proxy_error);
}

fn redact_network_evidence(report: &mut DiagnosticReport) {
    for address in &mut report.dns.addresses {
        *address = redact_socket(*address);
    }
    for route in &mut report.routes {
        route.address = redact_socket(route.address);
        route.interface = route
            .interface
            .as_deref()
            .map(|value| pseudonym("interface", value));
        route.gateway = route.gateway.as_deref().map(redact_address_text);
        route.source = route.source.as_deref().map(redact_address_text);
        redact_optional_error(&mut route.error);
    }
    for tcp in &mut report.tcp {
        tcp.address = redact_socket(tcp.address);
        redact_optional_error(&mut tcp.error);
    }
    redact_optional_error(&mut report.dns.error);
    for application in &mut report.application_attempts {
        application.address = redact_socket(application.address);
        redact_optional_error(&mut application.connect.error);
        if let Some(tls) = application.tls.as_mut() {
            redact_optional_error(&mut tls.error);
            for certificate in &mut tls.peer_certificates {
                certificate.subject = certificate
                    .subject
                    .as_deref()
                    .map(|value| pseudonym("subject", value));
                certificate.issuer = certificate
                    .issuer
                    .as_deref()
                    .map(|value| pseudonym("issuer", value));
                certificate.serial_number = certificate
                    .serial_number
                    .as_deref()
                    .map(|value| pseudonym("serial", value));
                certificate.sha256 = format!(
                    "{0:016x}{0:016x}{0:016x}{0:016x}",
                    stable_hash(&certificate.sha256)
                );
                certificate.dns_names = certificate
                    .dns_names
                    .iter()
                    .map(|value| format!("{}.redacted", pseudonym("dns", value)))
                    .collect();
                certificate.ip_addresses = certificate
                    .ip_addresses
                    .iter()
                    .map(|value| redact_address_text(value))
                    .collect();
            }
        }
        if let Some(http) = application.http.as_mut() {
            redact_optional_error(&mut http.error);
        }
    }
}

fn redact_proxy_evidence(report: &mut DiagnosticReport) {
    for proxy in &mut report.proxies {
        proxy.value = pseudonym("proxy", &proxy.value);
    }
    report.proxy_transport.selected_proxy = report
        .proxy_transport
        .selected_proxy
        .as_deref()
        .map(|value| pseudonym("proxy", value));
    redact_optional_error(&mut report.proxy_transport.error);
    for attempt in &mut report.proxy_transport.attempts {
        attempt.address = redact_socket(attempt.address);
        redact_optional_error(&mut attempt.error);
    }
}

fn redact_path_evidence(report: &mut DiagnosticReport) {
    for rule in &mut report.path_evidence.firewall.matches {
        rule.table = pseudonym("table", &rule.table);
        rule.chain = pseudonym("chain", &rule.chain);
        rule.comment = rule.comment.as_deref().map(|_| "REDACTED".to_owned());
    }
    report.path_evidence.firewall.relevant_base_chains = report
        .path_evidence
        .firewall
        .relevant_base_chains
        .iter()
        .map(|value| pseudonym("chain", value))
        .collect();
    for mtu in &mut report.path_evidence.mtu {
        mtu.address = redact_socket(mtu.address);
        redact_optional_error(&mut mtu.error);
    }
    redact_optional_error(&mut report.path_evidence.firewall.error);
    redact_optional_error(&mut report.path_evidence.address_preference.error);
    for rule in &mut report.path_evidence.address_preference.policy_rules {
        "REDACTED".clone_into(rule);
    }
    redact_optional_error(&mut report.path_evidence.resolver.error);
    redact_optional_error(&mut report.path_evidence.network_manager.error);
    for server in &mut report.path_evidence.resolver.global_servers {
        *server = redact_address_text(server);
    }
    for domain in &mut report.path_evidence.resolver.global_domains {
        *domain = format!("{}.redacted", pseudonym("domain", domain));
    }
    for link in &mut report.path_evidence.resolver.links {
        link.name = pseudonym("interface", &link.name);
        for server in &mut link.servers {
            *server = redact_address_text(server);
        }
        for domain in &mut link.domains {
            *domain = format!("{}.redacted", pseudonym("domain", domain));
        }
    }
    for connection in &mut report.path_evidence.network_manager.active_connections {
        connection.name = pseudonym("connection", &connection.name);
        connection.device = pseudonym("interface", &connection.device);
    }
}

fn redact_plugins_and_diagnosis(report: &mut DiagnosticReport) {
    for plugin in &mut report.plugins {
        plugin.name = pseudonym("plugin", &plugin.name);
        "Plugin summary redacted by strict report policy.".clone_into(&mut plugin.summary);
        plugin.evidence = json!({"redacted": true});
        plugin.error_kind = plugin.error_kind.as_deref().map(|_| "REDACTED".to_owned());
        plugin.error = plugin.error.as_deref().map(|_| "REDACTED".to_owned());
    }
    if report.diagnosis.likely_cause.is_some() {
        report.diagnosis.likely_cause =
            Some("Cause details were redacted by the strict report policy.".to_owned());
    }
    report.diagnosis.notes =
        vec!["Sensitive context details were pseudonymized by strict report redaction.".to_owned()];
}

fn redact_optional_error(error: &mut Option<String>) {
    if error.is_some() {
        *error = Some("REDACTED".to_owned());
    }
}

fn redact_socket(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(redact_ip(address.ip()), address.port())
}

fn redact_ip(address: IpAddr) -> IpAddr {
    let hash = stable_hash(&address.to_string());
    match address {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(
            192,
            0,
            2,
            u8::try_from((hash % 254) + 1).expect("modulo result always fits in u8"),
        )),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0x0db8,
            0,
            0,
            0,
            0,
            ((hash >> 16) & 0xffff) as u16,
            (hash & 0xffff) as u16,
        )),
    }
}

fn redact_address_text(value: &str) -> String {
    value.parse::<IpAddr>().map_or_else(
        |_| pseudonym("value", value),
        |address| redact_ip(address).to_string(),
    )
}

fn pseudonym(kind: &str, value: &str) -> String {
    format!("{kind}-{:016x}", stable_hash(value))
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{apply, redact_ip, stable_hash};
    use crate::{
        cli::RedactionLevel,
        model::{
            ActiveConnection, AddressFamily, AddressFamilySelection, AddressPreferenceEvidence,
            ApplicationConnectResult, ApplicationReport, CapabilityStatus, CertificateInfo,
            ContextRelation, Diagnosis, DiagnosisCode, DiagnosticReport, DnsResult,
            ExecutionContextInfo, ExecutionContextSource, FirewallEvidence, FirewallMatch,
            HttpResult, MtuResult, NetworkManagerEvidence, PathEvidence, PluginResult,
            ProxyConnectResult, ProxyEnvironmentStatus, ProxyTransportEvidence, ProxyVariable,
            RequestInfo, ResolverEvidence, ResolverLink, RouteResult, SCHEMA_VERSION, Status,
            TargetReport, TcpResult, TlsResult, ToolInfo,
        },
    };

    #[test]
    fn pseudonyms_are_stable_and_use_documentation_ranges() {
        assert_eq!(stable_hash("same"), stable_hash("same"));
        assert_ne!(stable_hash("same"), stable_hash("different"));

        let ipv4 = redact_ip("10.0.0.1".parse().unwrap());
        let ipv6 = redact_ip("fd00::1".parse().unwrap());
        assert!(ipv4.to_string().starts_with("192.0.2."));
        assert!(ipv6.to_string().starts_with("2001:db8:"));
    }

    #[test]
    fn strict_policy_redacts_every_sensitive_evidence_family_and_matches_schema() {
        let mut standard = sensitive_report();
        apply(&mut standard, RedactionLevel::Standard);
        assert_eq!(standard.request.redaction, "standard");
        assert_eq!(standard.target.host, "internal.example");

        let original_fingerprint = standard.application_attempts[0]
            .tls
            .as_ref()
            .unwrap()
            .peer_certificates[0]
            .sha256
            .clone();
        apply(&mut standard, RedactionLevel::Strict);

        let serialized = serde_json::to_string(&standard).unwrap();
        for secret in [
            "internal.example",
            "10.0.0.8",
            "corp-proxy",
            "secret-container",
            "secret-plugin-payload",
            "corp.example",
            "CN=internal.example",
            "serial-secret",
        ] {
            assert!(
                !serialized.contains(secret),
                "strict report leaked {secret}"
            );
        }
        assert_eq!(standard.request.execution_context.target_pid, Some(1));
        assert_eq!(
            standard.path_evidence.address_preference.policy_rules,
            ["REDACTED"]
        );
        assert_eq!(
            standard.plugins[0].evidence,
            serde_json::json!({"redacted": true})
        );
        assert_eq!(standard.plugins[0].error_kind.as_deref(), Some("REDACTED"));
        let certificate = &standard.application_attempts[0]
            .tls
            .as_ref()
            .unwrap()
            .peer_certificates[0];
        assert_ne!(certificate.sha256, original_fingerprint);
        assert_eq!(certificate.sha256.len(), 64);

        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let instance = serde_json::to_value(&standard).unwrap();
        let errors = validator
            .iter_errors(&instance)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "schema errors: {errors:#?}");
    }

    #[allow(clippy::too_many_lines)]
    fn sensitive_report() -> DiagnosticReport {
        let address = "10.0.0.8:443".parse().unwrap();
        DiagnosticReport {
            schema_version: SCHEMA_VERSION,
            kind: "diagnostic_report".to_owned(),
            tool: ToolInfo::current(),
            generated_at_unix_ms: 1,
            duration_ms: 2,
            request: RequestInfo {
                timeout_ms: 100,
                address_family: AddressFamilySelection::Any,
                application_transport: "proxy".to_owned(),
                proxy_mode: "explicit".to_owned(),
                redaction: "standard".to_owned(),
                execution_context: ExecutionContextInfo {
                    source: ExecutionContextSource::Docker,
                    target_pid: Some(4242),
                    target_container: Some("secret-container".to_owned()),
                    network_namespace: ContextRelation::Entered,
                    mount_namespace: ContextRelation::Entered,
                    filesystem_root: ContextRelation::Entered,
                    proxy_environment: ProxyEnvironmentStatus::Unavailable,
                    proxy_error: Some("environment secret".to_owned()),
                    required_capabilities: vec!["CAP_SYS_ADMIN".to_owned()],
                    capability_status: CapabilityStatus::Available,
                },
            },
            target: TargetReport {
                original: "https://internal.example/private".to_owned(),
                scheme: "https".to_owned(),
                host: "internal.example".to_owned(),
                port: 443,
                url: Some("https://internal.example/private".to_owned()),
            },
            dns: DnsResult {
                status: Status::Pass,
                duration_ms: 1,
                addresses: vec![address],
                truncated: false,
                error_kind: Some("resolver_error".to_owned()),
                error: Some("resolver secret".to_owned()),
            },
            routes: vec![RouteResult {
                status: Status::Pass,
                address,
                interface: Some("corp0".to_owned()),
                gateway: Some("10.0.0.1".to_owned()),
                source: Some("source-alias".to_owned()),
                mtu: Some(1400),
                advmss: Some(1360),
                error_kind: Some("tool_failed".to_owned()),
                error: Some("route secret".to_owned()),
            }],
            tcp: vec![TcpResult {
                status: Status::Pass,
                address,
                family: AddressFamily::Ipv4,
                duration_ms: 1,
                error_kind: Some("other".to_owned()),
                error: Some("tcp secret".to_owned()),
            }],
            application_attempts: vec![ApplicationReport {
                status: Status::Fail,
                protocol: "https".to_owned(),
                address,
                connect: ApplicationConnectResult {
                    status: Status::Pass,
                    duration_ms: 1,
                    error_kind: Some("other".to_owned()),
                    error: Some("connect secret".to_owned()),
                },
                tls: Some(TlsResult {
                    status: Status::Pass,
                    handshake_ms: 1,
                    trust_source: "mozilla_webpki_roots".to_owned(),
                    version: Some("TLSv1_3".to_owned()),
                    cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_owned()),
                    peer_certificates: vec![CertificateInfo {
                        position: 0,
                        der_bytes: 100,
                        sha256: "a".repeat(64),
                        subject: Some("CN=internal.example".to_owned()),
                        issuer: Some("CN=corp-ca".to_owned()),
                        serial_number: Some("serial-secret".to_owned()),
                        not_before_unix: Some(1),
                        not_after_unix: Some(2),
                        dns_names: vec!["internal.example".to_owned()],
                        ip_addresses: vec!["10.0.0.8".to_owned(), "alias-ip".to_owned()],
                    }],
                    error: Some("tls secret".to_owned()),
                }),
                http: Some(HttpResult {
                    status: Status::Fail,
                    duration_ms: 1,
                    status_code: None,
                    status_line: None,
                    error: Some("http secret".to_owned()),
                }),
            }],
            proxies: vec![ProxyVariable {
                name: "HTTPS_PROXY".to_owned(),
                value: "http://corp-proxy:8080".to_owned(),
            }],
            proxy_transport: ProxyTransportEvidence {
                status: Status::Fail,
                mode: "proxy".to_owned(),
                selected_proxy: Some("http://corp-proxy:8080/".to_owned()),
                bypassed: false,
                attempts: vec![ProxyConnectResult {
                    status: Status::Fail,
                    address: "10.0.0.9:8080".parse().unwrap(),
                    duration_ms: 1,
                    tunnel_status: None,
                    error_kind: Some("other".to_owned()),
                    error: Some("proxy secret".to_owned()),
                }],
                error_kind: Some("other".to_owned()),
                error: Some("proxy preparation secret".to_owned()),
            },
            path_evidence: sensitive_path_evidence(address),
            plugins: vec![PluginResult {
                protocol_version: 1,
                name: "secret-plugin".to_owned(),
                status: Status::Warn,
                summary: "plugin secret".to_owned(),
                evidence: serde_json::json!({"value":"secret-plugin-payload"}),
                error_kind: Some("provider_error".to_owned()),
                error: Some("plugin error secret".to_owned()),
            }],
            diagnosis: Diagnosis {
                code: DiagnosisCode::TlsHandshakeFailed,
                summary: "TLS failed".to_owned(),
                likely_cause: Some("cause secret".to_owned()),
                suggestions: Vec::new(),
                notes: vec!["note secret".to_owned()],
            },
            overall: Status::Fail,
            exit_code: 1,
        }
    }

    fn sensitive_path_evidence(address: std::net::SocketAddr) -> PathEvidence {
        PathEvidence {
            firewall: FirewallEvidence {
                status: Status::Warn,
                mode: "static_read_only".to_owned(),
                inspected_rules: 1,
                relevant_base_chains: vec!["inet/corp/output".to_owned()],
                matches: vec![FirewallMatch {
                    table: "corp".to_owned(),
                    chain: "output".to_owned(),
                    handle: Some(1),
                    verdict: "drop".to_owned(),
                    confidence: "exact".to_owned(),
                    comment: Some("secret firewall comment".to_owned()),
                }],
                incomplete: false,
                error_kind: Some("tool_failed".to_owned()),
                error: Some("firewall secret".to_owned()),
            },
            mtu: vec![MtuResult {
                status: Status::Warn,
                address,
                route_mtu: Some(1400),
                discovered_pmtu: Some(1300),
                error_kind: Some("probe_failed".to_owned()),
                error: Some("mtu secret".to_owned()),
            }],
            address_preference: AddressPreferenceEvidence {
                status: Status::Pass,
                first_resolved_family: Some(AddressFamily::Ipv4),
                resolver_order: vec![AddressFamily::Ipv4],
                policy_source: "/etc/gai.conf".to_owned(),
                policy_rules: vec!["precedence fd00::/8 100".to_owned()],
                error: Some("preference secret".to_owned()),
            },
            resolver: ResolverEvidence {
                status: Status::Pass,
                manager: "systemd-resolved".to_owned(),
                global_servers: vec!["10.0.0.53".to_owned(), "server-alias".to_owned()],
                global_domains: vec!["corp.example".to_owned()],
                links: vec![ResolverLink {
                    index: 2,
                    name: "corp0".to_owned(),
                    servers: vec!["10.0.0.54".to_owned()],
                    domains: vec!["link.corp.example".to_owned()],
                    default_route: Some(true),
                }],
                error_kind: Some("tool_failed".to_owned()),
                error: Some("resolver context secret".to_owned()),
            },
            network_manager: NetworkManagerEvidence {
                status: Status::Pass,
                active_connections: vec![ActiveConnection {
                    name: "corp vpn".to_owned(),
                    connection_type: "wireguard".to_owned(),
                    device: "wg-secret".to_owned(),
                    vpn: true,
                }],
                vpn_active: true,
                error_kind: Some("tool_failed".to_owned()),
                error: Some("network manager secret".to_owned()),
            },
        }
    }
}
