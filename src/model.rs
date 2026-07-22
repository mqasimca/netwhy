use std::net::SocketAddr;

use serde::Serialize;

use crate::target::Target;

pub const SCHEMA_VERSION: u8 = 2;
pub const COMPARISON_SCHEMA_VERSION: u8 = 1;
pub const PLUGIN_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

impl ToolInfo {
    #[must_use]
    pub fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl Status {
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Fail)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticReport {
    pub schema_version: u8,
    pub kind: String,
    pub tool: ToolInfo,
    pub generated_at_unix_ms: u128,
    pub duration_ms: u128,
    pub request: RequestInfo,
    pub target: TargetReport,
    pub dns: DnsResult,
    pub routes: Vec<RouteResult>,
    pub tcp: Vec<TcpResult>,
    pub application_attempts: Vec<ApplicationReport>,
    pub proxies: Vec<ProxyVariable>,
    pub proxy_transport: ProxyTransportEvidence,
    pub path_evidence: PathEvidence,
    pub plugins: Vec<PluginResult>,
    pub diagnosis: Diagnosis,
    pub overall: Status,
    pub exit_code: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestInfo {
    pub timeout_ms: u64,
    pub address_family: AddressFamilySelection,
    pub application_transport: String,
    pub proxy_mode: String,
    pub redaction: String,
    pub execution_context: ExecutionContextInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionContextInfo {
    pub source: ExecutionContextSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_container: Option<String>,
    pub network_namespace: ContextRelation,
    pub mount_namespace: ContextRelation,
    pub filesystem_root: ContextRelation,
    pub proxy_environment: ProxyEnvironmentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_error: Option<String>,
    pub required_capabilities: Vec<String>,
    pub capability_status: CapabilityStatus,
}

impl ExecutionContextInfo {
    #[must_use]
    pub fn current() -> Self {
        Self {
            source: ExecutionContextSource::CurrentProcess,
            target_pid: None,
            target_container: None,
            network_namespace: ContextRelation::Current,
            mount_namespace: ContextRelation::Current,
            filesystem_root: ContextRelation::Current,
            proxy_environment: ProxyEnvironmentStatus::CurrentProcess,
            proxy_error: None,
            required_capabilities: Vec::new(),
            capability_status: CapabilityStatus::NotRequired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionContextSource {
    CurrentProcess,
    Process,
    Docker,
    Podman,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextRelation {
    Current,
    Shared,
    Entered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyEnvironmentStatus {
    CurrentProcess,
    SelectedProcess,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    NotRequired,
    Available,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamilySelection {
    Any,
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub original: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl From<&Target> for TargetReport {
    fn from(target: &Target) -> Self {
        Self {
            original: target.original_report_value(),
            scheme: target.scheme.clone(),
            host: target.host.clone(),
            port: target.port,
            url: target.url.as_ref().map(|_| target.url_report_value()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsResult {
    pub status: Status,
    pub duration_ms: u128,
    pub addresses: Vec<SocketAddr>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteResult {
    pub status: Status,
    pub address: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advmss: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpResult {
    pub status: Status,
    pub address: SocketAddr,
    pub family: AddressFamily,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl From<&SocketAddr> for AddressFamily {
    fn from(address: &SocketAddr) -> Self {
        if address.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplicationReport {
    pub status: Status,
    pub protocol: String,
    pub address: SocketAddr,
    pub connect: ApplicationConnectResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplicationConnectResult {
    pub status: Status,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsResult {
    pub status: Status,
    pub handshake_ms: u128,
    pub trust_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    pub peer_certificates: Vec<CertificateInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub position: usize,
    pub der_bytes: usize,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after_unix: Option<i64>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpResult {
    pub status: Status,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyVariable {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyTransportEvidence {
    pub status: Status,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_proxy: Option<String>,
    pub bypassed: bool,
    pub attempts: Vec<ProxyConnectResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for ProxyTransportEvidence {
    fn default() -> Self {
        Self {
            status: Status::Skip,
            mode: "direct".to_owned(),
            selected_proxy: None,
            bypassed: false,
            attempts: Vec::new(),
            error_kind: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyConnectResult {
    pub status: Status,
    pub address: SocketAddr,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PathEvidence {
    pub firewall: FirewallEvidence,
    pub mtu: Vec<MtuResult>,
    pub address_preference: AddressPreferenceEvidence,
    pub resolver: ResolverEvidence,
    pub network_manager: NetworkManagerEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallEvidence {
    pub status: Status,
    pub mode: String,
    pub inspected_rules: usize,
    pub relevant_base_chains: Vec<String>,
    pub matches: Vec<FirewallMatch>,
    pub incomplete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for FirewallEvidence {
    fn default() -> Self {
        Self {
            status: Status::Skip,
            mode: "static_read_only".to_owned(),
            inspected_rules: 0,
            relevant_base_chains: Vec::new(),
            matches: Vec::new(),
            incomplete: true,
            error_kind: Some("not_run".to_owned()),
            error: Some("nftables evidence was not collected".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallMatch {
    pub table: String,
    pub chain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<u64>,
    pub verdict: String,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MtuResult {
    pub status: Status,
    pub address: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_pmtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddressPreferenceEvidence {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_resolved_family: Option<AddressFamily>,
    pub resolver_order: Vec<AddressFamily>,
    pub policy_source: String,
    pub policy_rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for AddressPreferenceEvidence {
    fn default() -> Self {
        Self {
            status: Status::Skip,
            first_resolved_family: None,
            resolver_order: Vec::new(),
            policy_source: "system_default".to_owned(),
            policy_rules: Vec::new(),
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverEvidence {
    pub status: Status,
    pub manager: String,
    pub global_servers: Vec<String>,
    pub global_domains: Vec<String>,
    pub links: Vec<ResolverLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for ResolverEvidence {
    fn default() -> Self {
        Self {
            status: Status::Skip,
            manager: "system_resolver".to_owned(),
            global_servers: Vec::new(),
            global_domains: Vec::new(),
            links: Vec::new(),
            error_kind: Some("not_run".to_owned()),
            error: Some("per-link resolver evidence was not collected".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverLink {
    pub index: u32,
    pub name: String,
    pub servers: Vec<String>,
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_route: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkManagerEvidence {
    pub status: Status,
    pub active_connections: Vec<ActiveConnection>,
    pub vpn_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for NetworkManagerEvidence {
    fn default() -> Self {
        Self {
            status: Status::Skip,
            active_connections: Vec::new(),
            vpn_active: false,
            error_kind: Some("not_run".to_owned()),
            error: Some("NetworkManager evidence was not collected".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveConnection {
    pub name: String,
    pub connection_type: String,
    pub device: String,
    pub vpn: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginResult {
    pub protocol_version: u8,
    pub name: String,
    pub status: Status,
    pub summary: String,
    pub evidence: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonReport {
    pub schema_version: u8,
    pub kind: String,
    pub tool: ToolInfo,
    pub left: ComparisonInput,
    pub right: ComparisonInput,
    pub changes: Vec<ComparisonChange>,
    pub truncated: bool,
    pub summary: String,
    pub overall: Status,
    pub exit_code: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonInput {
    pub path: String,
    pub report_schema_version: u64,
    pub target: String,
    pub execution_context: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonChange {
    pub path: String,
    pub significance: String,
    pub left: serde_json::Value,
    pub right: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosisCode {
    ConnectivityOk,
    DnsResolutionFailed,
    TcpConnectionRefused,
    NoRoute,
    TcpTimeout,
    TcpConnectFailed,
    AddressFamilyPartial,
    ApplicationAddressPartial,
    ApplicationConnectFailed,
    ProxyConnectionFailed,
    TlsHandshakeFailed,
    HttpExchangeFailed,
    HttpErrorStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnosis {
    pub code: DiagnosisCode,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub likely_cause: Option<String>,
    pub suggestions: Vec<String>,
    pub notes: Vec<String>,
}

impl Default for Diagnosis {
    fn default() -> Self {
        Self {
            code: DiagnosisCode::ConnectivityOk,
            summary: String::new(),
            likely_cause: None,
            suggestions: Vec::new(),
            notes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidInvocation,
    InvalidTarget,
    ContextUnavailable,
    OutputError,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
    pub hint: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorReport {
    pub schema_version: u8,
    pub kind: String,
    pub tool: ToolInfo,
    pub overall: Status,
    pub exit_code: u8,
    pub error: ErrorDetail,
}

impl ErrorReport {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>, hint: impl Into<String>) -> Self {
        let retryable = matches!(code, ErrorCode::OutputError);
        Self {
            schema_version: SCHEMA_VERSION,
            kind: "error".to_owned(),
            tool: ToolInfo::current(),
            overall: Status::Fail,
            exit_code: 2,
            error: ErrorDetail {
                code,
                message: message.into(),
                hint: hint.into(),
                retryable,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressFamily, ErrorCode, ErrorReport};

    #[test]
    fn only_output_errors_are_retryable() {
        assert!(
            ErrorReport::new(ErrorCode::OutputError, "write failed", "retry")
                .error
                .retryable
        );
        assert!(
            !ErrorReport::new(ErrorCode::InvalidTarget, "bad target", "fix it")
                .error
                .retryable
        );
        assert!(
            !ErrorReport::new(ErrorCode::ContextUnavailable, "bad context", "fix it")
                .error
                .retryable
        );
    }

    #[test]
    fn derives_address_family_from_socket_address() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();

        assert_eq!(AddressFamily::from(&ipv4), AddressFamily::Ipv4);
        assert_eq!(AddressFamily::from(&ipv6), AddressFamily::Ipv6);
    }
}
