use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{net::lookup_host, time::timeout};
use url::Url;

use crate::{
    cli::{DiagnosticArgs, ProxyMode},
    model::{AddressFamilySelection, ProxyTransportEvidence, Status},
    sanitize_report_text,
    target::Target,
};

const MAX_PROXY_ADDRESSES: usize = 16;

#[derive(Debug, Clone)]
pub(crate) struct SelectedProxy {
    pub(crate) url: Url,
    pub(crate) redacted_url: String,
    pub(crate) addresses: Vec<SocketAddr>,
    pub(crate) address_family: AddressFamilySelection,
}

impl SelectedProxy {
    pub(crate) fn scheme(&self) -> &str {
        self.url.scheme()
    }

    pub(crate) fn host(&self) -> &str {
        self.url.host_str().expect("validated proxy has a host")
    }

    pub(crate) fn credentials(&self) -> Option<(String, String)> {
        if self.url.username().is_empty() && self.url.password().is_none() {
            return None;
        }
        Some((
            percent_decode(self.url.username()),
            self.url.password().map_or_else(String::new, percent_decode),
        ))
    }

    pub(crate) const fn allows_ip(&self, address: IpAddr) -> bool {
        address_family_allows(self.address_family, address)
    }
}

const fn address_family_allows(selection: AddressFamilySelection, address: IpAddr) -> bool {
    matches!(
        (selection, address),
        (AddressFamilySelection::Any, _)
            | (AddressFamilySelection::Ipv4, IpAddr::V4(_))
            | (AddressFamilySelection::Ipv6, IpAddr::V6(_))
    )
}

#[derive(Debug)]
pub(crate) enum ProxyPlan {
    Direct(ProxyTransportEvidence),
    Proxy(SelectedProxy),
    Unavailable(ProxyTransportEvidence),
}

pub(crate) fn validate_args(args: &DiagnosticArgs) -> Result<()> {
    if let Some(value) = &args.proxy_url {
        parse_proxy_url(value)?;
    }
    Ok(())
}

pub(crate) async fn plan(
    args: &DiagnosticArgs,
    target: &Target,
    environment: &[(String, String)],
    operation_timeout: Duration,
) -> Result<ProxyPlan> {
    let (mode, value) = if let Some(explicit) = &args.proxy_url {
        ("explicit", Some(explicit.clone()))
    } else if args.proxy_mode == ProxyMode::Environment {
        if no_proxy_matches(target, environment) {
            return Ok(ProxyPlan::Direct(ProxyTransportEvidence {
                status: Status::Pass,
                mode: "environment".to_owned(),
                selected_proxy: None,
                bypassed: true,
                attempts: Vec::new(),
                error_kind: None,
                error: None,
            }));
        }
        ("environment", select_environment_proxy(target, environment))
    } else {
        return Ok(ProxyPlan::Direct(ProxyTransportEvidence::default()));
    };

    let Some(value) = value else {
        return Ok(unavailable_proxy(
            mode,
            None,
            "not_configured",
            "proxy transport was requested but no applicable proxy was configured",
        ));
    };
    let address_family = if args.ipv4 {
        AddressFamilySelection::Ipv4
    } else if args.ipv6 {
        AddressFamilySelection::Ipv6
    } else {
        AddressFamilySelection::Any
    };
    resolve_proxy(mode, &value, target, address_family, operation_timeout).await
}

async fn resolve_proxy(
    mode: &str,
    value: &str,
    target: &Target,
    address_family: AddressFamilySelection,
    operation_timeout: Duration,
) -> Result<ProxyPlan> {
    let url = match parse_proxy_url(value) {
        Ok(url) => url,
        Err(error) if mode == "environment" => {
            return Ok(unavailable_proxy(
                mode,
                None,
                "invalid_config",
                &error.to_string(),
            ));
        }
        Err(error) => return Err(error),
    };
    let redacted_url = redact_url(&url);
    if address_family != AddressFamilySelection::Any {
        if let Some(address) = target.literal_address {
            if !address_family_allows(address_family, address.ip()) {
                return Ok(unavailable_proxy(
                    mode,
                    Some(redacted_url),
                    "no_addresses",
                    "the target IP address is excluded by the selected address family",
                ));
            }
        } else if url.scheme() != "socks5" {
            return Ok(unavailable_proxy(
                mode,
                Some(redacted_url),
                "invalid_config",
                "--ipv4/--ipv6 cannot be guaranteed when the selected proxy resolves the target hostname remotely; use a target IP address or a socks5:// proxy",
            ));
        }
    }
    let host = url
        .host_str()
        .expect("validated proxy has a host")
        .to_owned();
    let port = url.port_or_known_default().unwrap_or(1080);
    let resolved = timeout(operation_timeout, lookup_host((host, port))).await;
    let addresses = match resolved {
        Ok(Ok(addresses)) => {
            let mut seen = HashSet::new();
            addresses
                .filter(|address| address_family_allows(address_family, address.ip()))
                .filter(|address| seen.insert(*address))
                .take(MAX_PROXY_ADDRESSES)
                .collect::<Vec<_>>()
        }
        Ok(Err(error)) => {
            return Ok(unavailable_proxy(
                mode,
                Some(redacted_url),
                "resolver_error",
                &format!("could not resolve proxy host: {error}"),
            ));
        }
        Err(_) => {
            return Ok(unavailable_proxy(
                mode,
                Some(redacted_url),
                "timeout",
                &format!(
                    "proxy DNS resolution timed out after {} ms",
                    operation_timeout.as_millis()
                ),
            ));
        }
    };
    if addresses.is_empty() {
        return Ok(unavailable_proxy(
            mode,
            Some(redacted_url),
            "no_addresses",
            "proxy DNS resolution returned no addresses in the selected address family",
        ));
    }
    Ok(ProxyPlan::Proxy(SelectedProxy {
        url,
        redacted_url,
        addresses,
        address_family,
    }))
}

fn unavailable_proxy(
    mode: &str,
    selected_proxy: Option<String>,
    error_kind: &str,
    error: &str,
) -> ProxyPlan {
    ProxyPlan::Unavailable(ProxyTransportEvidence {
        status: Status::Fail,
        mode: mode.to_owned(),
        selected_proxy,
        bypassed: false,
        attempts: Vec::new(),
        error_kind: Some(error_kind.to_owned()),
        error: Some(sanitize_report_text(error)),
    })
}

fn parse_proxy_url(value: &str) -> Result<Url> {
    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("http://{value}")
    };
    let url = Url::parse(&candidate).context("invalid proxy URL")?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h") {
        bail!(
            "unsupported proxy scheme '{}'; use http, https, socks5, or socks5h",
            url.scheme()
        );
    }
    if url.host_str().is_none() {
        bail!("proxy URL must include a hostname or IP address");
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        bail!("proxy URL must not include a path, query, or fragment");
    }
    Ok(url)
}

fn select_environment_proxy(target: &Target, environment: &[(String, String)]) -> Option<String> {
    let names: &[&str] = if target.scheme == "https" {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    };
    names.iter().find_map(|name| {
        environment
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
    })
}

fn no_proxy_matches(target: &Target, environment: &[(String, String)]) -> bool {
    let value = ["NO_PROXY", "no_proxy"].iter().find_map(|name| {
        environment
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    });
    value.is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .any(|entry| no_proxy_entry_matches(entry, &target.host, target.port))
    })
}

fn no_proxy_entry_matches(entry: &str, host: &str, port: u16) -> bool {
    if entry == "*" {
        return true;
    }
    let (entry_host, entry_port) = split_no_proxy_port(entry);
    if entry_port.is_some_and(|expected| expected != port) {
        return false;
    }
    let entry_host = entry_host.trim_matches(['[', ']']).to_ascii_lowercase();
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if let (Ok(address), Some((network, prefix))) = (host.parse(), parse_cidr(&entry_host)) {
        return cidr_contains(network, prefix, address);
    }
    let suffix = entry_host.trim_start_matches('.');
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn split_no_proxy_port(entry: &str) -> (&str, Option<u16>) {
    if let Some(bracket) = entry
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
    {
        return (
            bracket.0,
            bracket
                .1
                .strip_prefix(':')
                .and_then(|value| value.parse().ok()),
        );
    }
    if entry.matches(':').count() == 1 {
        if let Some((host, port)) = entry.rsplit_once(':') {
            if let Ok(port) = port.parse() {
                return (host, Some(port));
            }
        }
    }
    (entry, None)
}

fn parse_cidr(value: &str) -> Option<(std::net::IpAddr, u8)> {
    let (address, prefix) = value.split_once('/')?;
    Some((address.parse().ok()?, prefix.parse().ok()?))
}

fn cidr_contains(network: std::net::IpAddr, prefix: u8, address: std::net::IpAddr) -> bool {
    match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    if !redacted.username().is_empty() || redacted.password().is_some() {
        let _ = redacted.set_username("<redacted>");
        let _ = redacted.set_password(None);
    }
    sanitize_report_text(redacted.as_str())
}

fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

pub(crate) fn basic_authorization(proxy: &SelectedProxy) -> Option<String> {
    let (username, password) = proxy.credentials()?;
    Some(format!(
        "Basic {}",
        base64(&format!("{username}:{password}"))
    ))
}

fn base64(value: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.as_bytes().chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        result.push(TABLE[usize::from(first >> 2)] as char);
        result.push(TABLE[usize::from((first & 0x03) << 4 | second >> 4)] as char);
        result.push(if chunk.len() > 1 {
            TABLE[usize::from((second & 0x0f) << 2 | third >> 6)] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            TABLE[usize::from(third & 0x3f)] as char
        } else {
            '='
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use super::{
        ProxyPlan, base64, basic_authorization, no_proxy_entry_matches, parse_proxy_url, plan,
        redact_url,
    };
    use crate::{cli::Cli, target::Target};

    #[test]
    fn validates_and_redacts_proxy_urls() {
        let url = parse_proxy_url("http://alice:secret@proxy.test:8080").unwrap();
        let redacted = redact_url(&url);
        assert_eq!(redacted, "http://%3Credacted%3E@proxy.test:8080/");
        assert!(!redacted.contains("secret"));
        assert!(parse_proxy_url("ftp://proxy.test").is_err());
        assert!(parse_proxy_url("http://proxy.test/path").is_err());
    }

    #[test]
    fn applies_domain_port_and_cidr_no_proxy_rules() {
        assert!(no_proxy_entry_matches(
            ".example.test",
            "api.example.test",
            443
        ));
        assert!(no_proxy_entry_matches(
            "api.example.test:443",
            "api.example.test",
            443
        ));
        assert!(!no_proxy_entry_matches(
            "api.example.test:80",
            "api.example.test",
            443
        ));
        assert!(no_proxy_entry_matches("10.0.0.0/8", "10.2.3.4", 443));
        assert!(!no_proxy_entry_matches("10.0.0.0/8", "192.0.2.1", 443));
    }

    #[test]
    fn encodes_basic_proxy_credentials() {
        assert_eq!(
            base64("Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
    }

    #[tokio::test]
    async fn environment_proxy_honors_no_proxy_without_resolving_the_proxy() {
        let cli = Cli::try_parse_from([
            "netwhy",
            "http://api.example.test/",
            "--proxy-mode",
            "environment",
        ])
        .unwrap();
        let target = Target::parse(&cli.target).unwrap();
        let environment = vec![
            (
                "HTTP_PROXY".to_owned(),
                "http://unresolvable.invalid:8080".to_owned(),
            ),
            ("NO_PROXY".to_owned(), ".example.test".to_owned()),
        ];

        let selected = plan(
            &cli.diagnostic,
            &target,
            &environment,
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        match selected {
            ProxyPlan::Direct(evidence) => {
                assert_eq!(evidence.mode, "environment");
                assert!(evidence.bypassed);
            }
            _ => panic!("NO_PROXY should have selected direct transport"),
        }
    }

    #[tokio::test]
    async fn invalid_environment_proxy_is_structured_evidence() {
        let cli = Cli::try_parse_from([
            "netwhy",
            "http://example.test/",
            "--proxy-mode",
            "environment",
        ])
        .unwrap();
        let target = Target::parse(&cli.target).unwrap();

        let selected = plan(
            &cli.diagnostic,
            &target,
            &[("HTTP_PROXY".to_owned(), "ftp://proxy.test".to_owned())],
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        match selected {
            ProxyPlan::Unavailable(evidence) => {
                assert_eq!(evidence.error_kind.as_deref(), Some("invalid_config"));
                assert_eq!(evidence.mode, "environment");
            }
            _ => panic!("invalid environment proxy should be unavailable evidence"),
        }
    }

    #[tokio::test]
    async fn proxy_plans_enforce_the_selected_address_family() {
        let ipv6_cli = Cli::try_parse_from([
            "netwhy",
            "--ipv6",
            "--proxy-url",
            "socks5://127.0.0.1:9",
            "example.test",
        ])
        .unwrap();
        let target = Target::parse(&ipv6_cli.target).unwrap();
        let selected = plan(
            &ipv6_cli.diagnostic,
            &target,
            &[],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let ProxyPlan::Unavailable(evidence) = selected else {
            panic!("an IPv4-only proxy endpoint must be excluded in IPv6 mode");
        };
        assert_eq!(evidence.error_kind.as_deref(), Some("no_addresses"));

        let remote_cli = Cli::try_parse_from([
            "netwhy",
            "--ipv4",
            "--proxy-url",
            "http://127.0.0.1:9",
            "example.test",
        ])
        .unwrap();
        let selected = plan(
            &remote_cli.diagnostic,
            &target,
            &[],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let ProxyPlan::Unavailable(evidence) = selected else {
            panic!("remote proxy DNS cannot guarantee an address-family selection");
        };
        assert_eq!(evidence.error_kind.as_deref(), Some("invalid_config"));

        let literal_cli = Cli::try_parse_from([
            "netwhy",
            "--ipv4",
            "--proxy-url",
            "http://127.0.0.1:9",
            "http://192.0.2.1/",
        ])
        .unwrap();
        let literal_target = Target::parse(&literal_cli.target).unwrap();
        let selected = plan(
            &literal_cli.diagnostic,
            &literal_target,
            &[],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let ProxyPlan::Proxy(selected) = selected else {
            panic!("matching literal targets remain valid with remote-resolving proxies");
        };
        assert!(selected.addresses.iter().all(std::net::SocketAddr::is_ipv4));
    }

    #[tokio::test]
    async fn covers_direct_environment_and_resolved_proxy_plans() {
        let direct_cli = Cli::try_parse_from(["netwhy", "http://example.test/"]).unwrap();
        let target = Target::parse(&direct_cli.target).unwrap();
        assert!(matches!(
            plan(
                &direct_cli.diagnostic,
                &target,
                &[],
                Duration::from_millis(100)
            )
            .await
            .unwrap(),
            ProxyPlan::Direct(_)
        ));

        let environment_cli = Cli::try_parse_from([
            "netwhy",
            "http://example.test/",
            "--proxy-mode",
            "environment",
        ])
        .unwrap();
        let unavailable = plan(
            &environment_cli.diagnostic,
            &target,
            &[],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert!(matches!(unavailable, ProxyPlan::Unavailable(_)));

        let environment = [("HTTP_PROXY".to_owned(), "127.0.0.1:9".to_owned())];
        let selected = plan(
            &environment_cli.diagnostic,
            &target,
            &environment,
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let ProxyPlan::Proxy(selected) = selected else {
            panic!("loopback proxy should resolve");
        };
        assert_eq!(selected.scheme(), "http");
        assert_eq!(selected.host(), "127.0.0.1");
        assert_eq!(selected.credentials(), None);

        let authenticated_cli = Cli::try_parse_from([
            "netwhy",
            "http://example.test/",
            "--proxy-url",
            "socks5://user%20name:pass%21@127.0.0.1:9",
        ])
        .unwrap();
        let authenticated = plan(
            &authenticated_cli.diagnostic,
            &target,
            &[],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        let ProxyPlan::Proxy(authenticated) = authenticated else {
            panic!("loopback proxy should resolve");
        };
        assert_eq!(
            authenticated.credentials(),
            Some(("user name".to_owned(), "pass!".to_owned()))
        );
        assert_eq!(
            basic_authorization(&authenticated).as_deref(),
            Some("Basic dXNlciBuYW1lOnBhc3Mh")
        );

        assert!(no_proxy_entry_matches("*", "anything.test", 443));
        assert!(no_proxy_entry_matches(
            "2001:db8::/32",
            "2001:db8::1234",
            443
        ));
        assert!(!no_proxy_entry_matches(
            "2001:db8::/129",
            "2001:db8::1234",
            443
        ));
    }
}
