use std::{
    collections::{BTreeSet, HashMap},
    ffi::OsStr,
    fs::File,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};
use serde_json::Value;
use tokio::task::JoinSet;

use crate::{
    command::{BoundedCommandError, BoundedOutput, run_bounded},
    model::{
        ActiveConnection, AddressFamily, AddressPreferenceEvidence, FirewallEvidence,
        FirewallMatch, MtuResult, NetworkManagerEvidence, PathEvidence, ResolverEvidence,
        ResolverLink, RouteResult, Status,
    },
    sanitize_report_text,
};

const STANDARD_OUTPUT_LIMIT: usize = 256 * 1024;
const NFT_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const GAI_CONF_LIMIT: usize = 64 * 1024;

pub async fn collect(
    addresses: &[SocketAddr],
    routes: &[RouteResult],
    operation_timeout: Duration,
) -> PathEvidence {
    let address_preference = inspect_address_preference(addresses);
    let (firewall, mtu, resolver, network_manager) = tokio::join!(
        inspect_firewall(addresses, routes, operation_timeout),
        inspect_mtu(addresses, routes, operation_timeout),
        inspect_resolver(operation_timeout),
        inspect_network_manager(operation_timeout),
    );
    PathEvidence {
        firewall,
        mtu,
        address_preference,
        resolver,
        network_manager,
    }
}

fn inspect_address_preference(addresses: &[SocketAddr]) -> AddressPreferenceEvidence {
    let mut resolver_order = Vec::new();
    for address in addresses {
        let family = AddressFamily::from(address);
        if !resolver_order.contains(&family) {
            resolver_order.push(family);
        }
    }

    let mut evidence = AddressPreferenceEvidence {
        status: if addresses.is_empty() {
            Status::Skip
        } else {
            Status::Pass
        },
        first_resolved_family: resolver_order.first().copied(),
        resolver_order,
        policy_source: "RFC 6724 system defaults".to_owned(),
        policy_rules: Vec::new(),
        error: None,
    };

    match read_bounded_file(Path::new("/etc/gai.conf"), GAI_CONF_LIMIT) {
        Ok((_, true)) => {
            evidence.error = Some("/etc/gai.conf exceeded the 64 KiB safety limit".to_owned());
        }
        Ok((bytes, false)) => {
            let text = String::from_utf8_lossy(&bytes);
            evidence.policy_rules = text
                .lines()
                .map(str::trim)
                .filter(|line| {
                    !line.starts_with('#')
                        && (line.starts_with("label ")
                            || line.starts_with("precedence ")
                            || line.starts_with("reload "))
                })
                .take(64)
                .map(sanitize_report_text)
                .collect();
            if !evidence.policy_rules.is_empty() {
                "/etc/gai.conf overrides".clone_into(&mut evidence.policy_source);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => evidence.error = Some(sanitize_report_text(error.to_string())),
    }
    evidence
}

fn read_bounded_file(path: &Path, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let file = File::from(
        open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bounded input is not a regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .ok()
            .unwrap_or_default()
            .min(limit),
    );
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > limit;
    if truncated {
        bytes.truncate(limit);
    }
    Ok((bytes, truncated))
}

#[cfg(target_os = "linux")]
async fn inspect_firewall(
    addresses: &[SocketAddr],
    routes: &[RouteResult],
    operation_timeout: Duration,
) -> FirewallEvidence {
    let output = run_bounded(
        OsStr::new("nft"),
        ["--json", "list", "ruleset"],
        operation_timeout,
        NFT_OUTPUT_LIMIT,
    )
    .await;
    match output {
        Ok(output) => parse_nft_output(addresses, routes, &output),
        Err(BoundedCommandError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            skipped_firewall("tool_missing", "nft is not installed")
        }
        Err(BoundedCommandError::Io(error)) => skipped_firewall("tool_failed", &error.to_string()),
        Err(BoundedCommandError::Timeout) => {
            skipped_firewall("timeout", "nftables inspection timed out")
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn inspect_firewall(
    _addresses: &[SocketAddr],
    _routes: &[RouteResult],
    _operation_timeout: Duration,
) -> FirewallEvidence {
    skipped_firewall(
        "unsupported_platform",
        "nftables evidence is available on Linux only",
    )
}

fn parse_nft_output(
    addresses: &[SocketAddr],
    routes: &[RouteResult],
    output: &BoundedOutput,
) -> FirewallEvidence {
    if output.stdout.truncated || output.stderr.truncated {
        return skipped_firewall("output_truncated", "nft output exceeded the safety limit");
    }
    if !output.status.success() {
        let error = command_error(output, "nft failed without an error message");
        let kind = if error.to_ascii_lowercase().contains("permission denied")
            || error
                .to_ascii_lowercase()
                .contains("operation not permitted")
        {
            "permission_denied"
        } else {
            "tool_failed"
        };
        return skipped_firewall(kind, &error);
    }
    match parse_nft_ruleset(addresses, routes, &output.stdout.bytes) {
        Ok(evidence) => evidence,
        Err(error) => skipped_firewall("parse_error", &error),
    }
}

fn parse_nft_ruleset(
    addresses: &[SocketAddr],
    routes: &[RouteResult],
    bytes: &[u8],
) -> Result<FirewallEvidence, String> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid nftables JSON: {error}"))?;
    let entries = document
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nftables JSON did not contain an nftables array".to_owned())?;

    let mut relevant_chains = BTreeSet::new();
    let mut matches = Vec::new();
    let mut inspected_rules = 0;
    let mut incomplete = false;
    for entry in entries {
        if let Some(chain) = entry.get("chain") {
            let hook = chain.get("hook").and_then(Value::as_str);
            if matches!(hook, Some("output" | "postrouting")) {
                let family = string_value(chain, "family");
                let table = string_value(chain, "table");
                let name = string_value(chain, "name");
                relevant_chains.insert(format!("{family}/{table}/{name}"));
                if let Some(policy) = chain
                    .get("policy")
                    .and_then(Value::as_str)
                    .filter(|_| family_applicability(&family, addresses) != Applicability::No)
                {
                    incomplete = true;
                    matches.push(FirewallMatch {
                        table: format!("{family}/{table}"),
                        chain: name,
                        handle: None,
                        verdict: format!("policy:{policy}"),
                        confidence: "possible".to_owned(),
                        comment: None,
                    });
                }
            }
            continue;
        }
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        inspected_rules += 1;
        let family = string_value(rule, "family");
        let table = string_value(rule, "table");
        let chain = string_value(rule, "chain");
        if !relevant_chains.contains(&format!("{family}/{table}/{chain}")) {
            continue;
        }
        let expressions = rule
            .get("expr")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let Some(verdict) = expressions.iter().find_map(extract_verdict) else {
            continue;
        };
        let applicability = rule_applicability(&family, expressions, addresses, routes);
        if applicability == Applicability::No {
            continue;
        }
        incomplete |= applicability == Applicability::Possible
            || matches!(verdict.as_str(), "jump" | "goto" | "return" | "continue");
        matches.push(FirewallMatch {
            table: format!("{family}/{table}"),
            chain,
            handle: rule.get("handle").and_then(Value::as_u64),
            verdict,
            confidence: if applicability == Applicability::Exact {
                "exact"
            } else {
                "possible"
            }
            .to_owned(),
            comment: rule
                .get("comment")
                .and_then(Value::as_str)
                .map(sanitize_report_text),
        });
    }

    Ok(FirewallEvidence {
        status: Status::Pass,
        mode: "static_read_only".to_owned(),
        inspected_rules,
        relevant_base_chains: relevant_chains.into_iter().collect(),
        matches,
        incomplete,
        error_kind: None,
        error: None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Applicability {
    No,
    Exact,
    Possible,
}

fn rule_applicability(
    family: &str,
    expressions: &[Value],
    addresses: &[SocketAddr],
    routes: &[RouteResult],
) -> Applicability {
    let family = family_applicability(family, addresses);
    if family == Applicability::No {
        return Applicability::No;
    }
    let mut possible = family == Applicability::Possible;
    for expression in expressions {
        let Some(matcher) = expression.get("match") else {
            if !is_non_predicate_expression(expression) {
                possible = true;
            }
            continue;
        };
        match evaluate_match(matcher, addresses, routes) {
            Some(false) => return Applicability::No,
            Some(true) => {}
            None => possible = true,
        }
    }
    if possible {
        Applicability::Possible
    } else {
        Applicability::Exact
    }
}

fn family_applicability(family: &str, addresses: &[SocketAddr]) -> Applicability {
    match family {
        "ip" if addresses.iter().any(SocketAddr::is_ipv4) => Applicability::Exact,
        "ip6" if addresses.iter().any(SocketAddr::is_ipv6) => Applicability::Exact,
        "ip" | "ip6" => Applicability::No,
        "inet" if addresses.is_empty() => Applicability::No,
        "inet" => Applicability::Exact,
        _ if addresses.is_empty() => Applicability::No,
        _ => Applicability::Possible,
    }
}

fn is_non_predicate_expression(expression: &Value) -> bool {
    extract_verdict(expression).is_some()
        || expression.as_object().is_some_and(|object| {
            !object.is_empty()
                && object
                    .keys()
                    .all(|key| matches!(key.as_str(), "counter" | "comment" | "log"))
        })
}

fn evaluate_match(
    matcher: &Value,
    addresses: &[SocketAddr],
    routes: &[RouteResult],
) -> Option<bool> {
    if matcher.get("op").and_then(Value::as_str) != Some("==") {
        return None;
    }
    let left = matcher.get("left")?;
    let right = matcher.get("right")?;
    if let Some(payload) = left.get("payload") {
        let protocol = payload.get("protocol").and_then(Value::as_str);
        let field = payload.get("field").and_then(Value::as_str)?;
        return match field {
            "daddr" => {
                let expected = right.as_str()?.parse::<IpAddr>().ok()?;
                match (protocol, expected) {
                    (Some("ip"), IpAddr::V4(_)) | (Some("ip6"), IpAddr::V6(_)) => {
                        Some(addresses.iter().any(|address| address.ip() == expected))
                    }
                    (Some("ip" | "ip6"), _) => Some(false),
                    _ => None,
                }
            }
            "dport" => {
                let expected = u16::try_from(right.as_u64()?).ok()?;
                match protocol {
                    Some("tcp") => Some(addresses.iter().any(|address| address.port() == expected)),
                    Some("udp") => Some(false),
                    _ => None,
                }
            }
            _ => None,
        };
    }
    if left
        .get("meta")
        .and_then(|meta| meta.get("key"))
        .and_then(Value::as_str)
        == Some("oifname")
    {
        let expected = right.as_str()?;
        return Some(
            routes
                .iter()
                .filter_map(|route| route.interface.as_deref())
                .any(|interface| interface == expected),
        );
    }
    None
}

fn extract_verdict(expression: &Value) -> Option<String> {
    for verdict in [
        "accept", "drop", "reject", "return", "continue", "jump", "goto",
    ] {
        if let Some(value) = expression.get(verdict) {
            return Some(if let Some(target) = value.as_str() {
                format!("{verdict}:{target}")
            } else {
                verdict.to_owned()
            });
        }
    }
    None
}

fn string_value(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .map_or_else(|| "unknown".to_owned(), sanitize_report_text)
}

fn skipped_firewall(kind: &str, error: &str) -> FirewallEvidence {
    FirewallEvidence {
        error_kind: Some(kind.to_owned()),
        error: Some(sanitize_report_text(error)),
        ..FirewallEvidence::default()
    }
}

#[cfg(target_os = "linux")]
async fn inspect_mtu(
    addresses: &[SocketAddr],
    routes: &[RouteResult],
    operation_timeout: Duration,
) -> Vec<MtuResult> {
    let route_mtu = routes
        .iter()
        .map(|route| (route.address, route.mtu))
        .collect::<HashMap<_, _>>();
    let mut tasks = JoinSet::new();
    for (index, address) in addresses.iter().copied().enumerate() {
        let route_mtu = route_mtu.get(&address).copied().flatten();
        tasks.spawn(async move {
            (
                index,
                inspect_one_mtu(address, route_mtu, operation_timeout).await,
            )
        });
    }
    let mut results = std::iter::repeat_with(|| None)
        .take(addresses.len())
        .collect::<Vec<_>>();
    while let Some(result) = tasks.join_next().await {
        if let Ok((index, evidence)) = result {
            results[index] = Some(evidence);
        }
    }
    results
        .into_iter()
        .zip(addresses.iter().copied())
        .map(|(result, address)| {
            result.unwrap_or(MtuResult {
                status: Status::Skip,
                address,
                route_mtu: None,
                discovered_pmtu: None,
                error_kind: Some("tool_failed".to_owned()),
                error: Some("MTU probe task stopped before producing evidence".to_owned()),
            })
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
async fn inspect_mtu(
    addresses: &[SocketAddr],
    routes: &[RouteResult],
    _operation_timeout: Duration,
) -> Vec<MtuResult> {
    addresses
        .iter()
        .copied()
        .map(|address| MtuResult {
            status: Status::Skip,
            address,
            route_mtu: routes
                .iter()
                .find(|route| route.address == address)
                .and_then(|route| route.mtu),
            discovered_pmtu: None,
            error_kind: Some("unsupported_platform".to_owned()),
            error: Some("active MTU evidence is available on Linux only".to_owned()),
        })
        .collect()
}

#[cfg(target_os = "linux")]
async fn inspect_one_mtu(
    address: SocketAddr,
    route_mtu: Option<u32>,
    operation_timeout: Duration,
) -> MtuResult {
    let port = address.port().to_string();
    let destination = tracepath_destination(address);
    let output = run_bounded(
        OsStr::new("tracepath"),
        ["-n", "-m", "4", "-p", &port, &destination],
        operation_timeout,
        STANDARD_OUTPUT_LIMIT,
    )
    .await;
    match output {
        Ok(output) => {
            let mut combined = output.stdout.bytes;
            combined.extend_from_slice(&output.stderr.bytes);
            let discovered_pmtu = parse_tracepath_pmtu(&combined);
            let status = if discovered_pmtu.is_some() {
                if suspicious_mtu(address, discovered_pmtu, route_mtu) {
                    Status::Warn
                } else {
                    Status::Pass
                }
            } else {
                Status::Skip
            };
            MtuResult {
                status,
                address,
                route_mtu,
                discovered_pmtu,
                error_kind: discovered_pmtu.is_none().then(|| {
                    if output.status.success() {
                        "parse_error"
                    } else {
                        "probe_failed"
                    }
                    .to_owned()
                }),
                error: discovered_pmtu.is_none().then(|| {
                    let detail = String::from_utf8_lossy(&combined).trim().to_owned();
                    sanitize_report_text(if detail.is_empty() {
                        "tracepath did not report a path MTU".to_owned()
                    } else {
                        detail
                    })
                }),
            }
        }
        Err(BoundedCommandError::Io(error)) => MtuResult {
            status: Status::Skip,
            address,
            route_mtu,
            discovered_pmtu: None,
            error_kind: Some(
                if error.kind() == io::ErrorKind::NotFound {
                    "tool_missing"
                } else {
                    "tool_failed"
                }
                .to_owned(),
            ),
            error: Some(sanitize_report_text(
                if error.kind() == io::ErrorKind::NotFound {
                    "tracepath is not installed".to_owned()
                } else {
                    error.to_string()
                },
            )),
        },
        Err(BoundedCommandError::Timeout) => MtuResult {
            status: Status::Skip,
            address,
            route_mtu,
            discovered_pmtu: None,
            error_kind: Some("timeout".to_owned()),
            error: Some("tracepath timed out".to_owned()),
        },
    }
}

fn tracepath_destination(address: SocketAddr) -> String {
    match address {
        SocketAddr::V6(address) if address.scope_id() != 0 => {
            format!("{}%{}", address.ip(), address.scope_id())
        }
        _ => address.ip().to_string(),
    }
}

fn suspicious_mtu(
    address: SocketAddr,
    discovered_pmtu: Option<u32>,
    route_mtu: Option<u32>,
) -> bool {
    let minimum = if address.is_ipv6() { 1280 } else { 576 };
    discovered_pmtu.is_some_and(|mtu| mtu < minimum || route_mtu.is_some_and(|route| mtu < route))
}

fn parse_tracepath_pmtu(output: &[u8]) -> Option<u32> {
    let text = String::from_utf8_lossy(output);
    let tokens = text.split_whitespace().collect::<Vec<_>>();
    tokens
        .windows(2)
        .filter(|pair| pair[0] == "pmtu")
        .filter_map(|pair| pair[1].parse().ok())
        .next_back()
}

#[cfg(target_os = "linux")]
async fn inspect_resolver(operation_timeout: Duration) -> ResolverEvidence {
    let output = run_bounded(
        OsStr::new("resolvectl"),
        ["status", "--no-pager"],
        operation_timeout,
        STANDARD_OUTPUT_LIMIT,
    )
    .await;
    match output {
        Ok(output) if output.stdout.truncated || output.stderr.truncated => skipped_resolver(
            "output_truncated",
            "resolvectl output exceeded the safety limit",
        ),
        Ok(output) if !output.status.success() => {
            skipped_resolver("tool_failed", &command_error(&output, "resolvectl failed"))
        }
        Ok(output) => parse_resolvectl_status(&output.stdout.bytes)
            .unwrap_or_else(|error| skipped_resolver("parse_error", &error)),
        Err(BoundedCommandError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            skipped_resolver("tool_missing", "resolvectl is not installed")
        }
        Err(BoundedCommandError::Io(error)) => skipped_resolver("tool_failed", &error.to_string()),
        Err(BoundedCommandError::Timeout) => skipped_resolver("timeout", "resolvectl timed out"),
    }
}

#[cfg(not(target_os = "linux"))]
async fn inspect_resolver(_operation_timeout: Duration) -> ResolverEvidence {
    skipped_resolver(
        "unsupported_platform",
        "systemd-resolved evidence is available on Linux only",
    )
}

fn parse_resolvectl_status(output: &[u8]) -> Result<ResolverEvidence, String> {
    let text = std::str::from_utf8(output)
        .map_err(|error| format!("invalid resolvectl output: {error}"))?;
    let mut global_servers = Vec::new();
    let mut global_domains = Vec::new();
    let mut links = Vec::new();
    let mut current_link: Option<ResolverLink> = None;
    let mut continuation: Option<&str> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if let Some(header) = line.strip_prefix("Link ") {
            if let Some(link) = current_link.take() {
                links.push(link);
            }
            let (index, name) = header
                .split_once(' ')
                .ok_or_else(|| "malformed resolvectl link header".to_owned())?;
            let index = index
                .parse()
                .map_err(|_| "invalid resolvectl link index".to_owned())?;
            current_link = Some(ResolverLink {
                index,
                name: sanitize_report_text(name.trim_matches(['(', ')'])),
                servers: Vec::new(),
                domains: Vec::new(),
                default_route: None,
            });
            continuation = None;
            continue;
        }
        if line == "Global" || line.is_empty() {
            continuation = None;
            continue;
        }
        if let Some((field, value)) = line.split_once(':') {
            let field = field.trim();
            let value = value.trim();
            continuation = match field {
                "DNS Servers" => Some("servers"),
                "DNS Domain" | "DNS Domains" => Some("domains"),
                _ => None,
            };
            match (field, current_link.as_mut()) {
                ("Current DNS Server" | "DNS Servers", Some(resolver_link)) => {
                    push_unique_words(&mut resolver_link.servers, value);
                }
                ("DNS Domain" | "DNS Domains", Some(resolver_link)) => {
                    push_unique_words(&mut resolver_link.domains, value);
                }
                ("DefaultRoute setting" | "Default Route", Some(resolver_link)) => {
                    resolver_link.default_route = parse_yes_no(value);
                }
                ("Protocols", Some(resolver_link)) if resolver_link.default_route.is_none() => {
                    resolver_link.default_route =
                        value
                            .split_whitespace()
                            .find_map(|protocol| match protocol {
                                "+DefaultRoute" => Some(true),
                                "-DefaultRoute" => Some(false),
                                _ => None,
                            });
                }
                ("Current DNS Server" | "DNS Servers", None) => {
                    push_unique_words(&mut global_servers, value);
                }
                ("DNS Domain" | "DNS Domains", None) => {
                    push_unique_words(&mut global_domains, value);
                }
                _ => {}
            }
        } else if let Some(kind) = continuation {
            match (kind, current_link.as_mut()) {
                ("servers", Some(resolver_link)) => {
                    push_unique_words(&mut resolver_link.servers, line);
                }
                ("domains", Some(resolver_link)) => {
                    push_unique_words(&mut resolver_link.domains, line);
                }
                ("servers", None) => push_unique_words(&mut global_servers, line),
                ("domains", None) => push_unique_words(&mut global_domains, line),
                _ => {}
            }
        }
    }
    if let Some(link) = current_link {
        links.push(link);
    }
    Ok(ResolverEvidence {
        status: Status::Pass,
        manager: "systemd-resolved".to_owned(),
        global_servers,
        global_domains,
        links,
        error_kind: None,
        error: None,
    })
}

fn push_unique_words(destination: &mut Vec<String>, value: &str) {
    for item in value.split_whitespace().map(sanitize_report_text) {
        if !destination.contains(&item) {
            destination.push(item);
        }
    }
}

fn parse_yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

fn skipped_resolver(kind: &str, error: &str) -> ResolverEvidence {
    ResolverEvidence {
        error_kind: Some(kind.to_owned()),
        error: Some(sanitize_report_text(error)),
        ..ResolverEvidence::default()
    }
}

#[cfg(target_os = "linux")]
async fn inspect_network_manager(operation_timeout: Duration) -> NetworkManagerEvidence {
    let output = run_bounded(
        OsStr::new("nmcli"),
        [
            "-t",
            "--escape",
            "yes",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
        operation_timeout,
        STANDARD_OUTPUT_LIMIT,
    )
    .await;
    match output {
        Ok(output) if output.stdout.truncated || output.stderr.truncated => {
            skipped_network_manager("output_truncated", "nmcli output exceeded the safety limit")
        }
        Ok(output) if !output.status.success() => {
            skipped_network_manager("tool_failed", &command_error(&output, "nmcli failed"))
        }
        Ok(output) => parse_nmcli_active(&output.stdout.bytes)
            .unwrap_or_else(|error| skipped_network_manager("parse_error", &error)),
        Err(BoundedCommandError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            skipped_network_manager("tool_missing", "nmcli is not installed")
        }
        Err(BoundedCommandError::Io(error)) => {
            skipped_network_manager("tool_failed", &error.to_string())
        }
        Err(BoundedCommandError::Timeout) => skipped_network_manager("timeout", "nmcli timed out"),
    }
}

#[cfg(not(target_os = "linux"))]
async fn inspect_network_manager(_operation_timeout: Duration) -> NetworkManagerEvidence {
    skipped_network_manager(
        "unsupported_platform",
        "NetworkManager evidence is available on Linux only",
    )
}

fn parse_nmcli_active(output: &[u8]) -> Result<NetworkManagerEvidence, String> {
    let text =
        std::str::from_utf8(output).map_err(|error| format!("invalid nmcli output: {error}"))?;
    let mut active_connections = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields = split_nmcli_fields(line);
        if fields.len() != 3 {
            return Err("nmcli returned an unexpected active-connection row".to_owned());
        }
        let connection_type = fields[1].clone();
        let device = fields[2].clone();
        let lowered_type = connection_type.to_ascii_lowercase();
        let lowered_device = device.to_ascii_lowercase();
        let vpn = lowered_type.contains("vpn")
            || lowered_type.contains("wireguard")
            || ["tun", "tap", "wg", "tailscale", "zt", "vpn"]
                .iter()
                .any(|prefix| lowered_device.starts_with(prefix));
        active_connections.push(ActiveConnection {
            name: sanitize_report_text(&fields[0]),
            connection_type: sanitize_report_text(connection_type),
            device: sanitize_report_text(device),
            vpn,
        });
    }
    let vpn_active = active_connections.iter().any(|connection| connection.vpn);
    Ok(NetworkManagerEvidence {
        status: Status::Pass,
        active_connections,
        vpn_active,
        error_kind: None,
        error: None,
    })
}

fn split_nmcli_fields(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            fields.last_mut().expect("one field exists").push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == ':' {
            fields.push(String::new());
        } else {
            fields.last_mut().expect("one field exists").push(character);
        }
    }
    if escaped {
        fields.last_mut().expect("one field exists").push('\\');
    }
    fields
}

fn skipped_network_manager(kind: &str, error: &str) -> NetworkManagerEvidence {
    NetworkManagerEvidence {
        error_kind: Some(kind.to_owned()),
        error: Some(sanitize_report_text(error)),
        ..NetworkManagerEvidence::default()
    }
}

fn command_error(output: &BoundedOutput, fallback: &str) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr.bytes)
        .trim()
        .to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout.bytes)
        .trim()
        .to_owned();
    sanitize_report_text(if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        fallback.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        os::unix::process::ExitStatusExt,
        process::ExitStatus,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::{
        Applicability, collect, command_error, evaluate_match, extract_verdict, parse_nft_output,
        parse_nft_ruleset, parse_nmcli_active, parse_resolvectl_status, parse_tracepath_pmtu,
        parse_yes_no, read_bounded_file, rule_applicability, skipped_firewall,
        skipped_network_manager, skipped_resolver, split_nmcli_fields, string_value,
        suspicious_mtu, tracepath_destination,
    };
    use crate::{
        command::{BoundedOutput, CapturedStream},
        model::{RouteResult, Status},
    };

    fn route(address: SocketAddr) -> RouteResult {
        RouteResult {
            status: Status::Pass,
            address,
            interface: Some("eth0".to_owned()),
            gateway: None,
            source: None,
            mtu: Some(1500),
            advmss: None,
            error_kind: None,
            error: None,
        }
    }

    fn output(
        success: bool,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
        truncated: bool,
    ) -> BoundedOutput {
        BoundedOutput {
            status: ExitStatus::from_raw(if success { 0 } else { 1 << 8 }),
            stdout: CapturedStream {
                bytes: stdout.into(),
                truncated,
            },
            stderr: CapturedStream {
                bytes: stderr.into(),
                truncated: false,
            },
        }
    }

    #[test]
    fn parses_relevant_nftables_verdicts_without_claiming_unknown_matches() {
        let address: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let json = br#"{
          "nftables": [
            {"chain":{"family":"inet","table":"filter","name":"output","hook":"output","policy":"accept"}},
            {"rule":{"family":"inet","table":"filter","chain":"output","handle":7,"expr":[
              {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.10"}},
              {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
              {"drop":null}
            ]}},
            {"rule":{"family":"inet","table":"filter","chain":"input","handle":8,"expr":[{"drop":null}]}}
          ]
        }"#;

        let evidence = parse_nft_ruleset(&[address], &[route(address)], json).unwrap();

        assert_eq!(evidence.status, Status::Pass);
        assert_eq!(evidence.inspected_rules, 2);
        assert_eq!(evidence.matches.len(), 2);
        assert_eq!(evidence.matches[0].confidence, "possible");
        assert_eq!(evidence.matches[1].verdict, "drop");
        assert_eq!(evidence.matches[1].confidence, "exact");
        assert!(evidence.incomplete);
    }

    #[test]
    fn unsupported_nftables_predicates_are_only_possible() {
        let address: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let matcher = serde_json::json!({
            "match": {"op":"in", "left":{"meta":{"key":"mark"}}, "right":{"set":[1,2]}}
        });
        assert_eq!(
            rule_applicability("inet", &[matcher], &[address], &[]),
            Applicability::Possible
        );
        assert_eq!(
            rule_applicability(
                "inet",
                &[serde_json::json!({"limit":{"rate":1}})],
                &[address],
                &[]
            ),
            Applicability::Possible
        );
        assert_eq!(
            evaluate_match(&serde_json::json!({"op":"in"}), &[], &[]),
            None
        );
    }

    #[test]
    fn parses_resolvectl_global_and_link_details() {
        let output = b"Global\n       DNS Servers: 1.1.1.1\n        DNS Domain: example.test\nLink 2 (eth0)\n              Protocols: +DefaultRoute -LLMNR\n    Current DNS Server: 10.0.0.53\n           DNS Servers: 10.0.0.53\n            DNS Domain: corp.test ~.\n         Default Route: yes\nLink 3 (eth1)\n              Protocols: -DefaultRoute +LLMNR\n";

        let evidence = parse_resolvectl_status(output).unwrap();

        assert_eq!(evidence.global_servers, ["1.1.1.1"]);
        assert_eq!(evidence.links.len(), 2);
        assert_eq!(evidence.links[0].name, "eth0");
        assert_eq!(evidence.links[0].default_route, Some(true));
        assert_eq!(evidence.links[0].domains, ["corp.test", "~."]);
        assert_eq!(evidence.links[1].default_route, Some(false));
    }

    #[test]
    fn parses_nmcli_escaping_and_vpn_connections() {
        assert_eq!(
            split_nmcli_fields(r"work\:vpn:vpn:tun0"),
            ["work:vpn", "vpn", "tun0"]
        );
        let evidence =
            parse_nmcli_active(b"wired:802-3-ethernet:eth0\nwork\\:vpn:vpn:tun0\n").unwrap();
        assert_eq!(evidence.active_connections.len(), 2);
        assert!(evidence.vpn_active);
        assert_eq!(evidence.active_connections[1].name, "work:vpn");
    }

    #[test]
    fn extracts_the_last_tracepath_mtu() {
        assert_eq!(
            parse_tracepath_pmtu(b" 1?: [LOCALHOST] pmtu 1500\n 1: host pmtu 1420\n"),
            Some(1420)
        );
        assert_eq!(parse_tracepath_pmtu(b"no reply"), None);
    }

    #[test]
    fn classifies_nft_command_and_parse_failures() {
        let truncated = parse_nft_output(&[], &[], &output(true, b"{}", b"", true));
        assert_eq!(truncated.error_kind.as_deref(), Some("output_truncated"));

        let denied = parse_nft_output(
            &[],
            &[],
            &output(false, b"", b"Operation not permitted", false),
        );
        assert_eq!(denied.error_kind.as_deref(), Some("permission_denied"));

        let failed = parse_nft_output(&[], &[], &output(false, b"bad output", b"", false));
        assert_eq!(failed.error_kind.as_deref(), Some("tool_failed"));
        assert_eq!(failed.error.as_deref(), Some("bad output"));

        let fallback = parse_nft_output(&[], &[], &output(false, b"", b"", false));
        assert_eq!(
            fallback.error.as_deref(),
            Some("nft failed without an error message")
        );

        let invalid = parse_nft_output(&[], &[], &output(true, b"not json", b"", false));
        assert_eq!(invalid.error_kind.as_deref(), Some("parse_error"));
    }

    #[test]
    fn evaluates_supported_firewall_predicates_and_verdicts() {
        let address: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let routes = [route(address)];
        let destination = serde_json::json!({
            "op":"==", "left":{"payload":{"protocol":"ip","field":"daddr"}}, "right":"192.0.2.10"
        });
        let port = serde_json::json!({
            "op":"==", "left":{"payload":{"protocol":"tcp","field":"dport"}}, "right":443
        });
        let interface = serde_json::json!({
            "op":"==", "left":{"meta":{"key":"oifname"}}, "right":"eth0"
        });
        assert_eq!(
            evaluate_match(&destination, &[address], &routes),
            Some(true)
        );
        assert_eq!(evaluate_match(&port, &[address], &routes), Some(true));
        assert_eq!(evaluate_match(&interface, &[address], &routes), Some(true));
        assert_eq!(evaluate_match(&port, &[], &routes), Some(false));
        assert_eq!(
            rule_applicability(
                "inet",
                &[serde_json::json!({"match": port})],
                &[address],
                &routes
            ),
            Applicability::Exact
        );
        assert_eq!(
            rule_applicability(
                "ip6",
                &[serde_json::json!({"match": port})],
                &[address],
                &routes
            ),
            Applicability::No
        );
        let udp_port = serde_json::json!({
            "op":"==", "left":{"payload":{"protocol":"udp","field":"dport"}}, "right":443
        });
        assert_eq!(evaluate_match(&udp_port, &[address], &routes), Some(false));

        assert_eq!(
            extract_verdict(&serde_json::json!({"jump":"child"})).as_deref(),
            Some("jump:child")
        );
        assert_eq!(
            extract_verdict(&serde_json::json!({"accept":null})).as_deref(),
            Some("accept")
        );
        assert_eq!(extract_verdict(&serde_json::json!({})), None);
        assert_eq!(
            string_value(&serde_json::json!({"name":"bad\u{1b}name"}), "name"),
            "bad\\u{1b}name"
        );
        assert_eq!(string_value(&serde_json::json!({}), "name"), "unknown");
    }

    #[test]
    fn covers_path_parser_edge_cases_and_skip_helpers() {
        let ipv4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert!(suspicious_mtu(ipv4, Some(500), None));
        assert!(suspicious_mtu(ipv6, Some(1400), Some(1500)));
        assert!(!suspicious_mtu(ipv4, None, Some(1500)));
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 7));
        assert_eq!(tracepath_destination(scoped), "::1%7");
        assert_eq!(tracepath_destination(ipv4), "192.0.2.1");
        assert_eq!(parse_yes_no("yes"), Some(true));
        assert_eq!(parse_yes_no("no"), Some(false));
        assert_eq!(parse_yes_no("unknown"), None);

        assert!(parse_resolvectl_status(&[0xff]).is_err());
        assert!(parse_resolvectl_status(b"Link malformed\n").is_err());
        assert!(parse_resolvectl_status(b"Link x (eth0)\n").is_err());
        assert!(parse_nmcli_active(&[0xff]).is_err());
        assert!(parse_nmcli_active(b"only:two\n").is_err());
        assert_eq!(
            split_nmcli_fields("name:type:device\\"),
            ["name", "type", "device\\"]
        );

        assert_eq!(
            skipped_firewall("kind", "bad\u{1b}").error.as_deref(),
            Some("bad\\u{1b}")
        );
        assert_eq!(
            skipped_resolver("kind", "bad").error_kind.as_deref(),
            Some("kind")
        );
        assert_eq!(
            skipped_network_manager("kind", "bad").error_kind.as_deref(),
            Some("kind")
        );
        assert_eq!(
            command_error(&output(false, b"stdout", b"stderr", false), "x"),
            "stderr"
        );
    }

    #[test]
    fn bounded_file_reader_never_buffers_past_its_limit() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "netwhy-{}-{nonce}-bounded-gai.conf",
            std::process::id()
        ));
        fs::write(&path, vec![b'x'; 128]).unwrap();

        let (bytes, truncated) = read_bounded_file(&path, 16).unwrap();

        assert_eq!(bytes.len(), 16);
        assert!(truncated);
        fs::remove_file(path).unwrap();

        let fifo = std::env::temp_dir().join(format!(
            "netwhy-{}-{nonce}-bounded-gai.fifo",
            std::process::id()
        ));
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert_eq!(
            read_bounded_file(&fifo, 16).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        fs::remove_file(fifo).unwrap();
    }

    #[tokio::test]
    async fn bounded_path_collection_produces_evidence_for_each_address() {
        let address: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let evidence = Box::pin(collect(
            &[address],
            &[route(address)],
            Duration::from_millis(100),
        ))
        .await;

        assert_eq!(evidence.mtu.len(), 1);
        assert_eq!(evidence.address_preference.resolver_order.len(), 1);
        assert!(!evidence.firewall.mode.is_empty());
        assert!(!evidence.resolver.manager.is_empty());
    }
}
