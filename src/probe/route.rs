use std::{net::SocketAddr, time::Duration};

use serde_json::Value;
use tokio::{process::Command, task::JoinSet, time::timeout};

use crate::{
    model::{RouteResult, Status},
    sanitize_report_text,
};

const MAX_CONCURRENT_COMMANDS: usize = 8;

pub async fn inspect_all(
    addresses: &[SocketAddr],
    operation_timeout: Duration,
) -> Vec<RouteResult> {
    let mut tasks = JoinSet::new();
    let mut pending = addresses.iter().copied().enumerate();
    for (index, address) in pending.by_ref().take(MAX_CONCURRENT_COMMANDS) {
        tasks.spawn(async move { (index, inspect(address, operation_timeout).await) });
    }

    let mut routes = Vec::with_capacity(addresses.len());
    while let Some(result) = tasks.join_next().await {
        if let Ok(route) = result {
            routes.push(route);
        }
        if let Some((index, address)) = pending.next() {
            tasks.spawn(async move { (index, inspect(address, operation_timeout).await) });
        }
    }
    routes.sort_by_key(|(index, _)| *index);
    routes.into_iter().map(|(_, route)| route).collect()
}

async fn inspect(address: SocketAddr, operation_timeout: Duration) -> RouteResult {
    let destination = route_destination(address);
    let mut command = Command::new("ip");
    command
        .kill_on_drop(true)
        .args(["-j", "route", "get", &destination]);
    let output = timeout(operation_timeout, command.output()).await;

    let output = match output {
        Ok(Ok(output)) => output,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return skipped(
                address,
                "tool_missing",
                "iproute2 is not installed; route inspection skipped".to_owned(),
            );
        }
        Ok(Err(error)) => {
            return skipped(address, "tool_failed", error.to_string());
        }
        Err(_) => {
            return skipped(
                address,
                "timeout",
                format!(
                    "route inspection timed out after {} ms",
                    operation_timeout.as_millis()
                ),
            );
        }
    };

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let error = if error.is_empty() {
            format!("ip route exited with {}", output.status)
        } else {
            error
        };
        return if is_no_route_error(&error) {
            failed(address, "no_route", error)
        } else {
            skipped(address, "tool_failed", error)
        };
    }

    match parse_route(address, &output.stdout) {
        Ok(route) => route,
        Err(error) if error == "the kernel returned no route" => failed(address, "no_route", error),
        Err(error) => skipped(address, "parse_error", error),
    }
}

fn route_destination(address: SocketAddr) -> String {
    match address {
        SocketAddr::V6(address) if address.scope_id() != 0 => {
            format!("{}%{}", address.ip(), address.scope_id())
        }
        _ => address.ip().to_string(),
    }
}

fn is_no_route_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("network is unreachable")
        || error.contains("no route to host")
        || error.contains("no route")
}

fn parse_route(address: SocketAddr, json: &[u8]) -> Result<RouteResult, String> {
    let routes: Vec<Value> =
        serde_json::from_slice(json).map_err(|error| format!("invalid iproute2 JSON: {error}"))?;
    let route = routes
        .first()
        .ok_or_else(|| "the kernel returned no route".to_owned())?;

    Ok(RouteResult {
        status: Status::Pass,
        address,
        interface: string_field(route, "dev"),
        gateway: string_field(route, "gateway"),
        source: string_field(route, "prefsrc").or_else(|| string_field(route, "src")),
        error_kind: None,
        error: None,
    })
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value.get(name)?.as_str().map(sanitize_report_text)
}

fn failed(address: SocketAddr, error_kind: &str, error: String) -> RouteResult {
    RouteResult {
        status: Status::Fail,
        address,
        interface: None,
        gateway: None,
        source: None,
        error_kind: Some(error_kind.to_owned()),
        error: Some(sanitize_report_text(error)),
    }
}

fn skipped(address: SocketAddr, error_kind: &str, error: String) -> RouteResult {
    RouteResult {
        status: Status::Skip,
        address,
        interface: None,
        gateway: None,
        source: None,
        error_kind: Some(error_kind.to_owned()),
        error: Some(sanitize_report_text(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

    use super::{failed, is_no_route_error, parse_route, route_destination};
    use crate::model::Status;

    #[test]
    fn parses_iproute2_json() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let json = br#"[{"dst":"203.0.113.10","gateway":"192.168.1.1","dev":"enp5s0","prefsrc":"192.168.1.20"}]"#;

        let route = parse_route(address, json).unwrap();

        assert_eq!(route.status, Status::Pass);
        assert_eq!(route.interface.as_deref(), Some("enp5s0"));
        assert_eq!(route.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(route.source.as_deref(), Some("192.168.1.20"));
    }

    #[test]
    fn parses_source_fallback_and_optional_fields() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let route = parse_route(address, br#"[{"src":"192.168.1.21"}]"#).unwrap();

        assert_eq!(route.status, Status::Pass);
        assert_eq!(route.source.as_deref(), Some("192.168.1.21"));
        assert!(route.interface.is_none());
        assert!(route.gateway.is_none());
    }

    #[test]
    fn rejects_invalid_or_empty_route_json() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();

        assert!(
            parse_route(address, b"not-json")
                .unwrap_err()
                .contains("invalid")
        );
        assert_eq!(
            parse_route(address, b"[]").unwrap_err(),
            "the kernel returned no route"
        );
    }

    #[test]
    fn constructs_failed_route_evidence() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();

        let route = failed(
            address,
            "no_route",
            "network unreachable\u{1b}[2J".to_owned(),
        );

        assert_eq!(route.status, Status::Fail);
        assert_eq!(
            route.error.as_deref(),
            Some("network unreachable\\u{1b}[2J")
        );
        assert_eq!(route.error_kind.as_deref(), Some("no_route"));
        assert!(route.interface.is_none());
    }

    #[test]
    fn classifies_only_kernel_route_errors_as_no_route() {
        assert!(is_no_route_error(
            "RTNETLINK answers: Network is unreachable"
        ));
        assert!(!is_no_route_error("permission denied"));
    }

    #[test]
    fn preserves_ipv6_scope_for_route_lookup() {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            7,
        ));
        assert_eq!(route_destination(scoped), "fe80::1%7");
    }
}
