use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::net::lookup_host;
use tokio::time::timeout;

use crate::{
    model::{DnsResult, Status},
    sanitize_report_text,
    target::Target,
};

const MAX_ADDRESSES: usize = 32;

pub async fn resolve(
    target: &Target,
    ipv4_only: bool,
    ipv6_only: bool,
    operation_timeout: Duration,
) -> DnsResult {
    let started = Instant::now();

    if let Ok(ip) = target.host.parse::<IpAddr>() {
        if (ipv4_only && ip.is_ipv6()) || (ipv6_only && ip.is_ipv4()) {
            return DnsResult {
                status: Status::Fail,
                duration_ms: started.elapsed().as_millis(),
                addresses: Vec::new(),
                truncated: false,
                error_kind: Some("address_family_mismatch".to_owned()),
                error: Some(format!(
                    "target is {}, but the requested address family is {}",
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" },
                    if ipv4_only { "IPv4" } else { "IPv6" }
                )),
            };
        }

        return DnsResult {
            status: Status::Pass,
            duration_ms: started.elapsed().as_millis(),
            addresses: vec![(ip, target.port).into()],
            truncated: false,
            error_kind: None,
            error: None,
        };
    }

    resolve_lookup(
        started,
        lookup_host((target.host.as_str(), target.port)),
        ipv4_only,
        ipv6_only,
        operation_timeout,
    )
    .await
}

async fn resolve_lookup<F, I, E>(
    started: Instant,
    lookup: F,
    ipv4_only: bool,
    ipv6_only: bool,
    operation_timeout: Duration,
) -> DnsResult
where
    F: Future<Output = Result<I, E>>,
    I: IntoIterator<Item = SocketAddr>,
    E: std::fmt::Display,
{
    match timeout(operation_timeout, lookup).await {
        Ok(Ok(resolved)) => resolved_result(started, resolved, ipv4_only, ipv6_only),
        Ok(Err(error)) => DnsResult {
            status: Status::Fail,
            duration_ms: started.elapsed().as_millis(),
            addresses: Vec::new(),
            truncated: false,
            error_kind: Some("resolver_error".to_owned()),
            error: Some(sanitize_report_text(error.to_string())),
        },
        Err(_) => DnsResult {
            status: Status::Fail,
            duration_ms: started.elapsed().as_millis(),
            addresses: Vec::new(),
            truncated: false,
            error_kind: Some("timeout".to_owned()),
            error: Some(format!(
                "DNS resolution timed out after {} ms",
                operation_timeout.as_millis()
            )),
        },
    }
}

fn resolved_result(
    started: Instant,
    resolved: impl IntoIterator<Item = SocketAddr>,
    ipv4_only: bool,
    ipv6_only: bool,
) -> DnsResult {
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    let mut truncated = false;
    for address in resolved {
        if (ipv4_only && !address.is_ipv4())
            || (ipv6_only && !address.is_ipv6())
            || !seen.insert(address)
        {
            continue;
        }
        if addresses.len() == MAX_ADDRESSES {
            truncated = true;
            break;
        }
        addresses.push(address);
    }

    if addresses.is_empty() {
        let family = if ipv4_only {
            "IPv4"
        } else if ipv6_only {
            "IPv6"
        } else {
            "usable"
        };
        DnsResult {
            status: Status::Fail,
            duration_ms: started.elapsed().as_millis(),
            addresses,
            truncated,
            error_kind: Some("no_addresses".to_owned()),
            error: Some(format!("DNS returned no {family} addresses")),
        }
    } else {
        DnsResult {
            status: Status::Pass,
            duration_ms: started.elapsed().as_millis(),
            addresses,
            truncated,
            error_kind: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::pending, future::ready, io, time::Instant};

    use super::{resolve, resolve_lookup, resolved_result};
    use crate::{model::Status, target::Target};

    #[test]
    fn filters_and_deduplicates_resolved_addresses() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();

        let both = resolved_result(Instant::now(), [ipv4, ipv4, ipv6], false, false);
        let v4 = resolved_result(Instant::now(), [ipv4, ipv6], true, false);
        let v6 = resolved_result(Instant::now(), [ipv4, ipv6], false, true);

        assert_eq!(both.status, Status::Pass);
        assert_eq!(both.addresses, vec![ipv4, ipv6]);
        assert_eq!(v4.addresses, vec![ipv4]);
        assert_eq!(v6.addresses, vec![ipv6]);
        assert!(!both.truncated);
    }

    #[test]
    fn caps_large_resolver_results() {
        let addresses = (1..=40)
            .map(|last| format!("192.0.2.{last}:443").parse().unwrap())
            .collect::<Vec<_>>();

        let result = resolved_result(Instant::now(), addresses, false, false);

        assert_eq!(result.addresses.len(), 32);
        assert!(result.truncated);
    }

    #[test]
    fn explains_empty_family_filtered_results() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();

        let no_v4 = resolved_result(Instant::now(), [ipv6], true, false);
        let no_v6 = resolved_result(Instant::now(), [ipv4], false, true);
        let empty = resolved_result(Instant::now(), [], false, false);

        assert_eq!(no_v4.status, Status::Fail);
        assert_eq!(
            no_v4.error.as_deref(),
            Some("DNS returned no IPv4 addresses")
        );
        assert_eq!(
            no_v6.error.as_deref(),
            Some("DNS returned no IPv6 addresses")
        );
        assert_eq!(
            empty.error.as_deref(),
            Some("DNS returned no usable addresses")
        );
    }

    #[tokio::test]
    async fn reports_resolver_timeout() {
        let result = resolve_lookup(
            Instant::now(),
            pending::<Result<Vec<std::net::SocketAddr>, io::Error>>(),
            false,
            false,
            std::time::Duration::from_millis(1),
        )
        .await;

        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.error_kind.as_deref(), Some("timeout"));
        assert!(result.error.unwrap().contains("timed out"));
    }

    #[tokio::test]
    async fn reports_and_sanitizes_resolver_errors() {
        let result = resolve_lookup(
            Instant::now(),
            ready(Err::<Vec<std::net::SocketAddr>, _>(io::Error::other(
                "resolver\nfailed",
            ))),
            false,
            false,
            std::time::Duration::from_secs(1),
        )
        .await;

        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.error_kind.as_deref(), Some("resolver_error"));
        assert_eq!(result.error.as_deref(), Some("resolver\\nfailed"));
    }

    #[tokio::test]
    async fn resolves_ip_literals_without_using_the_system_resolver() {
        let ipv4 = Target::parse("192.0.2.1:443").unwrap();
        let ipv6 = Target::parse("[2001:db8::1]:443").unwrap();

        let v4 = resolve(&ipv4, false, false, std::time::Duration::from_secs(1)).await;
        let v6 = resolve(&ipv6, false, false, std::time::Duration::from_secs(1)).await;

        assert_eq!(v4.status, Status::Pass);
        assert_eq!(v4.addresses, vec!["192.0.2.1:443".parse().unwrap()]);
        assert_eq!(v6.status, Status::Pass);
        assert_eq!(v6.addresses, vec!["[2001:db8::1]:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn rejects_ip_literals_from_the_unrequested_address_family() {
        let ipv4 = Target::parse("192.0.2.1:443").unwrap();
        let ipv6 = Target::parse("[2001:db8::1]:443").unwrap();

        let v4 = resolve(&ipv4, false, true, std::time::Duration::from_secs(1)).await;
        let v6 = resolve(&ipv6, true, false, std::time::Duration::from_secs(1)).await;

        assert_eq!(v4.status, Status::Fail);
        assert_eq!(v4.error_kind.as_deref(), Some("address_family_mismatch"));
        assert_eq!(v6.status, Status::Fail);
        assert_eq!(v6.error_kind.as_deref(), Some("address_family_mismatch"));
    }

    #[tokio::test]
    async fn resolves_localhost_through_the_system_resolver() {
        let target = Target::parse("localhost:443").unwrap();

        let result = resolve(&target, false, false, std::time::Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Pass);
        assert!(!result.addresses.is_empty());
        assert!(result.addresses.iter().all(|address| address.port() == 443));
    }
}
