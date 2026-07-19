use std::{
    future::Future,
    io,
    net::SocketAddr,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use nix::{
    sys::{
        signal::{Signal, killpg},
        wait::{Id, WaitPidFlag, WaitStatus, waitid},
    },
    unistd::Pid,
};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::{
    model::{RouteResult, Status},
    sanitize_report_text,
};

const MAX_CONCURRENT_COMMANDS: usize = 8;
const MAX_ROUTE_OUTPUT_BYTES: usize = 64 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug)]
struct CapturedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
struct CommandOutput {
    status: ExitStatus,
    stdout: CapturedStream,
    stderr: CapturedStream,
}

#[derive(Debug)]
enum CommandError {
    Io(io::Error),
    Timeout,
}

pub async fn inspect_all(
    addresses: &[SocketAddr],
    operation_timeout: Duration,
) -> Vec<RouteResult> {
    inspect_all_with(addresses, operation_timeout, inspect).await
}

async fn inspect_all_with<I, F>(
    addresses: &[SocketAddr],
    operation_timeout: Duration,
    inspect_one: I,
) -> Vec<RouteResult>
where
    I: Fn(SocketAddr, Duration) -> F + Copy + Send + 'static,
    F: Future<Output = RouteResult> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut pending = addresses.iter().copied().enumerate();
    for (index, address) in pending.by_ref().take(MAX_CONCURRENT_COMMANDS) {
        tasks.spawn(async move { (index, inspect_one(address, operation_timeout).await) });
    }

    let mut routes = std::iter::repeat_with(|| None)
        .take(addresses.len())
        .collect::<Vec<_>>();
    while let Some(result) = tasks.join_next().await {
        if let Ok((index, route)) = result {
            routes[index] = Some(route);
        }
        if let Some((index, address)) = pending.next() {
            tasks.spawn(async move { (index, inspect_one(address, operation_timeout).await) });
        }
    }
    routes
        .into_iter()
        .zip(addresses.iter().copied())
        .map(|(route, address)| {
            route.unwrap_or_else(|| {
                skipped(
                    address,
                    "tool_failed",
                    "route inspection task stopped before producing evidence".to_owned(),
                )
            })
        })
        .collect()
}

async fn inspect(address: SocketAddr, operation_timeout: Duration) -> RouteResult {
    let destination = route_destination(address);
    let mut command = Command::new("ip");
    command
        .kill_on_drop(true)
        .args(["-j", "route", "get", &destination])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let output = run_command(&mut command, operation_timeout).await;

    let output = match output {
        Ok(output) => output,
        Err(CommandError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return skipped(
                address,
                "tool_missing",
                "iproute2 is not installed; route inspection skipped".to_owned(),
            );
        }
        Err(CommandError::Io(error)) => {
            return skipped(address, "tool_failed", error.to_string());
        }
        Err(CommandError::Timeout) => {
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

    if output.stderr.truncated {
        return skipped(
            address,
            "tool_failed",
            "ip route error output exceeded the 64 KiB safety limit".to_owned(),
        );
    }
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr.bytes)
            .trim()
            .to_owned();
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

    if output.stdout.truncated {
        return skipped(
            address,
            "parse_error",
            "ip route output exceeded the 64 KiB safety limit".to_owned(),
        );
    }

    match parse_route(address, &output.stdout.bytes) {
        Ok(route) => route,
        Err(error) if error == "the kernel returned no route" => failed(address, "no_route", error),
        Err(error) => skipped(address, "parse_error", error),
    }
}

async fn run_command(
    command: &mut Command,
    operation_timeout: Duration,
) -> Result<CommandOutput, CommandError> {
    let mut child = command.spawn().map_err(CommandError::Io)?;
    let Some(process_id) = child.id() else {
        let _ = child.start_kill();
        reap_child(child);
        return Err(CommandError::Io(io::Error::other(
            "ip route PID was unavailable",
        )));
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(child, process_id);
        return Err(CommandError::Io(io::Error::other(
            "ip route stdout was not captured",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(child, process_id);
        return Err(CommandError::Io(io::Error::other(
            "ip route stderr was not captured",
        )));
    };

    let capture = timeout(operation_timeout, async {
        let ((), stdout, stderr) = tokio::try_join!(
            wait_for_exit(process_id),
            read_bounded(stdout),
            read_bounded(stderr),
        )?;
        Ok::<_, io::Error>((stdout, stderr))
    })
    .await;

    let (stdout, stderr) = match capture {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            terminate_process_group(child, process_id);
            return Err(CommandError::Io(error));
        }
        Err(_) => {
            terminate_process_group(child, process_id);
            return Err(CommandError::Timeout);
        }
    };

    signal_process_group(process_id);
    let status = child.wait().await.map_err(CommandError::Io)?;
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

async fn wait_for_exit(process_id: u32) -> io::Result<()> {
    let pid = i32::try_from(process_id)
        .map(Pid::from_raw)
        .map_err(|_| io::Error::other("ip route PID exceeded i32"))?;
    loop {
        let status = waitid(
            Id::Pid(pid),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        )
        .map_err(io::Error::other)?;
        if !matches!(status, WaitStatus::StillAlive) {
            signal_process_group(process_id);
            return Ok(());
        }
        sleep(PROCESS_POLL_INTERVAL).await;
    }
}

fn signal_process_group(process_id: u32) {
    if let Ok(process_id) = i32::try_from(process_id) {
        let _ = killpg(Pid::from_raw(process_id), Signal::SIGKILL);
    }
}

fn terminate_process_group(mut child: Child, process_id: u32) {
    signal_process_group(process_id);
    let _ = child.start_kill();
    reap_child(child);
}

fn reap_child(mut child: Child) {
    std::mem::drop(tokio::spawn(async move {
        let _ = child.wait().await;
    }));
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin) -> io::Result<CapturedStream> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 4 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let remaining = MAX_ROUTE_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(CapturedStream { bytes, truncated })
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
    use std::{
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        time::Duration,
    };

    use super::{
        MAX_ROUTE_OUTPUT_BYTES, failed, inspect_all_with, is_no_route_error, parse_route,
        read_bounded, route_destination,
    };
    use crate::model::{RouteResult, Status};

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

        let unscoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            0,
        ));
        assert_eq!(route_destination(unscoped), "fe80::1");
    }

    #[tokio::test]
    async fn bounds_concurrent_route_commands_without_reordering_results() {
        async fn synthetic_route(address: SocketAddr, _timeout: Duration) -> RouteResult {
            RouteResult {
                status: Status::Pass,
                address,
                interface: Some(format!("test{}", address.port())),
                gateway: None,
                source: None,
                error_kind: None,
                error: None,
            }
        }

        let addresses = (1..=super::MAX_CONCURRENT_COMMANDS + 1)
            .map(|port| format!("192.0.2.1:{port}").parse().unwrap())
            .collect::<Vec<_>>();

        let routes = inspect_all_with(&addresses, Duration::from_secs(1), synthetic_route).await;

        assert_eq!(routes.len(), addresses.len());
        assert_eq!(
            routes.iter().map(|route| route.address).collect::<Vec<_>>(),
            addresses
        );
    }

    #[tokio::test]
    async fn converts_a_panicked_route_task_into_explicit_evidence() {
        async fn synthetic_route(address: SocketAddr, _timeout: Duration) -> RouteResult {
            assert_ne!(address.port(), 2, "simulated route task panic");
            RouteResult {
                status: Status::Pass,
                address,
                interface: None,
                gateway: None,
                source: None,
                error_kind: None,
                error: None,
            }
        }

        let addresses = [
            "192.0.2.1:1".parse().unwrap(),
            "192.0.2.1:2".parse().unwrap(),
        ];

        let routes = inspect_all_with(&addresses, Duration::from_secs(1), synthetic_route).await;

        assert_eq!(routes.len(), addresses.len());
        assert_eq!(routes[0].status, Status::Pass);
        assert_eq!(routes[1].status, Status::Skip);
        assert_eq!(routes[1].error_kind.as_deref(), Some("tool_failed"));
    }

    #[tokio::test]
    async fn bounds_route_output_while_draining_the_stream() {
        let input = vec![b'x'; MAX_ROUTE_OUTPUT_BYTES + 1];

        let captured = read_bounded(input.as_slice()).await.unwrap();

        assert_eq!(captured.bytes.len(), MAX_ROUTE_OUTPUT_BYTES);
        assert!(captured.truncated);
    }
}
