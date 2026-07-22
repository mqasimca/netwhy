use std::{
    ffi::{OsStr, OsString},
    future::Future,
    io,
    net::SocketAddr,
    os::unix::ffi::OsStringExt,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use nix::{
    net::if_::if_indextoname,
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
#[cfg(any(target_os = "linux", test))]
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    task::JoinSet,
    time::timeout,
};

use crate::{
    model::{RouteResult, Status},
    sanitize_report_text,
};

const MAX_CONCURRENT_COMMANDS: usize = 8;
const MAX_ROUTE_OUTPUT_BYTES: usize = 64 * 1024;

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
    let scope_interface = match route_scope_interface(address) {
        Ok(interface) => interface,
        Err(error) => return skipped(address, "tool_failed", error),
    };
    let mut command = route_command(address, &destination, scope_interface.as_deref());
    command
        .kill_on_drop(true)
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
                route_tool_missing_message().to_owned(),
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
            format!(
                "{} error output exceeded the 64 KiB safety limit",
                route_command_name()
            ),
        );
    }
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr.bytes)
            .trim()
            .to_owned();
        let error = if error.is_empty() {
            format!("{} exited with {}", route_command_name(), output.status)
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
            format!(
                "{} output exceeded the 64 KiB safety limit",
                route_command_name()
            ),
        );
    }

    match parse_platform_route(address, &output.stdout.bytes) {
        Ok(route) => route,
        Err(error) if error == "the kernel returned no route" => failed(address, "no_route", error),
        Err(error) => skipped(address, "parse_error", error),
    }
}

#[cfg(target_os = "linux")]
fn route_command(
    address: SocketAddr,
    destination: &str,
    scope_interface: Option<&OsStr>,
) -> Command {
    let mut command = Command::new("ip");
    command.args(linux_route_arguments(address, destination, scope_interface));
    command
}

#[cfg(target_os = "macos")]
fn route_command(
    address: SocketAddr,
    destination: &str,
    scope_interface: Option<&OsStr>,
) -> Command {
    let mut command = Command::new("/sbin/route");
    command.args(macos_route_arguments(address, destination, scope_interface));
    command
}

#[cfg(target_os = "linux")]
const fn route_tool_missing_message() -> &'static str {
    "iproute2 is not installed; route inspection skipped"
}

#[cfg(target_os = "macos")]
const fn route_tool_missing_message() -> &'static str {
    "the macOS route utility is not available; route inspection skipped"
}

#[cfg(target_os = "linux")]
const fn route_command_name() -> &'static str {
    "ip route"
}

#[cfg(target_os = "macos")]
const fn route_command_name() -> &'static str {
    "macOS route"
}

#[cfg(target_os = "linux")]
fn parse_platform_route(address: SocketAddr, output: &[u8]) -> Result<RouteResult, String> {
    parse_iproute2_route(address, output)
}

#[cfg(target_os = "macos")]
fn parse_platform_route(address: SocketAddr, output: &[u8]) -> Result<RouteResult, String> {
    parse_macos_route(address, output)
}

#[cfg(any(target_os = "macos", test))]
fn macos_route_arguments(
    address: SocketAddr,
    destination: &str,
    scope_interface: Option<&OsStr>,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("-n"),
        OsString::from("get"),
        OsString::from(if address.is_ipv6() { "-inet6" } else { "-inet" }),
    ];
    if let Some(interface) = scope_interface {
        arguments.push(OsString::from("-ifscope"));
        arguments.push(interface.to_owned());
    }
    arguments.push(OsString::from(destination));
    arguments
}

#[cfg(any(target_os = "linux", test))]
fn linux_route_arguments(
    address: SocketAddr,
    destination: &str,
    scope_interface: Option<&OsStr>,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("-j"),
        OsString::from(if address.is_ipv6() { "-6" } else { "-4" }),
        OsString::from("route"),
        OsString::from("get"),
        OsString::from(destination),
    ];
    if let Some(interface) = scope_interface {
        arguments.push(OsString::from("oif"));
        arguments.push(interface.to_owned());
    }
    arguments
}

async fn run_command(
    command: &mut Command,
    operation_timeout: Duration,
) -> Result<CommandOutput, CommandError> {
    let mut child = command.spawn().map_err(CommandError::Io)?;
    let Some(process_id) = child.id() else {
        let _ = child.start_kill();
        reap_child(child);
        return Err(CommandError::Io(io::Error::other(format!(
            "{} PID was unavailable",
            route_command_name()
        ))));
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(child, process_id);
        return Err(CommandError::Io(io::Error::other(format!(
            "{} stdout was not captured",
            route_command_name()
        ))));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(child, process_id);
        return Err(CommandError::Io(io::Error::other(format!(
            "{} stderr was not captured",
            route_command_name()
        ))));
    };

    let capture = timeout(operation_timeout, async {
        let (status, stdout, stderr) = tokio::try_join!(
            wait_for_exit(&mut child, process_id),
            read_bounded(stdout),
            read_bounded(stderr),
        )?;
        Ok::<_, io::Error>((status, stdout, stderr))
    })
    .await;

    let (status, stdout, stderr) = match capture {
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

    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

async fn wait_for_exit(child: &mut Child, process_id: u32) -> io::Result<ExitStatus> {
    let status = child.wait().await?;
    signal_process_group(process_id);
    Ok(status)
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
    address.ip().to_string()
}

fn route_scope_interface(address: SocketAddr) -> Result<Option<OsString>, String> {
    let SocketAddr::V6(address) = address else {
        return Ok(None);
    };
    if address.scope_id() == 0 {
        return Ok(None);
    }

    let name = if_indextoname(address.scope_id()).map_err(|error| {
        format!(
            "IPv6 scope interface index {} is unavailable: {error}",
            address.scope_id()
        )
    })?;
    if name.as_bytes().is_empty() {
        return Err(format!(
            "IPv6 scope interface index {} is unavailable",
            address.scope_id()
        ));
    }
    Ok(Some(OsString::from_vec(name.into_bytes())))
}

fn is_no_route_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("network is unreachable")
        || error.contains("no route to host")
        || error.contains("no route")
        || error.contains("not in table")
}

#[cfg(any(target_os = "linux", test))]
fn parse_iproute2_route(address: SocketAddr, json: &[u8]) -> Result<RouteResult, String> {
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
        mtu: numeric_field(route, "mtu").or_else(|| {
            route
                .get("metrics")
                .and_then(|metrics| numeric_field(metrics, "mtu"))
        }),
        advmss: numeric_field(route, "advmss").or_else(|| {
            route
                .get("metrics")
                .and_then(|metrics| numeric_field(metrics, "advmss"))
        }),
        error_kind: None,
        error: None,
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_route(address: SocketAddr, output: &[u8]) -> Result<RouteResult, String> {
    let output = std::str::from_utf8(output)
        .map_err(|error| format!("invalid macOS route output: {error}"))?;
    let mut interface = None;
    let mut gateway = None;
    let mut mtu = None;

    for line in output.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match name.trim() {
            "interface" if interface.is_none() => {
                interface = Some(sanitize_report_text(value));
            }
            "gateway" if gateway.is_none() => {
                gateway = Some(sanitize_report_text(value));
            }
            "mtu" if mtu.is_none() => {
                mtu = value.parse().ok();
            }
            _ => {}
        }
    }

    if interface.is_none() {
        return Err("macOS route output did not include an interface".to_owned());
    }

    Ok(RouteResult {
        status: Status::Pass,
        address,
        interface,
        gateway,
        source: None,
        mtu,
        advmss: None,
        error_kind: None,
        error: None,
    })
}

#[cfg(any(target_os = "linux", test))]
fn string_field(value: &Value, name: &str) -> Option<String> {
    value.get(name)?.as_str().map(sanitize_report_text)
}

#[cfg(any(target_os = "linux", test))]
fn numeric_field(value: &Value, name: &str) -> Option<u32> {
    u32::try_from(value.get(name)?.as_u64()?).ok()
}

fn failed(address: SocketAddr, error_kind: &str, error: String) -> RouteResult {
    RouteResult {
        status: Status::Fail,
        address,
        interface: None,
        gateway: None,
        source: None,
        mtu: None,
        advmss: None,
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
        mtu: None,
        advmss: None,
        error_kind: Some(error_kind.to_owned()),
        error: Some(sanitize_report_text(error)),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{OsStr, OsString},
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        time::Duration,
    };

    use super::{
        MAX_ROUTE_OUTPUT_BYTES, failed, inspect_all_with, is_no_route_error, linux_route_arguments,
        macos_route_arguments, parse_iproute2_route, parse_macos_route, read_bounded,
        route_destination, route_scope_interface,
    };
    use crate::model::{RouteResult, Status};

    #[test]
    fn parses_iproute2_json() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let json = br#"[{"dst":"203.0.113.10","gateway":"192.168.1.1","dev":"enp5s0","prefsrc":"192.168.1.20","mtu":1420,"advmss":1380}]"#;

        let route = parse_iproute2_route(address, json).unwrap();

        assert_eq!(route.status, Status::Pass);
        assert_eq!(route.interface.as_deref(), Some("enp5s0"));
        assert_eq!(route.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(route.source.as_deref(), Some("192.168.1.20"));
        assert_eq!(route.mtu, Some(1420));
        assert_eq!(route.advmss, Some(1380));
    }

    #[test]
    fn parses_source_fallback_and_optional_fields() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let route = parse_iproute2_route(address, br#"[{"src":"192.168.1.21"}]"#).unwrap();

        assert_eq!(route.status, Status::Pass);
        assert_eq!(route.source.as_deref(), Some("192.168.1.21"));
        assert!(route.interface.is_none());
        assert!(route.gateway.is_none());
    }

    #[test]
    fn parses_nested_iproute2_metrics() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let route = parse_iproute2_route(
            address,
            br#"[{"dev":"eth0","metrics":{"mtu":1280,"advmss":1240}}]"#,
        )
        .unwrap();

        assert_eq!(route.mtu, Some(1280));
        assert_eq!(route.advmss, Some(1240));
    }

    #[test]
    fn rejects_invalid_or_empty_route_json() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();

        assert!(
            parse_iproute2_route(address, b"not-json")
                .unwrap_err()
                .contains("invalid")
        );
        assert_eq!(
            parse_iproute2_route(address, b"[]").unwrap_err(),
            "the kernel returned no route"
        );
    }

    #[test]
    fn builds_macos_route_arguments_for_each_address_family() {
        let ipv4: SocketAddr = "203.0.113.10:443".parse().unwrap();
        assert_eq!(
            macos_route_arguments(ipv4, "203.0.113.10", None),
            ["-n", "get", "-inet", "203.0.113.10"].map(OsString::from)
        );

        let ipv6 = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            7,
        ));
        assert_eq!(
            macos_route_arguments(ipv6, "fe80::1", Some(OsStr::new("en7"))),
            ["-n", "get", "-inet6", "-ifscope", "en7", "fe80::1"].map(OsString::from)
        );
    }

    #[test]
    fn builds_linux_route_arguments_for_each_address_family() {
        let ipv4: SocketAddr = "203.0.113.10:443".parse().unwrap();
        assert_eq!(
            linux_route_arguments(ipv4, "203.0.113.10", None),
            ["-j", "-4", "route", "get", "203.0.113.10"].map(OsString::from)
        );

        let ipv6 = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            7,
        ));
        assert_eq!(
            linux_route_arguments(ipv6, "fe80::1", Some(OsStr::new("eth7"))),
            ["-j", "-6", "route", "get", "fe80::1", "oif", "eth7"].map(OsString::from)
        );
    }

    #[test]
    fn parses_and_sanitizes_macos_route_output() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let output = b"route to: 203.0.113.10\ndestination: 203.0.113.10\ngateway: 192.168.1.1\ninterface: en0\x1b[2J\nflags: <UP,GATEWAY,HOST,DONE,STATIC>\n";

        let route = parse_macos_route(address, output).unwrap();

        assert_eq!(route.status, Status::Pass);
        assert_eq!(route.interface.as_deref(), Some("en0\\u{1b}[2J"));
        assert_eq!(route.gateway.as_deref(), Some("192.168.1.1"));
        assert!(route.source.is_none());
    }

    #[test]
    fn rejects_malformed_macos_route_output() {
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        assert!(
            parse_macos_route(address, b"route to: 203.0.113.10\n")
                .unwrap_err()
                .contains("did not include an interface")
        );
        assert!(
            parse_macos_route(address, b"interface: \xff")
                .unwrap_err()
                .contains("invalid macOS route output")
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
        assert!(is_no_route_error(
            "route: writing to routing socket: not in table"
        ));
        assert!(!is_no_route_error("permission denied"));
    }

    #[test]
    fn resolves_ipv6_scope_for_route_lookup() {
        let interface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let interface_index = nix::net::if_::if_nametoindex(interface).unwrap();
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            interface_index,
        ));
        assert_eq!(route_destination(scoped), "fe80::1");
        assert_eq!(
            route_scope_interface(scoped).unwrap().as_deref(),
            Some(OsStr::new(interface))
        );

        let unscoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            0,
        ));
        assert_eq!(route_destination(unscoped), "fe80::1");
        assert_eq!(route_scope_interface(unscoped).unwrap(), None);
    }

    #[test]
    fn rejects_an_unavailable_ipv6_scope_for_route_lookup() {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            443,
            0,
            u32::MAX,
        ));

        assert!(
            route_scope_interface(scoped)
                .unwrap_err()
                .contains("4294967295")
        );
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
                mtu: None,
                advmss: None,
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
                mtu: None,
                advmss: None,
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
