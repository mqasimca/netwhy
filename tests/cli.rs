use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use netwhy::{ErrorCode, ErrorReport};
use serde_json::Value;
use socket2::{Domain, SockAddr, Socket, Type};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn netwhy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(args)
        .output()
        .unwrap()
}

fn parse_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn reserved_refused_address() -> (Socket, std::net::SocketAddr) {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    socket
        .bind(&SockAddr::from(
            "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .unwrap();
    let address = socket.local_addr().unwrap().as_socket().unwrap();
    (socket, address)
}

fn accept_with_timeout(listener: &TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "server timed out waiting for NetWhy"
                );
                thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => panic!("server accept failed: {error}"),
        }
    }
}

fn assert_error_schema(value: &Value) {
    let schema: Value = serde_json::from_str(include_str!("../docs/error.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
}

fn assert_report_schema(value: &Value) {
    let schema: Value = serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
}

fn assert_error_schema_rejects(value: &Value) {
    let schema: Value = serde_json::from_str(include_str!("../docs/error.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.iter_errors(value).next().is_some());
}

fn netwhy_with_fake_ip(args: &[&str], script: &str) -> Output {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let directory =
        std::env::temp_dir().join(format!("netwhy-ip-test-{}-{id}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let executable = directory.join("ip");
    fs::write(&executable, script).unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(args)
        .env("PATH", &directory)
        .output()
        .unwrap();

    fs::remove_file(executable).unwrap();
    fs::remove_dir(directory).unwrap();
    output
}

#[test]
fn help_and_version_are_plain_text_metadata_commands() {
    let help = netwhy(&["--help"]);
    let version = netwhy(&["--version"]);

    assert!(help.status.success());
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--json"));
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        "netwhy 0.1.0"
    );
}

#[test]
fn invalid_target_exits_two() {
    let output = netwhy(&["ftp://example.test"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported scheme"));
}

#[test]
fn invalid_target_is_a_structured_json_error() {
    let output = netwhy(&["--json", "ftp://example.test"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let error = parse_json(&output);
    assert_eq!(error["kind"], "error");
    assert_eq!(error["error"]["code"], "INVALID_TARGET");
    assert_eq!(error["exit_code"], 2);
    assert_error_schema(&error);
}

#[test]
fn target_credentials_are_rejected_without_echoing_the_secret() {
    let output = netwhy(&["--json", "https://alice:topsecret@example.test/"]);

    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("alice:topsecret"));
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "INVALID_TARGET");
    assert_eq!(error["error"]["retryable"], false);
    assert_error_schema(&error);
}

#[test]
fn invalid_invocation_is_a_structured_json_error() {
    let output = netwhy(&["--json", "--not-a-netwhy-option"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "INVALID_INVOCATION");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unexpected")
    );
    assert_error_schema(&error);
}

#[test]
fn output_error_retryability_is_enforced_by_the_schema() {
    let report = ErrorReport::new(ErrorCode::OutputError, "write failed", "retry");
    let mut value = serde_json::to_value(report).unwrap();
    assert_eq!(value["error"]["retryable"], true);
    assert_error_schema(&value);

    value["error"]["retryable"] = Value::Bool(false);
    assert_error_schema_rejects(&value);
}

#[test]
fn refused_connection_exits_one() {
    let (_reservation, address) = reserved_refused_address();

    let output = netwhy(&[&address.to_string(), "--timeout-ms", "250"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Result: FAIL"));
    assert!(stdout.contains("Next steps:"));
    assert!(stdout.contains("Evidence:"));
    assert!(stdout.contains("[FAIL] TCP"));
    assert!(stdout.find("Result: FAIL") < stdout.find("Evidence:"));
}

#[test]
fn successful_http_cli_emits_a_schema_valid_report() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let first = accept_with_timeout(&listener);
        drop(first);
        let mut stream = accept_with_timeout(&listener);
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap();
    });

    let output = netwhy(&[
        "--json",
        &format!("http://{address}/health"),
        "--timeout-ms",
        "500",
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    assert_eq!(report["kind"], "diagnostic_report");
    assert_eq!(report["overall"], "pass");
    assert_eq!(report["diagnosis"]["code"], "CONNECTIVITY_OK");
    assert_eq!(
        report["application_attempts"][0]["http"]["status_code"],
        200
    );
    assert_eq!(report["exit_code"], 0);
    assert_report_schema(&report);
    server.join().unwrap();
}

#[test]
fn missing_iproute2_is_skipped_without_failing_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(["--json", &address.to_string(), "--timeout-ms", "250"])
        .env("PATH", "/netwhy-test-path-without-iproute2")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    assert_eq!(report["kind"], "diagnostic_report");
    assert_eq!(report["tool"]["name"], "netwhy");
    assert_eq!(report["overall"], "pass");
    assert_eq!(report["diagnosis"]["code"], "CONNECTIVITY_OK");
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["routes"][0]["status"], "skip");
}

#[test]
fn failed_iproute2_command_is_evidence_but_not_a_false_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let target = address.to_string();
    let output = netwhy_with_fake_ip(
        &["--json", &target, "--timeout-ms", "250"],
        "#!/bin/sh\nprintf 'simulated route failure\\n' >&2\nexit 2\n",
    );

    assert_eq!(output.status.code(), Some(0));
    let report = parse_json(&output);
    assert_eq!(report["overall"], "pass");
    assert_eq!(report["routes"][0]["status"], "skip");
    assert_eq!(report["routes"][0]["error_kind"], "tool_failed");
    assert_eq!(report["routes"][0]["error"], "simulated route failure");
}

#[test]
fn malformed_iproute2_json_is_reported_without_hiding_tcp_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let target = address.to_string();
    let output = netwhy_with_fake_ip(
        &["--json", &target, "--timeout-ms", "250"],
        "#!/bin/sh\nprintf 'not-json\\n'\n",
    );

    assert_eq!(output.status.code(), Some(0));
    let report = parse_json(&output);
    assert_eq!(report["overall"], "pass");
    assert_eq!(report["routes"][0]["status"], "skip");
    assert_eq!(report["routes"][0]["error_kind"], "parse_error");
    assert!(
        report["routes"][0]["error"]
            .as_str()
            .unwrap()
            .contains("invalid iproute2 JSON")
    );
}

#[test]
fn closed_output_pipe_does_not_turn_a_diagnosis_into_an_internal_error() {
    let (_reservation, address) = reserved_refused_address();
    let mut child = Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args([
            address.to_string(),
            "--timeout-ms".to_owned(),
            "250".to_owned(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdout.take());

    let status = child.wait().unwrap();

    assert_eq!(status.code(), Some(1));
}

#[test]
fn http_warning_exits_zero() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let first = accept_with_timeout(&listener);
        drop(first);
        let mut stream = accept_with_timeout(&listener);
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            .unwrap();
    });

    let output = netwhy(&[
        "--json",
        &format!("http://{address}/health?token=topsecret#private"),
        "--timeout-ms",
        "500",
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    assert_eq!(report["overall"], "warn");
    assert_eq!(report["diagnosis"]["code"], "HTTP_ERROR_STATUS");
    assert_eq!(report["exit_code"], 0);
    assert_eq!(
        report["target"]["original"],
        format!("http://{address}/health?REDACTED#REDACTED")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("topsecret"));
    server.join().unwrap();
}

#[test]
fn proxy_credentials_are_redacted_before_json_serialization() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(["--json", &address.to_string(), "--timeout-ms", "250"])
        .env(
            "HTTPS_PROXY",
            "http://alice:secret@proxy.example/path@tag?next=@later",
        )
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("alice:secret"));
    let report = parse_json(&output);
    let proxy = report["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|proxy| proxy["name"] == "HTTPS_PROXY")
        .unwrap();
    assert_eq!(
        proxy["value"],
        "http://<redacted>@proxy.example/path@tag?next=@later"
    );
}

#[test]
fn route_helper_timeout_is_bounded_and_structured() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let started = std::time::Instant::now();
    let output = netwhy_with_fake_ip(
        &["--json", &target, "--timeout-ms", "25"],
        "#!/bin/sh\nwhile :; do :; done\n",
    );

    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(output.status.code(), Some(0));
    let report = parse_json(&output);
    assert_eq!(report["routes"][0]["status"], "skip");
    assert_eq!(report["routes"][0]["error_kind"], "timeout");
}

#[test]
fn option_terminator_prevents_false_json_mode() {
    let output = netwhy(&["example.test", "--", "--json"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .trim()
            .starts_with('{')
    );
}
