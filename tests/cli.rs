use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
};

use netwhy::{ErrorCode, ErrorReport};
use serde_json::Value;
use socket2::{Domain, SockAddr, Socket, Type};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct ChildGuard(Child);

impl ChildGuard {
    fn id(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn netwhy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(args)
        .output()
        .unwrap()
}

fn netwhy_with_unwritable_stdout(args: &[&str]) -> Output {
    let unwritable = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(args)
        .stdout(Stdio::from(unwritable))
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn unique_temp_path(label: &str) -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("netwhy-{label}-{}-{id}", std::process::id()))
}

fn user_namespaces_available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_ready_file(path: &Path, child: &mut ChildGuard) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            return;
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("namespace fixture exited before becoming ready: {status}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "namespace fixture did not become ready"
        );
        thread::sleep(std::time::Duration::from_millis(10));
    }
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

fn assert_report_schema_rejects(value: &Value) {
    let schema: Value = serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.iter_errors(value).next().is_some());
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

fn netwhy_with_fake_runtime(runtime: &str, args: &[&str], script: &str) -> Output {
    netwhy_with_fake_runtime_env(runtime, args, script, &[])
}

fn netwhy_with_fake_runtime_env(
    runtime: &str,
    args: &[&str],
    script: &str,
    environment: &[(&str, &str)],
) -> Output {
    let directory = unique_temp_path("runtime-test");
    fs::create_dir(&directory).unwrap();
    let executable = directory.join(runtime);
    fs::write(&executable, script).unwrap();
    let mut permissions = fs::metadata(&executable).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_netwhy"));
    command
        .args(args)
        .env("PATH", &directory)
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_HOST")
        .env_remove("CONTAINER_CONNECTION")
        .env_remove("CONTAINER_HOST")
        .envs(environment.iter().copied());
    let output = command.output().unwrap();

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
    assert!(String::from_utf8_lossy(&help.stdout).contains("--pid"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("--docker"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("--podman"));
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        "netwhy 0.1.0"
    );

    for output in [
        netwhy(&["--json", "--help"]),
        netwhy(&["--json", "--version"]),
    ] {
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(
            !String::from_utf8_lossy(&output.stdout)
                .trim_start()
                .starts_with('{')
        );
    }
}

#[test]
fn invalid_target_exits_two() {
    let output = netwhy(&["ftp://example.test"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported scheme"));
}

#[test]
fn invalid_target_errors_escape_terminal_control_characters() {
    let target = "\u{1b}[31mBAD";

    let human = netwhy(&[target]);
    assert_eq!(human.status.code(), Some(2));
    assert!(human.stdout.is_empty());
    assert!(!human.stderr.contains(&0x1b));
    assert!(String::from_utf8_lossy(&human.stderr).contains(r"\u{1b}[31mBAD"));

    let json = netwhy(&["--json", target]);
    assert_eq!(json.status.code(), Some(2));
    assert!(json.stderr.is_empty());
    assert!(!json.stdout.contains(&0x1b));
    let error = parse_json(&json);
    assert_eq!(
        error["error"]["message"],
        r"invalid hostname or endpoint: \u{1b}[31mBAD"
    );
    assert_error_schema(&error);
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
fn all_cli_validation_failures_are_structured_in_json_mode() {
    let invocations = [
        vec!["--json"],
        vec!["--json", "--timeout-ms", "0", "example.test"],
        vec!["--json", "--pid", "0", "example.test"],
        vec!["--json", "--ipv4", "--ipv6", "example.test"],
        vec!["--json", "--pid", "42", "--docker", "web", "example.test"],
        vec!["--json", "--pid", "42", "--podman", "web", "example.test"],
        vec!["--json", "--docker", "", "example.test"],
        vec!["--json", "--podman", "", "example.test"],
        vec![
            "--json",
            "--docker",
            "web",
            "--podman",
            "api",
            "example.test",
        ],
    ];

    for args in invocations {
        let output = netwhy(&args);

        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(output.stderr.is_empty(), "args: {args:?}");
        let error = parse_json(&output);
        assert_eq!(error["error"]["code"], "INVALID_INVOCATION");
        assert_error_schema(&error);
    }
}

#[test]
fn missing_process_context_is_a_structured_json_error() {
    let output = netwhy(&["--json", "--pid", &u32::MAX.to_string(), "127.0.0.1:9"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert_eq!(error["error"]["retryable"], false);
    assert_error_schema(&error);
}

#[test]
fn missing_process_context_is_a_human_readable_error() {
    let output = netwhy(&["--pid", &u32::MAX.to_string(), "127.0.0.1:9"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("selected process context is unavailable"));
    assert!(stderr.contains("CAP_SYS_ADMIN"));
    assert!(stderr.contains("CAP_SYS_CHROOT"));
}

#[test]
fn selected_process_context_and_proxy_environment_are_reported() {
    let process = Command::new("/bin/sleep")
        .arg("30")
        .env(
            "HTTPS_PROXY",
            "http://alice:secret@selected-proxy.example:8080",
        )
        .spawn()
        .map(ChildGuard)
        .unwrap();
    let pid = process.id();
    let pid_string = pid.to_string();
    let (_reservation, address) = reserved_refused_address();

    let output = netwhy(&[
        "--json",
        "--pid",
        &pid_string,
        &address.to_string(),
        "--timeout-ms",
        "250",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    let context = &report["request"]["execution_context"];
    assert_eq!(context["source"], "process");
    assert_eq!(context["target_pid"], pid);
    assert_eq!(context["network_namespace"], "shared");
    assert_eq!(context["mount_namespace"], "shared");
    assert_eq!(context["filesystem_root"], "shared");
    assert_eq!(context["proxy_environment"], "selected_process");
    assert_eq!(context["required_capabilities"], serde_json::json!([]));
    assert_eq!(context["capability_status"], "not_required");
    let proxy = report["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|proxy| proxy["name"] == "HTTPS_PROXY")
        .unwrap();
    assert_eq!(
        proxy["value"],
        "http://<redacted>@selected-proxy.example:8080"
    );
    assert_report_schema(&report);

    let mut missing_pid = report.clone();
    missing_pid["request"]["execution_context"]
        .as_object_mut()
        .unwrap()
        .remove("target_pid");
    assert_report_schema_rejects(&missing_pid);

    let mut unexpected_container = report.clone();
    unexpected_container["request"]["execution_context"]["target_container"] =
        serde_json::json!("fixture");
    assert_report_schema_rejects(&unexpected_container);
}

#[test]
fn docker_and_podman_contexts_are_resolved_and_reported() {
    let (_reservation, address) = reserved_refused_address();
    let target = address.to_string();
    let script = r#"#!/bin/sh
if [ "$1" = context ]; then
    [ "$2" = inspect ] || exit 81
    [ "$3" = --format ] || exit 82
    [ "$4" = '{{.Endpoints.docker.Host}}' ] || exit 83
    printf 'unix:///var/run/docker.sock\n'
    exit 0
fi
if [ "$1" = info ]; then
    [ "$2" = --format ] || exit 84
    [ "$3" = '{{.Host.ServiceIsRemote}}' ] || exit 85
    printf 'false\n'
    exit 0
fi
[ "$1" = container ] || exit 91
[ "$2" = inspect ] || exit 92
[ "$3" = --format ] || exit 93
[ "$4" = '{{.State.Pid}}' ] || exit 94
[ "$5" = -- ] || exit 95
[ "$6" = fixture ] || exit 96
printf '%s\n' "$PPID"
"#;

    for (runtime, flag, source) in [
        ("docker", "--docker", "docker"),
        ("podman", "--podman", "podman"),
    ] {
        let output = netwhy_with_fake_runtime(
            runtime,
            &["--json", flag, "fixture", &target, "--timeout-ms", "250"],
            script,
        );

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let report = parse_json(&output);
        let context = &report["request"]["execution_context"];
        assert_eq!(context["source"], source);
        assert_eq!(context["target_container"], "fixture");
        assert!(context["target_pid"].as_u64().is_some_and(|pid| pid > 0));
        assert_eq!(context["network_namespace"], "shared");
        assert_eq!(context["mount_namespace"], "shared");
        assert_eq!(context["filesystem_root"], "shared");
        assert_eq!(context["capability_status"], "not_required");
        assert_report_schema(&report);

        let mut missing_container = report.clone();
        missing_container["request"]["execution_context"]
            .as_object_mut()
            .unwrap()
            .remove("target_container");
        assert_report_schema_rejects(&missing_container);
    }
}

#[test]
fn container_identifier_cannot_be_parsed_as_a_runtime_option() {
    let (_reservation, address) = reserved_refused_address();
    let target = address.to_string();
    let script = r#"#!/bin/sh
if [ "$1" = context ]; then
    printf 'unix:///var/run/docker.sock\n'
    exit 0
fi
[ "$1" = container ] || exit 91
[ "$2" = inspect ] || exit 92
[ "$5" = -- ] || exit 95
[ "$6" = -hostile ] || exit 96
printf '%s\n' "$PPID"
"#;
    let output = netwhy_with_fake_runtime(
        "docker",
        &[
            "--json",
            "--docker=-hostile",
            &target,
            "--timeout-ms",
            "250",
        ],
        script,
    );

    assert_eq!(output.status.code(), Some(1));
    let report = parse_json(&output);
    assert_eq!(
        report["request"]["execution_context"]["target_container"],
        "-hostile"
    );
    assert_report_schema(&report);
}

#[test]
fn unavailable_or_failing_container_runtimes_are_structured_errors() {
    let missing = Command::new(env!("CARGO_BIN_EXE_netwhy"))
        .args(["--json", "--docker", "fixture", "127.0.0.1:9"])
        .env("PATH", "/netwhy-test-path-without-container-runtimes")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let error = parse_json(&missing);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("could not start docker"))
    );
    assert_error_schema(&error);

    let failed = netwhy_with_fake_runtime(
        "podman",
        &["--json", "--podman", "fixture", "127.0.0.1:9"],
        "#!/bin/sh\nif [ \"$1\" = info ]; then printf 'false\\n'; exit 0; fi\nprintf 'no such container\\n' >&2\nexit 125\n",
    );
    assert_eq!(failed.status.code(), Some(2));
    let error = parse_json(&failed);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("no such container"))
    );
    assert_error_schema(&error);
}

#[test]
fn remote_container_runtimes_are_rejected_before_pid_resolution() {
    for (runtime, flag, script) in [
        (
            "docker",
            "--docker",
            "#!/bin/sh\nprintf 'ssh://runtime.example\\n'\n",
        ),
        ("podman", "--podman", "#!/bin/sh\nprintf 'true\\n'\n"),
    ] {
        let output =
            netwhy_with_fake_runtime(runtime, &["--json", flag, "fixture", "127.0.0.1:9"], script);

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let error = parse_json(&output);
        assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
        assert!(
            error["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("remote runtime"))
        );
        assert_error_schema(&error);
    }
}

#[test]
fn docker_host_locality_is_validated_without_running_a_context_command() {
    let (_reservation, address) = reserved_refused_address();
    let target = address.to_string();
    let script = r#"#!/bin/sh
[ "$1" = container ] || exit 91
[ "$2" = inspect ] || exit 92
printf '%s\n' "$PPID"
"#;
    let local = netwhy_with_fake_runtime_env(
        "docker",
        &[
            "--json",
            "--docker",
            "fixture",
            &target,
            "--timeout-ms",
            "250",
        ],
        script,
        &[("DOCKER_HOST", "unix:///run/docker.sock")],
    );
    assert_eq!(local.status.code(), Some(1));
    assert_report_schema(&parse_json(&local));

    let remote = netwhy_with_fake_runtime_env(
        "docker",
        &["--json", "--docker", "fixture", "127.0.0.1:9"],
        "#!/bin/sh\nexit 99\n",
        &[("DOCKER_HOST", "tcp://runtime.example:2376")],
    );
    assert_eq!(remote.status.code(), Some(2));
    let error = parse_json(&remote);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("remote runtime"))
    );
    assert_error_schema(&error);
}

#[test]
fn container_restart_during_context_preparation_is_rejected() {
    let state_file = unique_temp_path("runtime-state");
    let script = r#"#!/bin/sh
if [ "$1" = context ]; then
    printf 'unix:///var/run/docker.sock\n'
    exit 0
fi
if [ -e "$NETWHY_TEST_RUNTIME_STATE" ]; then
    printf '1\n'
else
    : > "$NETWHY_TEST_RUNTIME_STATE"
    printf '%s\n' "$PPID"
fi
"#;
    let state_file_text = state_file.to_string_lossy().into_owned();
    let output = netwhy_with_fake_runtime_env(
        "docker",
        &["--json", "--docker", "fixture", "127.0.0.1:9"],
        script,
        &[("NETWHY_TEST_RUNTIME_STATE", &state_file_text)],
    );
    fs::remove_file(state_file).unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("changed PID"))
    );
    assert_error_schema(&error);
}

#[test]
fn container_pid_that_is_absent_from_local_proc_is_rejected() {
    let output = netwhy_with_fake_runtime(
        "podman",
        &["--json", "--podman", "fixture", "127.0.0.1:9"],
        "#!/bin/sh\nif [ \"$1\" = info ]; then printf 'false\\n'; else printf '4294967295\\n'; fi\n",
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("4294967295"))
    );
    assert!(
        error["error"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("podman unshare"))
    );
    assert_error_schema(&error);
}

#[test]
fn container_runtime_inspection_honors_the_timeout() {
    let started = std::time::Instant::now();
    let output = netwhy_with_fake_runtime(
        "docker",
        &[
            "--json",
            "--docker",
            "fixture",
            "127.0.0.1:9",
            "--timeout-ms",
            "25",
        ],
        "#!/bin/sh\nwhile :; do :; done\n",
    );

    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(output.status.code(), Some(2));
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert!(
        error["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("timed out after 25 ms"))
    );
    assert_error_schema(&error);
}

#[test]
fn container_runtime_descendants_cannot_extend_the_operation_deadline() {
    let (_reservation, address) = reserved_refused_address();
    let target = address.to_string();
    let started = std::time::Instant::now();
    let output = netwhy_with_fake_runtime(
        "docker",
        &[
            "--json",
            "--docker",
            "fixture",
            &target,
            "--timeout-ms",
            "250",
        ],
        r#"#!/bin/sh
/bin/sleep 5 &
if [ "$1" = context ]; then
    printf 'unix:///var/run/docker.sock\n'
else
    printf '%s\n' "$PPID"
fi
"#,
    );

    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(output.status.code(), Some(1));
    assert_report_schema(&parse_json(&output));
}

#[test]
fn enters_real_mount_root_and_network_namespaces() {
    if !user_namespaces_available() {
        eprintln!("skipping: unprivileged user namespaces are unavailable");
        return;
    }

    let ready_file = unique_temp_path("namespace-ready");
    let script = r#"
unshare --net --mount /bin/sh -c 'printf ready > "$1"; exec /bin/sleep 30' sh "$NETWHY_READY_FILE" &
target_pid=$!
cleanup() {
    kill "$target_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
    rm -f "$NETWHY_READY_FILE"
}
trap cleanup EXIT
attempt=0
while [ ! -s "$NETWHY_READY_FILE" ]; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 200 ]; then
        echo "namespace fixture did not become ready" >&2
        exit 97
    fi
    sleep 0.01
done
"$NETWHY_BIN_PATH" --json --pid "$target_pid" --timeout-ms 250 127.0.0.1:9
exit $?
"#;
    let output = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--fork",
            "/bin/sh",
            "-c",
            script,
        ])
        .env("NETWHY_BIN_PATH", env!("CARGO_BIN_EXE_netwhy"))
        .env("NETWHY_READY_FILE", &ready_file)
        .output()
        .unwrap();
    let _ = fs::remove_file(&ready_file);

    assert_ne!(output.status.code(), Some(97), "fixture failed to start");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_json(&output);
    let context = &report["request"]["execution_context"];
    assert_eq!(context["source"], "process");
    assert_eq!(context["network_namespace"], "entered");
    assert_eq!(context["mount_namespace"], "entered");
    assert_eq!(context["filesystem_root"], "entered");
    assert_eq!(
        context["required_capabilities"],
        serde_json::json!(["CAP_SYS_ADMIN", "CAP_SYS_CHROOT"])
    );
    assert_eq!(context["capability_status"], "available");
    assert_report_schema(&report);
}

#[test]
fn rejects_a_namespace_owned_by_an_unavailable_user_context() {
    if !user_namespaces_available() {
        eprintln!("skipping: unprivileged user namespaces are unavailable");
        return;
    }

    let ready_file = unique_temp_path("denied-namespace-ready");
    let mut process = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--net",
            "--mount",
            "/bin/sh",
            "-c",
            "printf ready > \"$1\"; exec /bin/sleep 30",
            "sh",
        ])
        .arg(&ready_file)
        .spawn()
        .map(ChildGuard)
        .unwrap();
    wait_for_ready_file(&ready_file, &mut process);
    let pid = process.id().to_string();

    let output = netwhy(&["--json", "--pid", &pid, "127.0.0.1:9"]);
    let _ = fs::remove_file(&ready_file);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let error = parse_json(&output);
    assert_eq!(error["error"]["code"], "CONTEXT_UNAVAILABLE");
    assert_eq!(error["error"]["retryable"], false);
    assert!(
        error["error"]["hint"]
            .as_str()
            .is_some_and(|hint| hint.contains("CAP_SYS_ADMIN"))
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
fn reachable_tcp_cli_emits_successful_human_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();

    let output = netwhy(&[&target, "--timeout-ms", "250"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Result: PASS"));
    assert!(stdout.contains("[PASS] TCP"));
}

#[test]
fn unresolvable_name_is_a_structured_cli_diagnosis() {
    let output = netwhy(&[
        "--json",
        "does-not-exist.invalid:443",
        "--timeout-ms",
        "250",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    assert_eq!(report["dns"]["status"], "fail");
    assert_eq!(report["diagnosis"]["code"], "DNS_RESOLUTION_FAILED");
    assert_report_schema(&report);
}

#[test]
fn address_family_flags_control_the_compiled_cli() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();

    let ipv4 = netwhy(&["--json", "--ipv4", &target, "--timeout-ms", "250"]);
    assert_eq!(ipv4.status.code(), Some(0));
    let report = parse_json(&ipv4);
    assert_eq!(report["request"]["address_family"], "ipv4");
    assert_eq!(report["dns"]["status"], "pass");
    assert_report_schema(&report);

    let ipv6 = netwhy(&["--json", "--ipv6", &target, "--timeout-ms", "250"]);
    assert_eq!(ipv6.status.code(), Some(1));
    let report = parse_json(&ipv6);
    assert_eq!(report["request"]["address_family"], "ipv6");
    assert_eq!(report["dns"]["status"], "fail");
    assert_eq!(report["dns"]["error_kind"], "address_family_mismatch");
    assert_report_schema(&report);
}

#[test]
fn plain_server_is_a_structured_https_cli_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        drop(accept_with_timeout(&listener));
        let mut stream = accept_with_timeout(&listener);
        stream.write_all(b"this is not TLS").unwrap();
    });

    let output = netwhy(&[
        "--json",
        &format!("https://{address}/"),
        "--timeout-ms",
        "500",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    assert_eq!(report["overall"], "fail");
    assert_eq!(report["diagnosis"]["code"], "TLS_HANDSHAKE_FAILED");
    assert_eq!(report["application_attempts"][0]["tls"]["status"], "fail");
    assert_report_schema(&report);
    server.join().unwrap();
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
fn http_exchange_timeout_is_a_structured_cli_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        drop(accept_with_timeout(&listener));
        let mut stream = accept_with_timeout(&listener);
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        thread::sleep(std::time::Duration::from_millis(100));
    });

    let output = netwhy(&[
        "--json",
        &format!("http://{address}/"),
        "--timeout-ms",
        "25",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report = parse_json(&output);
    assert_eq!(report["diagnosis"]["code"], "HTTP_EXCHANGE_FAILED");
    assert_eq!(report["application_attempts"][0]["http"]["status"], "fail");
    assert!(
        report["application_attempts"][0]["http"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("timed out"))
    );
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
fn oversized_iproute2_output_is_bounded_without_hiding_tcp_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let chunk = "x".repeat(1024);
    let script = format!(
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 65 ]; do printf '%s' '{chunk}'; i=$((i + 1)); done\n"
    );
    let output = netwhy_with_fake_ip(&["--json", &target, "--timeout-ms", "500"], &script);

    assert_eq!(output.status.code(), Some(0));
    let report = parse_json(&output);
    assert_eq!(report["overall"], "pass");
    assert_eq!(report["routes"][0]["status"], "skip");
    assert_eq!(report["routes"][0]["error_kind"], "parse_error");
    assert_eq!(
        report["routes"][0]["error"],
        "ip route output exceeded the 64 KiB safety limit"
    );
}

#[test]
fn iproute2_descendants_cannot_extend_the_operation_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let started = std::time::Instant::now();
    let output = netwhy_with_fake_ip(
        &["--json", &target, "--timeout-ms", "250"],
        "#!/bin/sh\n/bin/sleep 5 &\nprintf '[{\"dev\":\"lo\",\"prefsrc\":\"127.0.0.1\"}]\\n'\n",
    );

    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(output.status.code(), Some(0));
    let report = parse_json(&output);
    assert_eq!(report["routes"][0]["status"], "pass");
    assert_eq!(report["routes"][0]["interface"], "lo");
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
fn unwritable_stdout_is_reported_for_human_and_json_output() {
    let (_reservation, address) = reserved_refused_address();
    let target = address.to_string();

    let human = netwhy_with_unwritable_stdout(&[&target, "--timeout-ms", "250"]);
    assert_eq!(human.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&human.stderr).contains("could not write output"));

    let json = netwhy_with_unwritable_stdout(&["--json", &target, "--timeout-ms", "250"]);
    assert_eq!(json.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&json.stderr).unwrap();
    assert_eq!(error["error"]["code"], "OUTPUT_ERROR");
    assert_eq!(error["error"]["retryable"], true);
    assert_error_schema(&error);
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
