use std::{
    io::{self, Read},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use netwhy::{ExecutionContextSource, sanitize_report_text};
use nix::{
    sys::{
        signal::{Signal, killpg},
        wait::{Id, WaitPidFlag, WaitStatus, waitid},
    },
    unistd::Pid,
};

const MAX_RUNTIME_OUTPUT_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const PID_TEMPLATE: &str = "{{.State.Pid}}";
const DOCKER_ENDPOINT_TEMPLATE: &str = "{{.Endpoints.docker.Host}}";
const PODMAN_REMOTE_TEMPLATE: &str = "{{.Host.ServiceIsRemote}}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl ContainerRuntime {
    const fn command(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    pub const fn execution_source(self) -> ExecutionContextSource {
        match self {
            Self::Docker => ExecutionContextSource::Docker,
            Self::Podman => ExecutionContextSource::Podman,
        }
    }
}

#[derive(Debug)]
struct CapturedStream {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
struct InspectionOutput {
    success: bool,
    stdout: CapturedStream,
    stderr: CapturedStream,
}

pub fn resolve_container_pid(
    runtime: ContainerRuntime,
    container: &str,
    operation_timeout: Duration,
) -> Result<u32> {
    ensure_local_runtime(runtime, operation_timeout)?;
    let output = inspect_container(runtime, container, operation_timeout)?;
    parse_container_pid(runtime, container, &output)
}

pub fn ensure_container_pid_unchanged(
    runtime: ContainerRuntime,
    container: &str,
    expected: u32,
    observed: u32,
) -> Result<()> {
    if observed != expected {
        bail!(
            "{} container {} changed PID while its context was being prepared (from {expected} to {observed}); retry the command",
            runtime.command(),
            sanitize_report_text(container)
        );
    }
    Ok(())
}

fn ensure_local_runtime(runtime: ContainerRuntime, operation_timeout: Duration) -> Result<()> {
    if runtime == ContainerRuntime::Docker && std::env::var_os("DOCKER_CONTEXT").is_none() {
        if let Some(endpoint) = std::env::var_os("DOCKER_HOST") {
            let endpoint = endpoint
                .to_str()
                .context("DOCKER_HOST is not valid UTF-8")?;
            return validate_runtime_locality(runtime, endpoint);
        }
    }

    let output = match runtime {
        ContainerRuntime::Docker => run_runtime(
            runtime,
            &["context", "inspect", "--format", DOCKER_ENDPOINT_TEMPLATE],
            operation_timeout,
            "runtime locality check",
        )?,
        ContainerRuntime::Podman => run_runtime(
            runtime,
            &["info", "--format", PODMAN_REMOTE_TEMPLATE],
            operation_timeout,
            "runtime locality check",
        )?,
    };
    let value = runtime_output_value(runtime, "runtime locality check", &output)?;
    validate_runtime_locality(runtime, value)
}

fn validate_runtime_locality(runtime: ContainerRuntime, value: &str) -> Result<()> {
    let local = match runtime {
        ContainerRuntime::Docker => value.trim().starts_with("unix://"),
        ContainerRuntime::Podman => value.trim() == "false",
    };
    if !local {
        bail!(
            "{} is connected to a remote runtime; container PIDs must belong to this Linux host",
            runtime.command()
        );
    }
    Ok(())
}

fn inspect_container(
    runtime: ContainerRuntime,
    container: &str,
    operation_timeout: Duration,
) -> Result<InspectionOutput> {
    run_runtime(
        runtime,
        &[
            "container",
            "inspect",
            "--format",
            PID_TEMPLATE,
            "--",
            container,
        ],
        operation_timeout,
        "container inspection",
    )
}

fn run_runtime(
    runtime: ContainerRuntime,
    arguments: &[&str],
    operation_timeout: Duration,
    operation: &str,
) -> Result<InspectionOutput> {
    let started = Instant::now();
    let mut command = Command::new(runtime.command());
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("could not start {} for the {operation}", runtime.command()))?;

    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(child);
        bail!("container runtime stdout was not captured");
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(child);
        bail!("container runtime stderr was not captured");
    };
    let stdout_reader = spawn_reader(stdout);
    let stderr_reader = spawn_reader(stderr);

    let status = loop {
        match child_has_exited(&child) {
            Ok(true) => {
                signal_process_group(child.id());
                break child
                    .wait()
                    .context("could not reap the container runtime")?;
            }
            Ok(false) => {}
            Err(error) => {
                terminate_process_group(child);
                return Err(error);
            }
        }

        let elapsed = started.elapsed();
        if elapsed >= operation_timeout {
            terminate_process_group(child);
            bail!(
                "{} {operation} timed out after {} ms",
                runtime.command(),
                operation_timeout.as_millis()
            );
        }
        thread::sleep(POLL_INTERVAL.min(operation_timeout.saturating_sub(elapsed)));
    };

    Ok(InspectionOutput {
        success: status.success(),
        stdout: receive_reader(
            &stdout_reader,
            started,
            operation_timeout,
            runtime,
            operation,
            "stdout",
        )?,
        stderr: receive_reader(
            &stderr_reader,
            started,
            operation_timeout,
            runtime,
            operation,
            "stderr",
        )?,
    })
}

fn child_has_exited(child: &Child) -> Result<bool> {
    let process_id = i32::try_from(child.id()).context("container runtime PID exceeded i32")?;
    let status = waitid(
        Id::Pid(Pid::from_raw(process_id)),
        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
    )
    .context("could not wait for the container runtime")?;
    Ok(!matches!(status, WaitStatus::StillAlive))
}

fn signal_process_group(process_id: u32) {
    if let Ok(process_id) = i32::try_from(process_id) {
        let _ = killpg(Pid::from_raw(process_id), Signal::SIGKILL);
    }
}

fn terminate_process_group(mut child: Child) {
    signal_process_group(child.id());
    let _ = child.kill();
    let _ = thread::Builder::new()
        .name("netwhy-runtime-reaper".to_owned())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn runtime_output_value<'a>(
    runtime: ContainerRuntime,
    operation: &str,
    output: &'a InspectionOutput,
) -> Result<&'a str> {
    let runtime_name = runtime.command();
    if output.stderr.truncated {
        bail!("{runtime_name} error output exceeded the 64 KiB safety limit");
    }
    if !output.success {
        let error = String::from_utf8_lossy(&output.stderr.bytes);
        let error = sanitize_report_text(error.trim());
        let detail = if error.is_empty() {
            "failed without an error message".to_owned()
        } else {
            error
        };
        bail!("{runtime_name} {operation} failed: {detail}");
    }
    if output.stdout.truncated {
        bail!("{runtime_name} output exceeded the 64 KiB safety limit");
    }
    std::str::from_utf8(&output.stdout.bytes)
        .with_context(|| format!("{runtime_name} returned non-UTF-8 output for {operation}"))
        .map(str::trim)
}

fn spawn_reader(reader: impl Read + Send + 'static) -> Receiver<io::Result<CapturedStream>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_bounded(reader));
    });
    receiver
}

fn receive_reader(
    reader: &Receiver<io::Result<CapturedStream>>,
    started: Instant,
    operation_timeout: Duration,
    runtime: ContainerRuntime,
    operation: &str,
    stream_name: &str,
) -> Result<CapturedStream> {
    let remaining = operation_timeout.saturating_sub(started.elapsed());
    match reader.recv_timeout(remaining) {
        Ok(result) => {
            result.with_context(|| format!("could not read container runtime {stream_name}"))
        }
        Err(RecvTimeoutError::Timeout) => bail!(
            "{} {operation} timed out after {} ms while reading {stream_name}",
            runtime.command(),
            operation_timeout.as_millis()
        ),
        Err(RecvTimeoutError::Disconnected) => {
            bail!("container runtime {stream_name} reader stopped unexpectedly")
        }
    }
}

fn read_bounded(mut reader: impl Read) -> io::Result<CapturedStream> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = MAX_RUNTIME_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(CapturedStream { bytes, truncated })
}

fn parse_container_pid(
    runtime: ContainerRuntime,
    container: &str,
    output: &InspectionOutput,
) -> Result<u32> {
    let runtime_name = runtime.command();
    let container = sanitize_report_text(container);
    if output.stderr.truncated {
        bail!("{runtime_name} error output exceeded the 64 KiB safety limit");
    }
    if !output.success {
        let error = String::from_utf8_lossy(&output.stderr.bytes);
        let error = sanitize_report_text(error.trim());
        let detail = if error.is_empty() {
            "container inspection failed without an error message".to_owned()
        } else {
            error
        };
        bail!("{runtime_name} could not inspect container {container}: {detail}");
    }
    if output.stdout.truncated {
        bail!("{runtime_name} PID output exceeded the 64 KiB safety limit");
    }

    let value = std::str::from_utf8(&output.stdout.bytes)
        .with_context(|| format!("{runtime_name} returned a non-UTF-8 container PID"))?
        .trim();
    let pid = value.parse::<u32>().with_context(|| {
        format!("{runtime_name} returned an invalid PID for container {container}")
    })?;
    if pid == 0 {
        bail!("{runtime_name} container {container} is not running");
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::{
        CapturedStream, ContainerRuntime, InspectionOutput, MAX_RUNTIME_OUTPUT_BYTES,
        ensure_container_pid_unchanged, parse_container_pid, read_bounded, runtime_output_value,
        validate_runtime_locality,
    };
    use netwhy::ExecutionContextSource;

    fn output(success: bool, stdout: &[u8], stderr: &[u8]) -> InspectionOutput {
        InspectionOutput {
            success,
            stdout: CapturedStream {
                bytes: stdout.to_vec(),
                truncated: false,
            },
            stderr: CapturedStream {
                bytes: stderr.to_vec(),
                truncated: false,
            },
        }
    }

    #[test]
    fn maps_runtimes_to_commands_and_report_sources() {
        assert_eq!(ContainerRuntime::Docker.command(), "docker");
        assert_eq!(ContainerRuntime::Podman.command(), "podman");
        assert_eq!(
            ContainerRuntime::Docker.execution_source(),
            ExecutionContextSource::Docker
        );
        assert_eq!(
            ContainerRuntime::Podman.execution_source(),
            ExecutionContextSource::Podman
        );
    }

    #[test]
    fn accepts_only_local_runtime_connections() {
        assert!(
            validate_runtime_locality(ContainerRuntime::Docker, "unix:///run/docker.sock\n")
                .is_ok()
        );
        assert!(validate_runtime_locality(ContainerRuntime::Podman, " false\n").is_ok());

        for (runtime, value) in [
            (ContainerRuntime::Docker, "tcp://runtime.example:2376"),
            (ContainerRuntime::Docker, "ssh://runtime.example"),
            (ContainerRuntime::Podman, "true"),
            (ContainerRuntime::Podman, "unexpected"),
        ] {
            let error = validate_runtime_locality(runtime, value).unwrap_err();
            assert!(error.to_string().contains("remote runtime"));
        }
    }

    #[test]
    fn rejects_a_container_pid_change_and_sanitizes_its_name() {
        assert!(ensure_container_pid_unchanged(ContainerRuntime::Docker, "web", 41, 41).is_ok());

        let error = ensure_container_pid_unchanged(
            ContainerRuntime::Podman,
            "api\nforged\u{1b}[2J",
            41,
            42,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("api\\nforged\\u{1b}[2J"));
        assert!(error.contains("from 41 to 42"));
        assert!(!error.contains('\u{1b}'));
    }

    #[test]
    fn parses_a_positive_container_pid() {
        let pid = parse_container_pid(
            ContainerRuntime::Docker,
            "web",
            &output(true, b" 42\n", b""),
        )
        .unwrap();

        assert_eq!(pid, 42);
    }

    #[test]
    fn rejects_stopped_and_malformed_container_pids() {
        let stopped =
            parse_container_pid(ContainerRuntime::Podman, "api", &output(true, b"0\n", b""))
                .unwrap_err();
        let malformed = parse_container_pid(
            ContainerRuntime::Docker,
            "web",
            &output(true, b"not-a-pid\n", b""),
        )
        .unwrap_err();

        assert!(stopped.to_string().contains("is not running"));
        assert!(malformed.to_string().contains("invalid PID"));
    }

    #[test]
    fn validates_all_runtime_locality_output_failures() {
        let mut stderr_too_large = output(true, b"false\n", b"");
        stderr_too_large.stderr.truncated = true;
        assert!(
            runtime_output_value(
                ContainerRuntime::Podman,
                "locality check",
                &stderr_too_large
            )
            .unwrap_err()
            .to_string()
            .contains("error output exceeded")
        );

        for (stderr, expected) in [
            (b"".as_slice(), "failed without an error message"),
            (
                b"daemon\nfailed\x1b[2J".as_slice(),
                "daemon\\nfailed\\u{1b}[2J",
            ),
        ] {
            let failed = output(false, b"", stderr);
            let error = runtime_output_value(ContainerRuntime::Docker, "locality check", &failed)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected));
            assert!(!error.contains('\x1b'));
        }

        let mut stdout_too_large = output(true, b"false\n", b"");
        stdout_too_large.stdout.truncated = true;
        assert!(
            runtime_output_value(
                ContainerRuntime::Podman,
                "locality check",
                &stdout_too_large
            )
            .unwrap_err()
            .to_string()
            .contains("output exceeded")
        );
        assert!(
            runtime_output_value(
                ContainerRuntime::Podman,
                "locality check",
                &output(true, b"\xff", b""),
            )
            .unwrap_err()
            .to_string()
            .contains("non-UTF-8")
        );
        assert_eq!(
            runtime_output_value(
                ContainerRuntime::Podman,
                "locality check",
                &output(true, b" false\n", b""),
            )
            .unwrap(),
            "false"
        );
    }

    #[test]
    fn validates_all_container_pid_output_failures() {
        let mut stderr_too_large = output(true, b"42\n", b"");
        stderr_too_large.stderr.truncated = true;
        assert!(
            parse_container_pid(ContainerRuntime::Docker, "web", &stderr_too_large)
                .unwrap_err()
                .to_string()
                .contains("error output exceeded")
        );

        let failed_without_message = output(false, b"", b"");
        assert!(
            parse_container_pid(ContainerRuntime::Docker, "web", &failed_without_message,)
                .unwrap_err()
                .to_string()
                .contains("failed without an error message")
        );

        let mut stdout_too_large = output(true, b"42\n", b"");
        stdout_too_large.stdout.truncated = true;
        assert!(
            parse_container_pid(ContainerRuntime::Docker, "web", &stdout_too_large)
                .unwrap_err()
                .to_string()
                .contains("PID output exceeded")
        );
        assert!(
            parse_container_pid(ContainerRuntime::Docker, "web", &output(true, b"\xff", b""),)
                .unwrap_err()
                .to_string()
                .contains("non-UTF-8")
        );
    }

    #[test]
    fn sanitizes_runtime_errors_and_container_identifiers() {
        let error = parse_container_pid(
            ContainerRuntime::Docker,
            "web\nforged",
            &output(false, b"", b"daemon\nfailed\x1b[2J"),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("web\\nforged"));
        assert!(error.contains("daemon\\nfailed\\u{1b}[2J"));
        assert!(!error.contains('\x1b'));
    }

    #[test]
    fn bounds_runtime_output_while_draining_the_stream() {
        let input = vec![b'x'; MAX_RUNTIME_OUTPUT_BYTES + 1];

        let captured = read_bounded(input.as_slice()).unwrap();

        assert_eq!(captured.bytes.len(), MAX_RUNTIME_OUTPUT_BYTES);
        assert!(captured.truncated);
    }
}
