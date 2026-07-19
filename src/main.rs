use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
    time::Duration,
};

mod container_context;
mod process_context;

use clap::Parser;
use container_context::{ContainerRuntime, ensure_container_pid_unchanged, resolve_container_pid};
use netwhy::{DiagnosticContext, ErrorCode, ErrorReport, cli::Cli, diagnose_with_context, output};
use process_context::PreparedProcessContext;
use serde::Serialize;
use tokio::runtime::{Builder, Runtime};

fn main() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    let json_requested = requests_json(&args);
    let cli = match parse_cli(args, json_requested) {
        Ok(cli) => cli,
        Err(exit_code) => return exit_code,
    };
    let context = match prepare_context(&cli) {
        Ok(context) => context,
        Err(error) if cli.json => {
            return emit_json_error(
                ErrorCode::ContextUnavailable,
                format!(
                    "could not enter the selected {} context: {error:#}",
                    context_kind(&cli)
                ),
                context_hint(&cli),
            );
        }
        Err(error) => {
            eprintln!(
                "netwhy: selected {} context is unavailable: {error:#}",
                context_kind(&cli)
            );
            eprintln!("Hint: {}", context_hint(&cli));
            return ExitCode::from(2);
        }
    };
    let runtime = match build_runtime() {
        Ok(runtime) => runtime,
        Err(error) if cli.json => {
            return emit_json_error(
                ErrorCode::OutputError,
                format!("could not initialize the async runtime: {error}"),
                "Retry the command; if this repeats, report it as a NetWhy bug.",
            );
        }
        Err(error) => {
            eprintln!("netwhy: could not initialize the async runtime: {error}");
            return ExitCode::from(2);
        }
    };

    let exit_code = runtime.block_on(run(cli, context));
    shutdown_runtime(runtime);
    exit_code
}

fn parse_cli(args: Vec<OsString>, json_requested: bool) -> Result<Cli, ExitCode> {
    match Cli::try_parse_from(args) {
        Ok(cli) => Ok(cli),
        Err(error) if error.exit_code() == 0 => {
            let _ = error.print();
            Err(ExitCode::SUCCESS)
        }
        Err(error) => {
            if json_requested {
                Err(emit_json_error(
                    ErrorCode::InvalidInvocation,
                    concise_clap_error(&error),
                    "Run `netwhy --help` to see valid targets and options.",
                ))
            } else {
                let _ = error.print();
                Err(ExitCode::from(2))
            }
        }
    }
}

fn prepare_context(cli: &Cli) -> anyhow::Result<DiagnosticContext> {
    if let Some(pid) = cli.pid {
        return PreparedProcessContext::prepare(pid)?.enter();
    }
    let selection = cli
        .docker
        .as_deref()
        .map(|container| (ContainerRuntime::Docker, container))
        .or_else(|| {
            cli.podman
                .as_deref()
                .map(|container| (ContainerRuntime::Podman, container))
        });
    let Some((runtime, container)) = selection else {
        return Ok(DiagnosticContext::current());
    };

    let operation_timeout = Duration::from_millis(cli.timeout_ms);
    let pid = resolve_container_pid(runtime, container, operation_timeout)?;
    let prepared = PreparedProcessContext::prepare_container(
        pid,
        runtime.execution_source(),
        container.to_owned(),
    )?;
    let verified_pid = resolve_container_pid(runtime, container, operation_timeout)?;
    ensure_container_pid_unchanged(runtime, container, pid, verified_pid)?;
    prepared.enter()
}

fn context_kind(cli: &Cli) -> &'static str {
    if cli.docker.is_some() || cli.podman.is_some() {
        "container"
    } else {
        "process"
    }
}

fn context_hint(cli: &Cli) -> &'static str {
    if cli.podman.is_some() {
        "Check that the container is running and Podman is installed and accessible. For rootless Podman, run NetWhy through `podman unshare`; otherwise grant CAP_SYS_ADMIN and CAP_SYS_CHROOT when namespaces or root differ."
    } else if cli.docker.is_some() {
        "Check that the container is running, its runtime is installed and accessible, and grant CAP_SYS_ADMIN and CAP_SYS_CHROOT when its namespaces or root differ."
    } else {
        "Check that the PID still exists and grant CAP_SYS_ADMIN and CAP_SYS_CHROOT when its namespaces or root differ."
    }
}

fn build_runtime() -> io::Result<Runtime> {
    Builder::new_multi_thread().enable_all().build()
}

fn shutdown_runtime(runtime: Runtime) {
    // System DNS uses a non-cancellable blocking getaddrinfo task. Once the operation-level
    // timeout has produced a report, do not let that abandoned task keep the CLI process alive.
    runtime.shutdown_timeout(Duration::ZERO);
}

async fn run(cli: Cli, context: DiagnosticContext) -> ExitCode {
    match diagnose_with_context(&cli, context).await {
        Ok(report) if cli.json => emit_json(&report, report.exit_code),
        Ok(report) => emit_text(&output::render_human(&report), report.exit_code, false),
        Err(error) if cli.json => emit_json_error(
            ErrorCode::InvalidTarget,
            error.to_string(),
            "Use a URL, hostname, IP address, or host:port; supported schemes are tcp, http, and https.",
        ),
        Err(error) => {
            eprintln!("netwhy: invalid target: {error}");
            eprintln!(
                "Hint: use a URL, hostname, IP address, or host:port; run `netwhy --help` for examples."
            );
            ExitCode::from(2)
        }
    }
}

fn requests_json(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|argument| argument != &"--")
        .any(|argument| {
            argument
                .to_str()
                .is_some_and(|argument| argument == "--json" || argument.starts_with("--json="))
        })
}

fn concise_clap_error(error: &clap::Error) -> String {
    error
        .to_string()
        .lines()
        .find_map(|line| line.trim().strip_prefix("error: "))
        .unwrap_or("invalid command-line invocation")
        .to_owned()
}

fn emit_json<T: Serialize>(value: &T, intended_exit_code: u8) -> ExitCode {
    match serde_json::to_string_pretty(value) {
        Ok(json) => emit_text(&json, intended_exit_code, true),
        Err(error) => emit_json_error(
            ErrorCode::OutputError,
            format!("could not serialize JSON output: {error}"),
            "Retry the command; if this repeats, report it as a NetWhy bug.",
        ),
    }
}

fn emit_json_error(
    code: ErrorCode,
    message: impl Into<String>,
    hint: impl Into<String>,
) -> ExitCode {
    let report = ErrorReport::new(code, message, hint);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => emit_text(&json, 2, true),
        Err(error) => {
            eprintln!("netwhy: could not serialize an error report: {error}");
            ExitCode::from(2)
        }
    }
}

fn emit_text(text: &str, intended_exit_code: u8, json_mode: bool) -> ExitCode {
    let result = (|| -> io::Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        stdout.write_all(text.as_bytes())?;
        if !text.ends_with('\n') {
            stdout.write_all(b"\n")?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => ExitCode::from(intended_exit_code),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            ExitCode::from(intended_exit_code)
        }
        Err(error) => {
            if json_mode {
                let fallback = ErrorReport::new(
                    ErrorCode::OutputError,
                    format!("could not write JSON output: {error}"),
                    "Check that stdout is open and writable, then retry.",
                );
                if let Ok(json) = serde_json::to_string(&fallback) {
                    eprintln!("{json}");
                }
            } else {
                eprintln!("netwhy: could not write output: {error}");
            }
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        sync::mpsc,
        time::{Duration, Instant},
    };

    use super::{build_runtime, requests_json, shutdown_runtime};

    #[test]
    fn json_prescan_stops_at_the_option_terminator() {
        let args = ["netwhy", "example.test", "--", "--json"].map(OsString::from);
        assert!(!requests_json(&args));

        let args = ["netwhy", "--json", "example.test"].map(OsString::from);
        assert!(requests_json(&args));
    }

    #[test]
    fn runtime_shutdown_does_not_wait_for_an_abandoned_blocking_task() {
        let runtime = build_runtime().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        runtime.handle().spawn_blocking(move || {
            started_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let started = Instant::now();
        shutdown_runtime(runtime);
        drop(release_tx);

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "runtime shutdown waited for an abandoned blocking task"
        );
    }
}
