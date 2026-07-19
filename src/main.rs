use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

use clap::Parser;
use netwhy::{ErrorCode, ErrorReport, cli::Cli, diagnose, output};
use serde::Serialize;

#[tokio::main]
async fn main() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    let json_requested = requests_json(&args);
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) if error.exit_code() == 0 => {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            if json_requested {
                return emit_json_error(
                    ErrorCode::InvalidInvocation,
                    concise_clap_error(&error),
                    "Run `netwhy --help` to see valid targets and options.",
                );
            }
            let _ = error.print();
            return ExitCode::from(2);
        }
    };

    match diagnose(&cli).await {
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
    use std::ffi::OsString;

    use super::requests_json;

    #[test]
    fn json_prescan_stops_at_the_option_terminator() {
        let args = ["netwhy", "example.test", "--", "--json"].map(OsString::from);
        assert!(!requests_json(&args));

        let args = ["netwhy", "--json", "example.test"].map(OsString::from);
        assert!(requests_json(&args));
    }
}
