use std::{
    ops::{Deref, DerefMut},
    path::PathBuf,
};

use clap::{Args, Parser, ValueEnum};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ProxyMode {
    /// Connect directly while still reporting detected proxy variables.
    #[default]
    Direct,
    /// Select HTTP(S)/SOCKS proxy transport from the execution context environment.
    Environment,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum RedactionLevel {
    /// Redact credentials and URL query/fragment values.
    #[default]
    Standard,
    /// Also pseudonymize targets, addresses, interfaces, containers, and plugin payloads.
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    Powershell,
    Zsh,
}

#[derive(Debug, Clone, Args)]
pub struct DiagnosticArgs {
    /// URL, hostname, IP address, or host:port to diagnose
    pub target: String,

    /// Emit a machine-readable JSON report
    #[arg(long)]
    pub json: bool,

    /// Diagnose from the network, mount, root, and proxy context of a Linux process
    #[arg(
        long,
        value_parser = clap::value_parser!(u32).range(1..),
        conflicts_with_all = ["docker", "podman"]
    )]
    pub pid: Option<u32>,

    /// Diagnose from the context of a running Docker container (Linux only)
    #[arg(
        long,
        value_name = "CONTAINER",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        conflicts_with_all = ["pid", "podman"]
    )]
    pub docker: Option<String>,

    /// Diagnose from the context of a running Podman container (Linux only)
    #[arg(
        long,
        value_name = "CONTAINER",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        conflicts_with_all = ["pid", "docker"]
    )]
    pub podman: Option<String>,

    /// Test IPv4 addresses only
    #[arg(long, conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Test IPv6 addresses only
    #[arg(long, conflicts_with = "ipv4")]
    pub ipv6: bool,

    /// Timeout for each network operation, in milliseconds
    #[arg(long, default_value_t = 3_000, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_ms: u64,

    /// Application transport selection
    #[arg(long, value_enum, default_value_t = ProxyMode::Direct)]
    pub proxy_mode: ProxyMode,

    /// Explicit HTTP, HTTPS, SOCKS5, or SOCKS5H proxy URL
    #[arg(long, value_name = "URL")]
    pub proxy_url: Option<String>,

    /// Run a versioned external evidence plugin (repeatable; maximum 8)
    #[arg(long, value_name = "PROGRAM", action = clap::ArgAction::Append)]
    pub plugin: Vec<PathBuf>,
}

/// Explain why a network connection succeeds or fails.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "netwhy",
    version,
    about,
    color = clap::ColorChoice::Never,
    long_about = "Trace a connection through DNS, system routing, TCP, TLS, HTTP, proxy, and host path evidence, then explain the most likely failure.",
    after_help = "Additional commands:\n  netwhy report [OPTIONS] <TARGET>\n  netwhy compare [OPTIONS] <LEFT.json> <RIGHT.json>\n  netwhy completions <SHELL>"
)]
pub struct Cli {
    #[command(flatten)]
    pub diagnostic: DiagnosticArgs,
}

impl Deref for Cli {
    type Target = DiagnosticArgs;

    fn deref(&self) -> &Self::Target {
        &self.diagnostic
    }
}

impl DerefMut for Cli {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.diagnostic
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "netwhy report",
    bin_name = "netwhy report",
    version,
    about = "Generate a shareable JSON diagnostic report",
    color = clap::ColorChoice::Never
)]
pub struct ReportCli {
    #[command(flatten)]
    pub diagnostic: DiagnosticArgs,

    /// Report redaction policy
    #[arg(long, value_enum, default_value_t = RedactionLevel::Standard)]
    pub redaction: RedactionLevel,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "netwhy compare",
    bin_name = "netwhy compare",
    version,
    about = "Compare two NetWhy JSON diagnostic reports",
    color = clap::ColorChoice::Never
)]
pub struct CompareCli {
    /// First diagnostic report
    pub left: PathBuf,

    /// Second diagnostic report
    pub right: PathBuf,

    /// Emit a machine-readable JSON comparison
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "netwhy completions",
    bin_name = "netwhy completions",
    version,
    about = "Generate shell completion definitions",
    color = clap::ColorChoice::Never
)]
pub struct CompletionsCli {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: CompletionShell,
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::{Cli, CompareCli, ProxyMode, RedactionLevel, ReportCli};

    #[test]
    fn parses_the_default_cli_contract() {
        let cli = Cli::try_parse_from(["netwhy", "example.test"]).unwrap();

        assert_eq!(cli.target, "example.test");
        assert!(!cli.json);
        assert_eq!(cli.pid, None);
        assert_eq!(cli.docker, None);
        assert_eq!(cli.podman, None);
        assert!(!cli.ipv4);
        assert!(!cli.ipv6);
        assert_eq!(cli.timeout_ms, 3_000);
    }

    #[test]
    fn parses_machine_readable_ipv4_options() {
        let cli = Cli::try_parse_from([
            "netwhy",
            "--json",
            "--ipv4",
            "--timeout-ms",
            "750",
            "https://example.test/health",
        ])
        .unwrap();

        assert_eq!(cli.target, "https://example.test/health");
        assert!(cli.json);
        assert!(cli.ipv4);
        assert!(!cli.ipv6);
        assert_eq!(cli.timeout_ms, 750);
    }

    #[test]
    fn parses_a_process_execution_context() {
        let cli = Cli::try_parse_from(["netwhy", "--pid", "42", "example.test"]).unwrap();

        assert_eq!(cli.pid, Some(42));
    }

    #[test]
    fn parses_container_execution_contexts() {
        let docker = Cli::try_parse_from(["netwhy", "--docker", "web", "example.test"]).unwrap();
        let podman = Cli::try_parse_from(["netwhy", "--podman", "api", "example.test"]).unwrap();

        assert_eq!(docker.docker.as_deref(), Some("web"));
        assert_eq!(docker.podman, None);
        assert_eq!(podman.podman.as_deref(), Some("api"));
        assert_eq!(podman.docker, None);
    }

    #[test]
    fn rejects_conflicting_execution_contexts() {
        for args in [
            ["netwhy", "--pid", "42", "--docker", "web", "example.test"],
            [
                "netwhy",
                "--docker",
                "web",
                "--podman",
                "api",
                "example.test",
            ],
        ] {
            let error = Cli::try_parse_from(args).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn rejects_pid_zero() {
        let error = Cli::try_parse_from(["netwhy", "--pid", "0", "example.test"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn rejects_conflicting_address_families() {
        let error =
            Cli::try_parse_from(["netwhy", "--ipv4", "--ipv6", "example.test"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn rejects_a_zero_timeout() {
        let error =
            Cli::try_parse_from(["netwhy", "--timeout-ms", "0", "example.test"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn parses_proxy_and_plugin_options() {
        let cli = Cli::try_parse_from([
            "netwhy",
            "--proxy-mode",
            "environment",
            "--proxy-url",
            "socks5h://proxy.test:1080",
            "--plugin",
            "/tmp/one",
            "--plugin",
            "/tmp/two",
            "example.test",
        ])
        .unwrap();

        assert_eq!(cli.proxy_mode, ProxyMode::Environment);
        assert_eq!(cli.proxy_url.as_deref(), Some("socks5h://proxy.test:1080"));
        assert_eq!(cli.plugin.len(), 2);
    }

    #[test]
    fn parses_report_and_compare_commands() {
        let report =
            ReportCli::try_parse_from(["netwhy report", "--redaction", "strict", "example.test"])
                .unwrap();
        assert_eq!(report.redaction, RedactionLevel::Strict);
        assert_eq!(report.diagnostic.target, "example.test");

        let compare =
            CompareCli::try_parse_from(["netwhy compare", "--json", "host.json", "container.json"])
                .unwrap();
        assert!(compare.json);
        assert_eq!(compare.left.to_string_lossy(), "host.json");
    }
}
