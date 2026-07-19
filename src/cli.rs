use clap::Parser;

/// Explain why a network connection succeeds or fails.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "netwhy",
    version,
    about,
    color = clap::ColorChoice::Never,
    long_about = "Trace a connection through DNS, system routing, TCP, TLS, and HTTP, then explain the most likely failure."
)]
pub struct Cli {
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
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::Cli;

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
}
