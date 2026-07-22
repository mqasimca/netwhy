use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, bail};
use url::{Host, Url};

use crate::sanitize_report_text;

#[derive(Debug, Clone)]
pub struct Target {
    pub original: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub url: Option<Url>,
    pub(crate) literal_address: Option<SocketAddr>,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            bail!("target cannot be empty");
        }

        if input.contains("://") {
            let url = Url::parse(input).context("invalid target URL")?;
            return Self::from_url(input, &url);
        }

        if let Ok(socket) = input.parse::<SocketAddr>() {
            if socket.port() == 0 {
                bail!("target port must be between 1 and 65535");
            }
            return Ok(Self {
                original: input.to_owned(),
                scheme: "tcp".to_owned(),
                host: socket_host(socket),
                port: socket.port(),
                url: None,
                literal_address: Some(socket),
            });
        }

        if let Ok(ip) = input.parse::<IpAddr>() {
            let host = match ip {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let url = Url::parse(&format!("https://{host}/"))?;
            return Self::from_url(input, &url);
        }

        let tcp_candidate = Url::parse(&format!("tcp://{input}"));
        if let Ok(url) = tcp_candidate
            && url.port().is_some()
        {
            return Self::from_url(input, &url);
        }

        let url = Url::parse(&format!("https://{input}/")).with_context(|| {
            format!(
                "invalid hostname or endpoint: {}",
                sanitize_report_text(input)
            )
        })?;
        Self::from_url(input, &url)
    }

    fn from_url(original: &str, url: &Url) -> Result<Self> {
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https" | "tcp") {
            bail!("unsupported scheme '{scheme}'; use http, https, or tcp");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!(
                "target URL credentials are not supported; remove userinfo and use an authenticated application client"
            );
        }

        let (host, literal_ip) = match url
            .host()
            .context("target must include a hostname or IP address")?
        {
            Host::Domain(host) => (host.to_owned(), None),
            Host::Ipv4(host) => (host.to_string(), Some(IpAddr::V4(host))),
            Host::Ipv6(host) => (host.to_string(), Some(IpAddr::V6(host))),
        };
        let port = url
            .port_or_known_default()
            .context("TCP targets must include a port")?;
        if port == 0 {
            bail!("target port must be between 1 and 65535");
        }
        let application_url = matches!(scheme, "http" | "https").then(|| url.clone());

        Ok(Self {
            original: original.to_owned(),
            scheme: scheme.to_owned(),
            host,
            port,
            url: application_url,
            literal_address: literal_ip.map(|ip| (ip, port).into()),
        })
    }

    #[must_use]
    pub fn request_path(&self) -> String {
        let Some(url) = &self.url else {
            return "/".to_owned();
        };

        let mut path = if url.path().is_empty() {
            "/".to_owned()
        } else {
            url.path().to_owned()
        };
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    }

    #[must_use]
    pub fn proxy_request_uri(&self) -> String {
        let Some(url) = &self.url else {
            return self.request_path();
        };
        let mut url = url.clone();
        url.set_fragment(None);
        url.to_string()
    }

    #[must_use]
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host.trim_matches(['[', ']']))
        } else {
            self.host.clone()
        };
        let default_port = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        if default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    #[must_use]
    pub fn connection_authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host.trim_matches(['[', ']']))
        } else {
            self.host.clone()
        };
        format!("{host}:{}", self.port)
    }

    #[must_use]
    pub fn original_report_value(&self) -> String {
        sanitize_report_text(redact_query_and_fragment(&self.original))
    }

    #[must_use]
    pub fn url_report_value(&self) -> String {
        let Some(url) = &self.url else {
            return self.original.clone();
        };

        let mut redacted = url.clone();
        if redacted.query().is_some() {
            redacted.set_query(Some("REDACTED"));
        }
        if redacted.fragment().is_some() {
            redacted.set_fragment(Some("REDACTED"));
        }
        redacted.to_string()
    }
}

fn socket_host(socket: SocketAddr) -> String {
    match socket {
        SocketAddr::V6(socket) if socket.scope_id() != 0 => {
            format!("{}%{}", socket.ip(), socket.scope_id())
        }
        _ => socket.ip().to_string(),
    }
}

fn redact_query_and_fragment(value: &str) -> String {
    let query = value.find('?');
    let fragment = value.find('#');
    let first_sensitive = [query, fragment].into_iter().flatten().min();
    let Some(first_sensitive) = first_sensitive else {
        return value.to_owned();
    };

    let mut redacted = value[..first_sensitive].to_owned();
    if query.is_some_and(|query| fragment.is_none_or(|fragment| query < fragment)) {
        redacted.push_str("?REDACTED");
    }
    if fragment.is_some() {
        redacted.push_str("#REDACTED");
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::Target;

    #[test]
    fn parses_https_url() {
        let target = Target::parse("https://example.com:8443/health?full=1").unwrap();
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);
        assert_eq!(target.request_path(), "/health?full=1");
        assert_eq!(target.host_header(), "example.com:8443");
    }

    #[test]
    fn defaults_bare_host_to_https() {
        let target = Target::parse("example.com").unwrap();
        assert_eq!(target.scheme, "https");
        assert_eq!(target.port, 443);
        assert_eq!(target.request_path(), "/");
        assert_eq!(target.host_header(), "example.com");
    }

    #[test]
    fn parses_host_port_as_tcp() {
        let target = Target::parse("localhost:5432").unwrap();
        assert_eq!(target.scheme, "tcp");
        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, 5432);
        assert!(target.url.is_none());
    }

    #[test]
    fn parses_bracketed_ipv6_socket() {
        let target = Target::parse("[::1]:8080").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn preserves_a_scoped_ipv6_socket() {
        let target = Target::parse("[fe80::1%3]:8080").unwrap();

        assert_eq!(target.host, "fe80::1%3");
        assert_eq!(
            target.literal_address,
            Some("[fe80::1%3]:8080".parse().unwrap())
        );
    }

    #[test]
    fn parses_bare_ipv6_as_https() {
        let target = Target::parse("::1").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
        assert_eq!(target.host_header(), "[::1]");
    }

    #[test]
    fn rejects_port_zero() {
        for value in ["127.0.0.1:0", "http://127.0.0.1:0/"] {
            let error = Target::parse(value).unwrap_err();
            assert!(error.to_string().contains("between 1 and 65535"));
        }
    }

    #[test]
    fn rejects_unknown_scheme() {
        let error = Target::parse("ftp://example.com").unwrap_err();
        assert!(error.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn rejects_url_credentials_and_redacts_report_tokens() {
        let error = Target::parse("https://alice:secret@example.com/").unwrap_err();
        assert!(error.to_string().contains("credentials are not supported"));

        let target = Target::parse("https://example.com/check?token=secret#private").unwrap();
        assert_eq!(
            target.original_report_value(),
            "https://example.com/check?REDACTED#REDACTED"
        );
        assert_eq!(
            target.url_report_value(),
            "https://example.com/check?REDACTED#REDACTED"
        );
        assert_eq!(target.request_path(), "/check?token=secret");
    }

    #[test]
    fn preserves_non_sensitive_original_input_in_reports() {
        let target = Target::parse("example.com").unwrap();
        assert_eq!(target.original_report_value(), "example.com");
        assert_eq!(target.url_report_value(), "https://example.com/");
    }

    #[test]
    fn escapes_controls_in_original_report_input() {
        let target = Target::parse("https://example.com/line\nbreak").unwrap();
        assert_eq!(
            target.original_report_value(),
            "https://example.com/line\\nbreak"
        );
    }

    #[test]
    fn rejects_empty_target() {
        let error = Target::parse("   ").unwrap_err();
        assert_eq!(error.to_string(), "target cannot be empty");
    }

    #[test]
    fn requires_a_port_for_tcp_urls() {
        let error = Target::parse("tcp://example.com").unwrap_err();
        assert!(error.to_string().contains("must include a port"));
    }

    #[test]
    fn requires_a_url_host() {
        let url = url::Url::parse("tcp:path").unwrap();
        let error = Target::from_url("tcp:path", &url).unwrap_err();
        assert!(error.to_string().contains("hostname or IP address"));
    }

    #[test]
    fn parses_ip_literal_urls() {
        let ipv4 = Target::parse("http://192.0.2.1/").unwrap();
        let ipv6 = Target::parse("https://[2001:db8::1]/").unwrap();

        assert_eq!(ipv4.host, "192.0.2.1");
        assert_eq!(ipv4.host_header(), "192.0.2.1");
        assert_eq!(ipv6.host, "2001:db8::1");
        assert_eq!(ipv6.host_header(), "[2001:db8::1]");
    }

    #[test]
    fn builds_application_paths_and_host_headers() {
        let target = Target::parse("https://example.com/search?q=rust").unwrap();
        let non_default = Target::parse("http://example.com:8080").unwrap();
        let tcp = Target::parse("example.com:443").unwrap();

        assert_eq!(target.request_path(), "/search?q=rust");
        assert_eq!(target.host_header(), "example.com");
        assert_eq!(target.connection_authority(), "example.com:443");
        assert_eq!(
            target.proxy_request_uri(),
            "https://example.com/search?q=rust"
        );
        assert_eq!(non_default.request_path(), "/");
        assert_eq!(non_default.host_header(), "example.com:8080");
        assert_eq!(non_default.connection_authority(), "example.com:8080");
        assert_eq!(tcp.request_path(), "/");
        assert_eq!(tcp.host_header(), "example.com:443");
        assert_eq!(tcp.url_report_value(), "example.com:443");
    }
}
