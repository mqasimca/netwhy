use std::{
    future::Future,
    io::{Error, ErrorKind},
    sync::Arc,
    time::Duration,
};

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::{
    model::{
        ApplicationConnectResult, ApplicationReport, HttpResult, Status, TcpResult, TlsResult,
    },
    probe::tcp::error_kind,
    sanitize_report_text,
    target::Target,
};

pub async fn probe(
    target: &Target,
    tcp_results: &[TcpResult],
    operation_timeout: Duration,
) -> Vec<ApplicationReport> {
    if target.scheme == "tcp" {
        return Vec::new();
    }

    let mut candidates = tcp_results
        .iter()
        .filter(|result| result.status == Status::Pass)
        .collect::<Vec<_>>();
    candidates.sort_by_key(|result| result.duration_ms);

    let mut attempts = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let attempt = if target.scheme == "https" {
            probe_https(target, candidate.address, operation_timeout).await
        } else {
            probe_http(target, candidate.address, operation_timeout).await
        };
        let reachable = !attempt.status.is_failure();
        attempts.push(attempt);
        if reachable {
            break;
        }
    }
    attempts
}

async fn probe_https(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
) -> ApplicationReport {
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<RootCertStore>();
    probe_https_with_roots_and_source(
        target,
        address,
        operation_timeout,
        roots,
        "mozilla_webpki_roots",
    )
    .await
}

#[cfg(test)]
async fn probe_https_with_roots(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
    roots: RootCertStore,
) -> ApplicationReport {
    probe_https_with_roots_and_source(target, address, operation_timeout, roots, "custom_roots")
        .await
}

async fn probe_https_with_roots_and_source(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
    roots: RootCertStore,
    trust_source: &str,
) -> ApplicationReport {
    probe_https_with_connection(
        target,
        address,
        operation_timeout,
        roots,
        trust_source,
        TcpStream::connect(address),
    )
    .await
}

async fn probe_https_with_connection<F>(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
    roots: RootCertStore,
    trust_source: &str,
    connection: F,
) -> ApplicationReport
where
    F: Future<Output = std::io::Result<TcpStream>>,
{
    let connect_started = std::time::Instant::now();
    let stream = match timeout(operation_timeout, connection).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return connect_failure(
                "https",
                address,
                connect_started.elapsed().as_millis(),
                error_kind(error.kind()),
                error.to_string(),
            );
        }
        Err(_) => {
            return connect_failure(
                "https",
                address,
                connect_started.elapsed().as_millis(),
                "timeout",
                format!(
                    "TCP connection timed out after {} ms",
                    operation_timeout.as_millis()
                ),
            );
        }
    };
    let connect_ms = connect_started.elapsed().as_millis();
    let connect = successful_connect(connect_ms);

    let server_name = match ServerName::try_from(target.host.clone()) {
        Ok(name) => name,
        Err(error) => {
            return tls_failure(
                address,
                connect,
                0,
                trust_source,
                format!("invalid TLS server name: {error}"),
            );
        }
    };

    let handshake_started = std::time::Instant::now();
    let connector = tls_connector(roots);
    let mut tls_stream =
        match timeout(operation_timeout, connector.connect(server_name, stream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                return tls_failure(
                    address,
                    connect,
                    handshake_started.elapsed().as_millis(),
                    trust_source,
                    error.to_string(),
                );
            }
            Err(_) => {
                return tls_failure(
                    address,
                    connect,
                    handshake_started.elapsed().as_millis(),
                    trust_source,
                    format!(
                        "TLS handshake timed out after {} ms",
                        operation_timeout.as_millis()
                    ),
                );
            }
        };
    let handshake_ms = handshake_started.elapsed().as_millis();
    let connection = &tls_stream.get_ref().1;
    let version = connection
        .protocol_version()
        .map(|value| format!("{value:?}"));
    let cipher_suite = connection
        .negotiated_cipher_suite()
        .map(|value| format!("{:?}", value.suite()));

    let http = http_exchange(&mut tls_stream, target, operation_timeout).await;
    let status = http.status;
    ApplicationReport {
        status,
        protocol: "https".to_owned(),
        address,
        connect,
        tls: Some(TlsResult {
            status: Status::Pass,
            handshake_ms,
            trust_source: trust_source.to_owned(),
            version,
            cipher_suite,
            error: None,
        }),
        http: Some(http),
    }
}

async fn probe_http(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
) -> ApplicationReport {
    probe_http_with_connection(
        target,
        address,
        operation_timeout,
        TcpStream::connect(address),
    )
    .await
}

async fn probe_http_with_connection<F>(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
    connection: F,
) -> ApplicationReport
where
    F: Future<Output = std::io::Result<TcpStream>>,
{
    let started = std::time::Instant::now();
    let stream = timeout(operation_timeout, connection).await;
    let mut stream = match stream {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            return connect_failure(
                "http",
                address,
                started.elapsed().as_millis(),
                error_kind(error.kind()),
                error.to_string(),
            );
        }
        Err(_) => {
            return connect_failure(
                "http",
                address,
                started.elapsed().as_millis(),
                "timeout",
                format!(
                    "HTTP connection timed out after {} ms",
                    operation_timeout.as_millis()
                ),
            );
        }
    };
    let connect = successful_connect(started.elapsed().as_millis());
    let http = http_exchange(&mut stream, target, operation_timeout).await;
    let status = http.status;

    ApplicationReport {
        status,
        protocol: "http".to_owned(),
        address,
        connect,
        tls: None,
        http: Some(http),
    }
}

async fn http_exchange<S>(
    stream: &mut S,
    target: &Target,
    operation_timeout: Duration,
) -> HttpResult
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netwhy/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.request_path(),
        target.host_header(),
        env!("CARGO_PKG_VERSION")
    );

    let exchange = async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        for informational_count in 0..=MAX_INFORMATIONAL_RESPONSES {
            let bytes = read_crlf_line(&mut reader, MAX_STATUS_LINE_BYTES).await?;
            let (status_line, status_code) = parse_http_status_line(&bytes)?;
            if (100..200).contains(&status_code) && status_code != 101 {
                if informational_count == MAX_INFORMATIONAL_RESPONSES {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "too many informational HTTP responses",
                    ));
                }
                drain_headers(&mut reader).await?;
                continue;
            }
            return Ok::<(String, u16), std::io::Error>((status_line, status_code));
        }
        unreachable!("informational response loop always returns")
    };

    match timeout(operation_timeout, exchange).await {
        Ok(Ok((status_line, status_code))) => HttpResult {
            status: if status_code >= 400 {
                Status::Warn
            } else {
                Status::Pass
            },
            duration_ms: started.elapsed().as_millis(),
            status_code: Some(status_code),
            status_line: Some(status_line),
            error: None,
        },
        Ok(Err(error)) => HttpResult {
            status: Status::Fail,
            duration_ms: started.elapsed().as_millis(),
            status_code: None,
            status_line: None,
            error: Some(sanitize_report_text(error.to_string())),
        },
        Err(_) => HttpResult {
            status: Status::Fail,
            duration_ms: started.elapsed().as_millis(),
            status_code: None,
            status_line: None,
            error: Some(format!(
                "HTTP response timed out after {} ms",
                operation_timeout.as_millis()
            )),
        },
    }
}

const MAX_STATUS_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_INFORMATIONAL_HEADER_BYTES: usize = 64 * 1024;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

async fn read_crlf_line<R>(reader: &mut R, max_bytes: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::with_capacity(max_bytes.min(1024));
    reader
        .take((max_bytes + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await?;
    if bytes.is_empty() {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "server closed the connection without an HTTP response",
        ));
    }
    if bytes.len() > max_bytes {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("HTTP line exceeds the {max_bytes}-byte safety limit"),
        ));
    }
    if !bytes.ends_with(b"\r\n") {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "HTTP line is not terminated with CRLF",
        ));
    }
    Ok(bytes)
}

fn parse_http_status_line(bytes: &[u8]) -> std::io::Result<(String, u16)> {
    let line = std::str::from_utf8(&bytes[..bytes.len() - 2]).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "HTTP status line is not valid UTF-8",
        )
    })?;
    if line.chars().any(char::is_control) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "HTTP status line contains control characters",
        ));
    }

    let mut parts = line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || code.len() != 3
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid HTTP status line",
        ));
    }
    let status_code = code
        .parse::<u16>()
        .ok()
        .filter(|code| (100..=599).contains(code))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid HTTP status code"))?;
    Ok((line.to_owned(), status_code))
}

async fn drain_headers<R>(reader: &mut R) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    let mut total = 0;
    loop {
        let line = read_crlf_line(reader, MAX_HEADER_LINE_BYTES).await?;
        total += line.len();
        if total > MAX_INFORMATIONAL_HEADER_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "informational HTTP headers exceed the safety limit",
            ));
        }
        if line == b"\r\n" {
            return Ok(());
        }
    }
}

fn tls_failure(
    address: std::net::SocketAddr,
    connect: ApplicationConnectResult,
    handshake_ms: u128,
    trust_source: &str,
    error: String,
) -> ApplicationReport {
    ApplicationReport {
        status: Status::Fail,
        protocol: "https".to_owned(),
        address,
        connect,
        tls: Some(TlsResult {
            status: Status::Fail,
            handshake_ms,
            trust_source: trust_source.to_owned(),
            version: None,
            cipher_suite: None,
            error: Some(sanitize_report_text(error)),
        }),
        http: None,
    }
}

fn successful_connect(duration_ms: u128) -> ApplicationConnectResult {
    ApplicationConnectResult {
        status: Status::Pass,
        duration_ms,
        error_kind: None,
        error: None,
    }
}

fn connect_failure(
    protocol: &str,
    address: std::net::SocketAddr,
    duration_ms: u128,
    error_kind: &str,
    error: String,
) -> ApplicationReport {
    ApplicationReport {
        status: Status::Fail,
        protocol: protocol.to_owned(),
        address,
        connect: ApplicationConnectResult {
            status: Status::Fail,
            duration_ms,
            error_kind: Some(error_kind.to_owned()),
            error: Some(sanitize_report_text(error)),
        },
        tls: None,
        http: None,
    }
}

fn tls_connector(roots: RootCertStore) -> TlsConnector {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::{future::pending, sync::Arc, time::Duration};

    use rustls::{RootCertStore, ServerConfig};
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsAcceptor;

    use super::{
        http_exchange, probe, probe_http, probe_http_with_connection, probe_https_with_connection,
        probe_https_with_roots,
    };
    use crate::{
        model::{AddressFamily, Status, TcpResult},
        target::Target,
    };

    async fn accept_with_timeout(listener: &TcpListener) -> tokio::net::TcpStream {
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("server timed out waiting for NetWhy")
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn reads_an_http_status_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_with_timeout(&listener).await;
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let target = Target::parse(&format!("http://{address}/health")).unwrap();

        let result = probe_http(&target, address, Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.http.unwrap().status_code, Some(204));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn validates_a_trusted_tls_server() {
        let cert_der = CertificateDer::from_pem_slice(include_bytes!(
            "../../tests/fixtures/tls/localhost-cert.pem"
        ))
        .unwrap();
        let private_key = PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../tests/fixtures/tls/localhost-key.pem"
        ))
        .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], private_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let stream = accept_with_timeout(&listener).await;
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let target = Target::parse(&format!("https://localhost:{}/", address.port())).unwrap();

        let result = probe_https_with_roots(&target, address, Duration::from_secs(1), roots).await;

        assert_eq!(result.status, Status::Pass, "{result:#?}");
        let tls = result.tls.unwrap();
        assert_eq!(tls.status, Status::Pass);
        assert_eq!(tls.trust_source, "custom_roots");
        assert_eq!(result.http.unwrap().status_code, Some(200));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_an_invalid_http_status_line() {
        let (mut client, mut server) = duplex(1024);
        let peer = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let _ = server.read(&mut request).await.unwrap();
            server.write_all(b"NOT-HTTP 200 maybe\r\n").await.unwrap();
        });
        let target = Target::parse("http://example.test/health").unwrap();

        let result = http_exchange(&mut client, &target, Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.status_code, None);
        assert_eq!(result.error.as_deref(), Some("invalid HTTP status line"));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_and_control_character_status_lines() {
        for response in [
            {
                let mut response = b"HTTP/1.1 200 ".to_vec();
                response.resize(super::MAX_STATUS_LINE_BYTES + 1, b'x');
                response
            },
            b"HTTP/1.1 200 forged\x1b[2J\r\n".to_vec(),
            b"HTTP/1.1 200 OK\n".to_vec(),
            b"HTTP/1.1 200 \xff\r\n".to_vec(),
        ] {
            let (mut client, mut server) = duplex(16 * 1024);
            let peer = tokio::spawn(async move {
                let mut request = [0_u8; 512];
                let _ = server.read(&mut request).await.unwrap();
                server.write_all(&response).await.unwrap();
            });
            let target = Target::parse("http://example.test/").unwrap();

            let result = http_exchange(&mut client, &target, Duration::from_secs(1)).await;

            assert_eq!(result.status, Status::Fail);
            assert!(result.error.is_some());
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_excessive_informational_responses_and_headers() {
        let mut responses = Vec::new();
        for _ in 0..=super::MAX_INFORMATIONAL_RESPONSES {
            responses.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n\r\n");
        }
        let mut oversized_headers = b"HTTP/1.1 103 Early Hints\r\n".to_vec();
        let header = format!("X-Fill: {}\r\n", "x".repeat(8_000));
        while oversized_headers.len() <= super::MAX_INFORMATIONAL_HEADER_BYTES {
            oversized_headers.extend_from_slice(header.as_bytes());
        }

        for (response, expected) in [
            (responses, "too many informational HTTP responses"),
            (
                oversized_headers,
                "informational HTTP headers exceed the safety limit",
            ),
        ] {
            let (mut client, mut server) = duplex(128 * 1024);
            let peer = tokio::spawn(async move {
                let mut request = [0_u8; 512];
                let _ = server.read(&mut request).await.unwrap();
                server.write_all(&response).await.unwrap();
            });
            let target = Target::parse("http://example.test/").unwrap();

            let result = http_exchange(&mut client, &target, Duration::from_secs(1)).await;

            assert_eq!(result.status, Status::Fail);
            assert_eq!(result.error.as_deref(), Some(expected));
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn follows_informational_responses_and_warns_on_final_http_error() {
        let (mut client, mut server) = duplex(2048);
        let peer = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let _ = server.read(&mut request).await.unwrap();
            server
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 503 Service Unavailable\r\n",
                )
                .await
                .unwrap();
        });
        let target = Target::parse("http://example.test/").unwrap();

        let result = http_exchange(&mut client, &target, Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Warn);
        assert_eq!(result.status_code, Some(503));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn retries_application_probe_on_another_successful_tcp_address() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_address = first.local_addr().unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_address = second.local_addr().unwrap();
        let first_server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), first.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).await.unwrap();
        });
        let second_server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), second.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        });
        let target = Target::parse("http://example.test/").unwrap();
        let tcp = [
            TcpResult {
                status: Status::Pass,
                address: first_address,
                family: AddressFamily::Ipv4,
                duration_ms: 1,
                error_kind: None,
                error: None,
            },
            TcpResult {
                status: Status::Pass,
                address: second_address,
                family: AddressFamily::Ipv4,
                duration_ms: 2,
                error_kind: None,
                error: None,
            },
        ];

        let attempts = probe(&target, &tcp, Duration::from_secs(1)).await;

        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].status, Status::Fail);
        assert_eq!(attempts[1].status, Status::Pass);
        first_server.await.unwrap();
        second_server.await.unwrap();
    }

    #[tokio::test]
    async fn reports_an_empty_http_response() {
        let (mut client, mut server) = duplex(1024);
        let peer = tokio::spawn(async move {
            let mut request = [0_u8; 512];
            let _ = server.read(&mut request).await.unwrap();
        });
        let target = Target::parse("http://example.test/").unwrap();

        let result = http_exchange(&mut client, &target, Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Fail);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("without an HTTP response"))
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn reports_http_stream_io_errors() {
        let (mut client, server) = duplex(64);
        drop(server);
        let target = Target::parse("http://example.test/").unwrap();

        let result = http_exchange(&mut client, &target, Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Fail);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn reports_fresh_http_connection_failure() {
        let address = "0.0.0.0:0".parse().unwrap();
        let target = Target::parse("http://example.test/").unwrap();

        let result = probe_http(&target, address, Duration::from_secs(1)).await;

        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.connect.status, Status::Fail);
        assert!(result.connect.error.is_some());
        assert!(result.http.is_none());
    }

    #[tokio::test]
    async fn reports_fresh_https_connection_failure() {
        let address = "0.0.0.0:0".parse().unwrap();
        let target = Target::parse("https://localhost/").unwrap();

        let result = probe_https_with_roots(
            &target,
            address,
            Duration::from_secs(1),
            RootCertStore::empty(),
        )
        .await;

        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.connect.status, Status::Fail);
        assert!(result.connect.error.is_some());
        assert!(result.tls.is_none());
    }

    #[tokio::test]
    async fn bounds_fresh_application_connection_attempts() {
        let address = "192.0.2.1:443".parse().unwrap();
        let http_target = Target::parse("http://example.test/").unwrap();
        let https_target = Target::parse("https://example.test/").unwrap();

        let http = probe_http_with_connection(
            &http_target,
            address,
            Duration::from_millis(1),
            pending::<std::io::Result<TcpStream>>(),
        )
        .await;
        let https = probe_https_with_connection(
            &https_target,
            address,
            Duration::from_millis(1),
            RootCertStore::empty(),
            "custom_roots",
            pending::<std::io::Result<TcpStream>>(),
        )
        .await;

        assert_eq!(http.connect.error_kind.as_deref(), Some("timeout"));
        assert_eq!(https.connect.error_kind.as_deref(), Some("timeout"));
    }

    #[tokio::test]
    async fn reports_an_invalid_tls_server_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            drop(accept_with_timeout(&listener).await);
        });
        let mut target = Target::parse(&format!("https://localhost:{}/", address.port())).unwrap();
        target.host.clear();

        let result = probe_https_with_roots(
            &target,
            address,
            Duration::from_secs(1),
            RootCertStore::empty(),
        )
        .await;

        assert_eq!(result.status, Status::Fail);
        assert!(
            result
                .tls
                .unwrap()
                .error
                .as_deref()
                .is_some_and(|error| error.contains("invalid TLS server name"))
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reports_tls_handshake_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _stream = accept_with_timeout(&listener).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let target = Target::parse(&format!("https://localhost:{}/", address.port())).unwrap();

        let result = probe_https_with_roots(
            &target,
            address,
            Duration::from_millis(10),
            RootCertStore::empty(),
        )
        .await;

        assert_eq!(result.status, Status::Fail);
        assert!(
            result
                .tls
                .unwrap()
                .error
                .as_deref()
                .is_some_and(|error| error.contains("handshake timed out"))
        );
        server.await.unwrap();
    }
}
