use std::{
    fmt::Write as _,
    future::Future,
    io::{Error, ErrorKind},
    sync::Arc,
    time::Duration,
};

use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use sha2::{Digest, Sha256};
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::{
    model::{
        ApplicationConnectResult, ApplicationReport, CertificateInfo, HttpResult,
        ProxyConnectResult, ProxyTransportEvidence, Status, TcpResult, TlsResult,
    },
    probe::tcp::error_kind,
    proxy::{SelectedProxy, basic_authorization},
    sanitize_report_text,
    target::Target,
};

trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedIo = Box<dyn IoStream>;

#[derive(Debug)]
struct HttpConnectStatusError(u16);

impl std::fmt::Display for HttpConnectStatusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "proxy CONNECT returned HTTP {}", self.0)
    }
}

impl std::error::Error for HttpConnectStatusError {}

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

pub(crate) async fn probe_via_proxy(
    target: &Target,
    proxy: &SelectedProxy,
    operation_timeout: Duration,
) -> (Vec<ApplicationReport>, ProxyTransportEvidence) {
    let mut applications = Vec::new();
    let mut proxy_attempts = Vec::new();
    for address in proxy.addresses.iter().copied() {
        let started = std::time::Instant::now();
        let stream = open_proxy_stream(proxy, target, address, operation_timeout).await;
        let (stream, tunnel_status) = match stream {
            Ok(stream) => stream,
            Err(error) => {
                let duration_ms = started.elapsed().as_millis();
                record_proxy_failure(
                    &mut applications,
                    &mut proxy_attempts,
                    target,
                    address,
                    duration_ms,
                    &error,
                );
                continue;
            }
        };
        let duration_ms = started.elapsed().as_millis();
        let application = probe_proxy_application(
            target,
            proxy,
            address,
            successful_connect(duration_ms),
            stream,
            operation_timeout,
        )
        .await;
        let proxy_rejection = (target.scheme == "http"
            && matches!(proxy.scheme(), "http" | "https"))
        .then(|| forwarded_proxy_rejection(&application))
        .flatten();
        proxy_attempts.push(ProxyConnectResult {
            status: if proxy_rejection.is_some() {
                Status::Fail
            } else {
                Status::Pass
            },
            address,
            duration_ms,
            tunnel_status,
            error_kind: proxy_rejection.map(|_| "permission_denied".to_owned()),
            error: proxy_rejection
                .map(|status| format!("forward proxy rejected the request with HTTP {status}")),
        });
        let reachable = proxy_rejection.is_none() && !application.status.is_failure();
        applications.push(application);
        if reachable {
            break;
        }
    }
    let status = if proxy_attempts
        .iter()
        .any(|attempt| attempt.status == Status::Pass)
    {
        Status::Pass
    } else {
        Status::Fail
    };
    (
        applications,
        ProxyTransportEvidence {
            status,
            mode: "proxy".to_owned(),
            selected_proxy: Some(proxy.redacted_url.clone()),
            bypassed: false,
            attempts: proxy_attempts,
            error_kind: None,
            error: None,
        },
    )
}

fn forwarded_proxy_rejection(application: &ApplicationReport) -> Option<u16> {
    application
        .http
        .as_ref()
        .and_then(|http| http.status_code)
        .filter(|status| *status == 407)
}

fn record_proxy_failure(
    applications: &mut Vec<ApplicationReport>,
    proxy_attempts: &mut Vec<ProxyConnectResult>,
    target: &Target,
    address: std::net::SocketAddr,
    duration_ms: u128,
    error: &Error,
) {
    let kind = error_kind(error.kind()).to_owned();
    let message = sanitize_report_text(error.to_string());
    let tunnel_status = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<HttpConnectStatusError>())
        .map(|source| source.0);
    proxy_attempts.push(ProxyConnectResult {
        status: Status::Fail,
        address,
        duration_ms,
        tunnel_status,
        error_kind: Some(kind.clone()),
        error: Some(message.clone()),
    });
    applications.push(connect_failure(
        &target.scheme,
        address,
        duration_ms,
        &kind,
        message,
    ));
}

async fn probe_proxy_application(
    target: &Target,
    proxy: &SelectedProxy,
    address: std::net::SocketAddr,
    connect: ApplicationConnectResult,
    stream: BoxedIo,
    operation_timeout: Duration,
) -> ApplicationReport {
    match target.scheme.as_str() {
        "tcp" => ApplicationReport {
            status: Status::Pass,
            protocol: "tcp".to_owned(),
            address,
            connect,
            tls: None,
            http: None,
        },
        "https" => probe_https_stream(target, address, connect, stream, operation_timeout).await,
        "http" => {
            let mut stream = stream;
            let authorization = basic_authorization(proxy);
            let http = if matches!(proxy.scheme(), "http" | "https") {
                http_exchange_proxy(
                    &mut stream,
                    target,
                    authorization.as_deref(),
                    operation_timeout,
                )
                .await
            } else {
                http_exchange(&mut stream, target, operation_timeout).await
            };
            ApplicationReport {
                status: http.status,
                protocol: "http".to_owned(),
                address,
                connect,
                tls: None,
                http: Some(http),
            }
        }
        _ => unreachable!("target parser restricts schemes"),
    }
}

async fn open_proxy_stream(
    proxy: &SelectedProxy,
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
) -> std::io::Result<(BoxedIo, Option<u16>)> {
    open_proxy_stream_with_roots(proxy, target, address, operation_timeout, default_roots()).await
}

async fn open_proxy_stream_with_roots(
    proxy: &SelectedProxy,
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
    proxy_roots: RootCertStore,
) -> std::io::Result<(BoxedIo, Option<u16>)> {
    let tcp = timeout(operation_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "proxy TCP connection timed out"))??;
    let mut stream: BoxedIo = if proxy.scheme() == "https" {
        let server_name = ServerName::try_from(proxy.host().to_owned()).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid proxy TLS server name: {error}"),
            )
        })?;
        let tls = timeout(
            operation_timeout,
            tls_connector(proxy_roots).connect(server_name, tcp),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "proxy TLS handshake timed out"))?
        .map_err(|error| Error::other(format!("proxy TLS handshake failed: {error}")))?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    match proxy.scheme() {
        "http" | "https" if target.scheme != "http" => {
            let status = http_connect(
                &mut stream,
                target,
                basic_authorization(proxy).as_deref(),
                operation_timeout,
            )
            .await?;
            Ok((stream, Some(status)))
        }
        "socks5" | "socks5h" => {
            socks5_connect(&mut stream, proxy, target, operation_timeout).await?;
            Ok((stream, None))
        }
        "http" | "https" => Ok((stream, None)),
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "unsupported proxy scheme",
        )),
    }
}

async fn http_connect(
    stream: &mut BoxedIo,
    target: &Target,
    authorization: Option<&str>,
    operation_timeout: Duration,
) -> std::io::Result<u16> {
    let authority = target.connection_authority();
    let authorization = authorization
        .map(|value| format!("Proxy-Authorization: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: netwhy/{}\r\n{authorization}Connection: keep-alive\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    timeout(operation_timeout, async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut reader = BufReader::new(stream);
        let line = read_crlf_line(&mut reader, MAX_STATUS_LINE_BYTES).await?;
        let (_, status) = parse_http_status_line(&line)?;
        drain_headers(&mut reader).await?;
        if !(200..300).contains(&status) {
            return Err(Error::new(
                ErrorKind::ConnectionRefused,
                HttpConnectStatusError(status),
            ));
        }
        Ok(status)
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "proxy CONNECT timed out"))?
}

async fn socks5_connect(
    stream: &mut BoxedIo,
    proxy: &SelectedProxy,
    target: &Target,
    operation_timeout: Duration,
) -> std::io::Result<()> {
    timeout(operation_timeout, async {
        socks5_authenticate(stream, proxy.credentials()).await?;
        let request = socks5_request(proxy, target).await?;
        stream.write_all(&request).await?;
        stream.flush().await?;
        read_socks5_response(stream).await
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "SOCKS5 negotiation timed out"))?
}

async fn socks5_authenticate(
    stream: &mut BoxedIo,
    credentials: Option<(String, String)>,
) -> std::io::Result<()> {
    let method = if credentials.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    stream.flush().await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, method] {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS5 proxy rejected the offered authentication method",
        ));
    }
    let Some((username, password)) = credentials else {
        return Ok(());
    };
    let username = username.as_bytes();
    let password = password.as_bytes();
    let username_len = u8::try_from(username.len()).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            "SOCKS5 username exceeds the 255-byte protocol limit",
        )
    })?;
    let password_len = u8::try_from(password.len()).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            "SOCKS5 password exceeds the 255-byte protocol limit",
        )
    })?;
    let mut request = Vec::with_capacity(username.len() + password.len() + 3);
    request.extend_from_slice(&[0x01, username_len]);
    request.extend_from_slice(username);
    request.push(password_len);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS5 username/password authentication failed",
        ));
    }
    Ok(())
}

async fn socks5_request(proxy: &SelectedProxy, target: &Target) -> std::io::Result<Vec<u8>> {
    let mut request = vec![0x05, 0x01, 0x00];
    let destination = if proxy.scheme() == "socks5" {
        if let Some(address) = target.literal_address.map(|address| address.ip()) {
            if !proxy.allows_ip(address) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "the SOCKS5 destination is excluded by the selected address family",
                ));
            }
            address
        } else {
            lookup_host((target.host.as_str(), target.port))
                .await?
                .find(|address| proxy.allows_ip(address.ip()))
                .map(|address| address.ip())
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        "local DNS returned no address for the SOCKS5 destination",
                    )
                })?
        }
    } else {
        let host = target.host.as_bytes();
        let host_len = u8::try_from(host.len()).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "SOCKS5 destination hostname exceeds 255 bytes",
            )
        })?;
        request.extend_from_slice(&[0x03, host_len]);
        request.extend_from_slice(host);
        request.extend_from_slice(&target.port.to_be_bytes());
        return Ok(request);
    };
    match destination {
        std::net::IpAddr::V4(address) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
}

async fn read_socks5_response(stream: &mut BoxedIo) -> std::io::Result<()> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[1] != 0x00 {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed with status {}", header[1]),
        ));
    }
    let address_bytes = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => usize::from(stream.read_u8().await?),
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "SOCKS5 proxy returned an invalid address type",
            ));
        }
    };
    let mut remainder = vec![0_u8; address_bytes + 2];
    stream.read_exact(&mut remainder).await?;
    Ok(())
}

async fn probe_https_stream(
    target: &Target,
    address: std::net::SocketAddr,
    connect: ApplicationConnectResult,
    stream: BoxedIo,
    operation_timeout: Duration,
) -> ApplicationReport {
    let trust_source = "mozilla_webpki_roots";
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
    let mut tls_stream = match timeout(
        operation_timeout,
        tls_connector(default_roots()).connect(server_name, stream),
    )
    .await
    {
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
    let peer_certificates = certificate_details(connection.peer_certificates());
    let http = http_exchange(&mut tls_stream, target, operation_timeout).await;
    ApplicationReport {
        status: http.status,
        protocol: "https".to_owned(),
        address,
        connect,
        tls: Some(TlsResult {
            status: Status::Pass,
            handshake_ms,
            trust_source: trust_source.to_owned(),
            version,
            cipher_suite,
            peer_certificates,
            error: None,
        }),
        http: Some(http),
    }
}

async fn probe_https(
    target: &Target,
    address: std::net::SocketAddr,
    operation_timeout: Duration,
) -> ApplicationReport {
    let roots = default_roots();
    probe_https_with_roots_and_source(
        target,
        address,
        operation_timeout,
        roots,
        "mozilla_webpki_roots",
    )
    .await
}

fn default_roots() -> RootCertStore {
    webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<RootCertStore>()
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
    let peer_certificates = certificate_details(connection.peer_certificates());

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
            peer_certificates,
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
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netwhy/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.request_path(),
        target.host_header(),
        env!("CARGO_PKG_VERSION")
    );
    http_exchange_with_request(stream, request, operation_timeout).await
}

async fn http_exchange_proxy<S>(
    stream: &mut S,
    target: &Target,
    authorization: Option<&str>,
    operation_timeout: Duration,
) -> HttpResult
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authorization = authorization
        .map(|value| format!("Proxy-Authorization: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netwhy/{}\r\nAccept: */*\r\n{authorization}Connection: close\r\n\r\n",
        target.proxy_request_uri(),
        target.host_header(),
        env!("CARGO_PKG_VERSION")
    );
    http_exchange_with_request(stream, request, operation_timeout).await
}

async fn http_exchange_with_request<S>(
    stream: &mut S,
    request: String,
    operation_timeout: Duration,
) -> HttpResult
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();

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
            peer_certificates: Vec::new(),
            error: Some(sanitize_report_text(error)),
        }),
        http: None,
    }
}

fn certificate_details(
    certificates: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> Vec<CertificateInfo> {
    certificates
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(position, certificate)| {
            let bytes = certificate.as_ref();
            let sha256 = Sha256::digest(bytes).iter().fold(
                String::with_capacity(64),
                |mut fingerprint, byte| {
                    let _ = write!(fingerprint, "{byte:02x}");
                    fingerprint
                },
            );
            let parsed = x509_parser::parse_x509_certificate(bytes)
                .ok()
                .map(|(_, value)| value);
            let mut dns_names = Vec::new();
            let mut ip_addresses = Vec::new();
            if let Some(parsed) = &parsed
                && let Ok(Some(names)) = parsed.subject_alternative_name()
            {
                for name in &names.value.general_names {
                    match name {
                        x509_parser::extensions::GeneralName::DNSName(value) => {
                            dns_names.push(sanitize_report_text(value));
                        }
                        x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                            let address = match bytes.len() {
                                4 => <[u8; 4]>::try_from(*bytes)
                                    .ok()
                                    .map(std::net::Ipv4Addr::from)
                                    .map(std::net::IpAddr::V4),
                                16 => <[u8; 16]>::try_from(*bytes)
                                    .ok()
                                    .map(std::net::Ipv6Addr::from)
                                    .map(std::net::IpAddr::V6),
                                _ => None,
                            };
                            if let Some(address) = address {
                                ip_addresses.push(address.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            CertificateInfo {
                position,
                der_bytes: bytes.len(),
                sha256,
                subject: parsed
                    .as_ref()
                    .map(|value| sanitize_report_text(value.subject().to_string())),
                issuer: parsed
                    .as_ref()
                    .map(|value| sanitize_report_text(value.issuer().to_string())),
                serial_number: parsed
                    .as_ref()
                    .map(|value| sanitize_report_text(value.raw_serial_as_string())),
                not_before_unix: parsed
                    .as_ref()
                    .map(|value| value.validity().not_before.timestamp()),
                not_after_unix: parsed
                    .as_ref()
                    .map(|value| value.validity().not_after.timestamp()),
                dns_names,
                ip_addresses,
            }
        })
        .collect()
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
        http_exchange, http_exchange_proxy, open_proxy_stream_with_roots, probe, probe_http,
        probe_http_with_connection, probe_https_with_connection, probe_https_with_roots,
        probe_via_proxy,
    };
    use crate::{
        model::{AddressFamily, Status, TcpResult},
        proxy::SelectedProxy,
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
    async fn treats_forward_proxy_407_as_a_proxy_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_with_timeout(&listener).await;
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let proxy = SelectedProxy {
            url: url::Url::parse(&format!("http://{address}")).unwrap(),
            redacted_url: format!("http://{address}/"),
            addresses: vec![address],
            address_family: crate::model::AddressFamilySelection::Any,
        };
        let target = Target::parse("http://example.test/").unwrap();

        let (applications, evidence) =
            probe_via_proxy(&target, &proxy, Duration::from_secs(1)).await;

        assert_eq!(evidence.status, Status::Fail);
        assert_eq!(evidence.attempts[0].status, Status::Fail);
        assert_eq!(
            evidence.attempts[0].error_kind.as_deref(),
            Some("permission_denied")
        );
        assert_eq!(
            applications[0].http.as_ref().unwrap().status_code,
            Some(407)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn preserves_failed_connect_status_in_proxy_evidence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_with_timeout(&listener).await;
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        let proxy = SelectedProxy {
            url: url::Url::parse(&format!("http://{address}")).unwrap(),
            redacted_url: format!("http://{address}/"),
            addresses: vec![address],
            address_family: crate::model::AddressFamilySelection::Any,
        };
        let target = Target::parse("tcp://example.test:443").unwrap();

        let (_, evidence) = probe_via_proxy(&target, &proxy, Duration::from_secs(1)).await;

        assert_eq!(evidence.status, Status::Fail);
        assert_eq!(evidence.attempts[0].tunnel_status, Some(407));
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
        assert_eq!(tls.peer_certificates.len(), 1);
        assert_eq!(tls.peer_certificates[0].sha256.len(), 64);
        assert!(
            tls.peer_certificates[0]
                .dns_names
                .iter()
                .any(|name| name == "localhost")
        );
        assert!(tls.peer_certificates[0].not_after_unix.is_some());
        assert_eq!(result.http.unwrap().status_code, Some(200));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sends_absolute_http_requests_over_a_trusted_https_proxy() {
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
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let count = stream.read(&mut chunk).await.unwrap();
                assert!(count > 0, "proxy request ended before its headers");
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 16 * 1024, "proxy request was not bounded");
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                request.starts_with("HEAD http://example.test:8080/health?ready=1 HTTP/1.1\r\n")
            );
            assert!(request.contains("\r\nHost: example.test:8080\r\n"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let proxy = SelectedProxy {
            url: url::Url::parse(&format!("https://localhost:{}", address.port())).unwrap(),
            redacted_url: format!("https://localhost:{}/", address.port()),
            addresses: vec![address],
            address_family: crate::model::AddressFamilySelection::Any,
        };
        let target = Target::parse("http://example.test:8080/health?ready=1").unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let (mut stream, tunnel_status) = Box::pin(open_proxy_stream_with_roots(
            &proxy,
            &target,
            address,
            Duration::from_secs(1),
            roots,
        ))
        .await
        .unwrap();

        let result = http_exchange_proxy(&mut stream, &target, None, Duration::from_secs(1)).await;

        assert_eq!(tunnel_status, None);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.status_code, Some(204));
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
