use clap::Parser;
use netwhy::{DiagnosisCode, Status, cli::Cli, diagnose};
use serde_json::Value;
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn cli_for(target: &str) -> Cli {
    Cli::try_parse_from(["netwhy", target, "--timeout-ms", "500"]).unwrap()
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

async fn accept_with_timeout(listener: &TcpListener) -> tokio::net::TcpStream {
    tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
        .await
        .expect("server timed out waiting for NetWhy")
        .unwrap()
        .0
}

fn assert_matches_schema(report: &netwhy::DiagnosticReport) {
    let schema: Value = serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
    let instance = serde_json::to_value(report).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema errors: {errors:#?}");
}

fn assert_schema_rejects(instance: &Value) {
    let schema: Value = serde_json::from_str(include_str!("../docs/report.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.iter_errors(instance).next().is_some());
}

#[tokio::test]
async fn raw_tcp_listener_passes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let report = diagnose(&cli_for(&listener.local_addr().unwrap().to_string()))
        .await
        .unwrap();

    assert_eq!(report.overall, Status::Pass);
    assert_eq!(report.diagnosis.code, DiagnosisCode::ConnectivityOk);
    assert_eq!(report.exit_code, 0);
    assert!(
        report
            .diagnosis
            .summary
            .contains("TCP connectivity succeeded")
    );
    assert_matches_schema(&report);

    let mut contradictory = serde_json::to_value(&report).unwrap();
    contradictory["overall"] = Value::String("fail".to_owned());
    contradictory["exit_code"] = Value::from(0);
    assert_schema_rejects(&contradictory);
}

#[tokio::test]
async fn refused_port_is_explained() {
    let (_reservation, address) = reserved_refused_address();

    let report = diagnose(&cli_for(&address.to_string())).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::TcpConnectionRefused);
    assert_eq!(report.exit_code, 1);
    assert!(report.diagnosis.summary.contains("refused"));
    assert_matches_schema(&report);
}

#[tokio::test]
async fn address_family_mismatch_is_a_dns_stage_failure() {
    let mut cli = cli_for("127.0.0.1");
    cli.ipv6 = true;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::DnsResolutionFailed);
    assert!(report.diagnosis.summary.contains("DNS resolution failed"));
    assert_matches_schema(&report);
}

#[tokio::test]
async fn http_error_is_reachable_but_warns() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // The first connection is the TCP stage; the second is the HTTP stage.
        let first = accept_with_timeout(&listener).await;
        drop(first);
        let mut stream = accept_with_timeout(&listener).await;
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let mut cli = cli_for(&format!("http://{address}/health"));
    cli.timeout_ms = 1_000;
    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Warn);
    assert_eq!(report.diagnosis.code, DiagnosisCode::HttpErrorStatus);
    assert_eq!(report.exit_code, 0);
    assert!(report.diagnosis.summary.contains("HTTP 503"));
    assert_eq!(report.application_attempts[0].status, Status::Warn);
    assert_eq!(
        report.application_attempts[0].http.as_ref().unwrap().status,
        Status::Warn
    );
    assert_eq!(report.request.timeout_ms, 1_000);
    assert_matches_schema(&report);
    let mut inconsistent = serde_json::to_value(&report).unwrap();
    inconsistent["application_attempts"][0]["status"] = Value::String("pass".to_owned());
    assert_schema_rejects(&inconsistent);
    server.await.unwrap();
}

#[tokio::test]
async fn successful_http_response_passes_the_application_pipeline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let first = accept_with_timeout(&listener).await;
        drop(first);
        let mut stream = accept_with_timeout(&listener).await;
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let report = diagnose(&cli_for(&format!("http://{address}/health")))
        .await
        .unwrap();

    assert_eq!(report.overall, Status::Pass);
    assert_eq!(report.diagnosis.code, DiagnosisCode::ConnectivityOk);
    assert!(report.diagnosis.summary.contains("application protocol"));
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn plain_server_on_https_port_is_a_tls_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let first = accept_with_timeout(&listener).await;
        drop(first);
        let mut stream = accept_with_timeout(&listener).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let report = diagnose(&cli_for(&format!("https://{address}/")))
        .await
        .unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::TlsHandshakeFailed);
    assert_eq!(report.proxy_transport.status, Status::Skip);
    assert!(report.diagnosis.summary.contains("TLS handshake fails"));
    assert_eq!(
        report.application_attempts[0]
            .tls
            .as_ref()
            .unwrap()
            .trust_source,
        "mozilla_webpki_roots"
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn http_response_honors_the_configured_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let first = accept_with_timeout(&listener).await;
        drop(first);
        let _stream = accept_with_timeout(&listener).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    });
    let mut cli = cli_for(&format!("http://{address}/"));
    cli.timeout_ms = 25;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::HttpExchangeFailed);
    assert!(report.diagnosis.summary.contains("HTTP exchange fails"));
    assert!(
        report
            .diagnosis
            .likely_cause
            .as_deref()
            .is_some_and(|cause| cause.contains("timed out"))
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn explicit_http_proxy_can_resolve_and_reach_the_target_remotely() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut request = vec![0_u8; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("HEAD http://does-not-exist.invalid/health HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let mut cli = cli_for("http://does-not-exist.invalid/health");
    cli.proxy_url = Some(format!("http://user:secret@{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Pass);
    assert_eq!(report.diagnosis.code, DiagnosisCode::ConnectivityOk);
    assert_eq!(report.request.application_transport, "proxy");
    assert_eq!(report.request.proxy_mode, "explicit");
    assert_eq!(report.proxy_transport.status, Status::Pass);
    assert_eq!(
        report.application_attempts[0]
            .http
            .as_ref()
            .unwrap()
            .status_code,
        Some(204)
    );
    assert!(
        !report
            .proxy_transport
            .selected_proxy
            .as_deref()
            .unwrap()
            .contains("secret")
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn refused_proxy_connection_is_structured_and_explained() {
    let (_reservation, proxy_address) = reserved_refused_address();
    let mut cli = cli_for("http://does-not-exist.invalid/health");
    cli.proxy_url = Some(format!("http://{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::ProxyConnectionFailed);
    assert_eq!(report.proxy_transport.status, Status::Fail);
    assert_eq!(report.proxy_transport.attempts.len(), 1);
    assert_eq!(report.proxy_transport.attempts[0].status, Status::Fail);
    assert_eq!(
        report.proxy_transport.attempts[0].error_kind.as_deref(),
        Some("connection_refused")
    );
    assert_eq!(report.application_attempts[0].connect.status, Status::Fail);
    assert_matches_schema(&report);
}

#[tokio::test]
async fn forward_proxy_authentication_rejection_is_a_proxy_failure() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut request = [0_u8; 1024];
        let count = stream.read(&mut request).await.unwrap();
        assert!(
            String::from_utf8_lossy(&request[..count])
                .starts_with("HEAD http://example.test/ HTTP/1.1\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut cli = cli_for("http://example.test/");
    cli.proxy_url = Some(format!("http://{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.exit_code, 1);
    assert_eq!(report.diagnosis.code, DiagnosisCode::ProxyConnectionFailed);
    assert_eq!(report.proxy_transport.status, Status::Fail);
    assert_eq!(report.proxy_transport.attempts[0].status, Status::Fail);
    assert_eq!(
        report.proxy_transport.attempts[0].error_kind.as_deref(),
        Some("permission_denied")
    );
    assert_eq!(
        report.application_attempts[0]
            .http
            .as_ref()
            .unwrap()
            .status_code,
        Some(407)
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn rejected_http_connect_is_a_proxy_connection_failure() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut request = [0_u8; 1024];
        let count = stream.read(&mut request).await.unwrap();
        assert!(
            String::from_utf8_lossy(&request[..count])
                .starts_with("CONNECT example.test:443 HTTP/1.1\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut cli = cli_for("tcp://example.test:443");
    cli.proxy_url = Some(format!("http://{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::ProxyConnectionFailed);
    assert_eq!(report.proxy_transport.status, Status::Fail);
    assert_eq!(report.proxy_transport.attempts[0].status, Status::Fail);
    assert_eq!(report.proxy_transport.attempts[0].tunnel_status, Some(407));
    assert!(
        report.application_attempts[0]
            .connect
            .error
            .as_deref()
            .is_some_and(|error| error.contains("HTTP 407"))
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn http_connect_proxy_supports_raw_tcp_targets() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut request = vec![0_u8; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("CONNECT does-not-exist.invalid:5432 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });
    let mut cli = cli_for("tcp://does-not-exist.invalid:5432");
    cli.proxy_url = Some(format!("http://{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Pass);
    assert_eq!(report.application_attempts[0].protocol, "tcp");
    assert_eq!(report.proxy_transport.attempts[0].tunnel_status, Some(200));
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn socks5h_proxy_uses_remote_hostname_resolution() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();

        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut tail = vec![0_u8; usize::from(header[4]) + 2];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail[..tail.len() - 2], b"does-not-exist.invalid");
        assert_eq!(&tail[tail.len() - 2..], &5432_u16.to_be_bytes());
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
    });
    let mut cli = cli_for("tcp://does-not-exist.invalid:5432");
    cli.proxy_url = Some(format!("socks5h://{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Pass);
    assert_eq!(report.proxy_transport.status, Status::Pass);
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn socks5_proxy_uses_local_dns_and_username_password_authentication() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        stream.write_all(&[5, 2]).await.unwrap();

        let mut auth_header = [0_u8; 2];
        stream.read_exact(&mut auth_header).await.unwrap();
        assert_eq!(auth_header[0], 1);
        let mut username = vec![0_u8; usize::from(auth_header[1])];
        stream.read_exact(&mut username).await.unwrap();
        let password_len = stream.read_u8().await.unwrap();
        let mut password = vec![0_u8; usize::from(password_len)];
        stream.read_exact(&mut password).await.unwrap();
        assert_eq!(username, b"alice");
        assert_eq!(password, b"secret");
        stream.write_all(&[1, 0]).await.unwrap();

        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..3], &[5, 1, 0]);
        let address_len = match header[3] {
            1 => 4,
            4 => 16,
            other => panic!("local SOCKS5 DNS used unexpected address type {other}"),
        };
        let mut destination = vec![0_u8; address_len + 2];
        stream.read_exact(&mut destination).await.unwrap();
        assert_eq!(&destination[address_len..], &5432_u16.to_be_bytes());
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
    });
    let mut cli = cli_for("tcp://localhost:5432");
    cli.proxy_url = Some(format!("socks5://alice:secret@{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Pass);
    assert_eq!(report.proxy_transport.status, Status::Pass);
    assert!(
        !report
            .proxy_transport
            .selected_proxy
            .as_deref()
            .unwrap()
            .contains("secret")
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}

#[tokio::test]
async fn https_target_performs_tls_inside_an_http_connect_tunnel() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_with_timeout(&proxy).await;
        let mut request = vec![0_u8; 4096];
        let count = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("CONNECT does-not-exist.invalid:443 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 200 Not TLS\r\n\r\n")
            .await
            .unwrap();
    });
    let mut cli = cli_for("https://does-not-exist.invalid/");
    cli.proxy_url = Some(format!("http://{proxy_address}"));
    cli.timeout_ms = 1_000;

    let report = diagnose(&cli).await.unwrap();

    assert_eq!(report.overall, Status::Fail);
    assert_eq!(report.diagnosis.code, DiagnosisCode::TlsHandshakeFailed);
    assert_eq!(report.proxy_transport.status, Status::Pass);
    assert_eq!(report.proxy_transport.attempts[0].tunnel_status, Some(200));
    assert_eq!(
        report.application_attempts[0].tls.as_ref().unwrap().status,
        Status::Fail
    );
    assert_matches_schema(&report);
    server.await.unwrap();
}
