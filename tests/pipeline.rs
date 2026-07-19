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
