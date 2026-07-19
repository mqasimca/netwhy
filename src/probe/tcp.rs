use std::{future::Future, io::ErrorKind, net::SocketAddr, time::Duration};

use tokio::{net::TcpStream, task::JoinSet, time::timeout};

use crate::{
    model::{AddressFamily, Status, TcpResult},
    sanitize_report_text,
};

const MAX_CONCURRENT_CONNECTS: usize = 8;

pub async fn connect_all(addresses: &[SocketAddr], operation_timeout: Duration) -> Vec<TcpResult> {
    let mut tasks = JoinSet::new();
    let mut pending = addresses.iter().copied().enumerate();
    for (index, address) in pending.by_ref().take(MAX_CONCURRENT_CONNECTS) {
        tasks.spawn(async move { (index, connect_one(address, operation_timeout).await) });
    }

    let mut results = Vec::with_capacity(addresses.len());
    while let Some(result) = tasks.join_next().await {
        if let Ok(result) = result {
            results.push(result);
        }
        if let Some((index, address)) = pending.next() {
            tasks.spawn(async move { (index, connect_one(address, operation_timeout).await) });
        }
    }
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

async fn connect_one(address: SocketAddr, operation_timeout: Duration) -> TcpResult {
    connect_with(address, operation_timeout, TcpStream::connect(address)).await
}

async fn connect_with<F, T>(
    address: SocketAddr,
    operation_timeout: Duration,
    connection: F,
) -> TcpResult
where
    F: Future<Output = std::io::Result<T>>,
{
    let started = std::time::Instant::now();
    match timeout(operation_timeout, connection).await {
        Ok(Ok(_stream)) => TcpResult {
            status: Status::Pass,
            address,
            family: AddressFamily::from(&address),
            duration_ms: started.elapsed().as_millis(),
            error_kind: None,
            error: None,
        },
        Ok(Err(error)) => TcpResult {
            status: Status::Fail,
            address,
            family: AddressFamily::from(&address),
            duration_ms: started.elapsed().as_millis(),
            error_kind: Some(error_kind(error.kind()).to_owned()),
            error: Some(sanitize_report_text(error.to_string())),
        },
        Err(_) => TcpResult {
            status: Status::Fail,
            address,
            family: AddressFamily::from(&address),
            duration_ms: started.elapsed().as_millis(),
            error_kind: Some("timeout".to_owned()),
            error: Some(format!(
                "connection timed out after {} ms",
                operation_timeout.as_millis()
            )),
        },
    }
}

pub(crate) fn error_kind(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "address_in_use",
        ErrorKind::AddrNotAvailable => "address_unavailable",
        ErrorKind::TimedOut => "timeout",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::NetworkUnreachable => "network_unreachable",
        ErrorKind::HostUnreachable => "host_unreachable",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use std::{future::pending, io, io::ErrorKind, time::Duration};

    use tokio::net::TcpListener;

    use super::{connect_all, connect_with, error_kind};
    use crate::model::Status;

    #[tokio::test]
    async fn reports_a_listening_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let result = connect_all(&[address], Duration::from_secs(1)).await;

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].status, Status::Pass);
    }

    #[test]
    fn assigns_stable_codes_to_socket_errors() {
        let cases = [
            (ErrorKind::ConnectionRefused, "connection_refused"),
            (ErrorKind::ConnectionReset, "connection_reset"),
            (ErrorKind::ConnectionAborted, "connection_aborted"),
            (ErrorKind::NotConnected, "not_connected"),
            (ErrorKind::AddrInUse, "address_in_use"),
            (ErrorKind::AddrNotAvailable, "address_unavailable"),
            (ErrorKind::TimedOut, "timeout"),
            (ErrorKind::PermissionDenied, "permission_denied"),
            (ErrorKind::NetworkUnreachable, "network_unreachable"),
            (ErrorKind::HostUnreachable, "host_unreachable"),
            (ErrorKind::InvalidInput, "other"),
        ];

        for (kind, expected) in cases {
            assert_eq!(error_kind(kind), expected);
        }
    }

    #[tokio::test]
    async fn enforces_the_connection_timeout() {
        let address = "192.0.2.1:443".parse().unwrap();

        let result = connect_with(
            address,
            Duration::from_millis(1),
            pending::<io::Result<()>>(),
        )
        .await;

        assert_eq!(result.status, Status::Fail);
        assert_eq!(result.error_kind.as_deref(), Some("timeout"));
        assert!(result.error.unwrap().contains("timed out"));
    }
}
