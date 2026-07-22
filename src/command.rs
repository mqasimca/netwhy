use std::{
    ffi::OsStr,
    io,
    process::{ExitStatus, Stdio},
    time::Duration,
};

use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    time::timeout,
};

#[derive(Debug)]
pub(crate) struct CapturedStream {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

#[derive(Debug)]
pub(crate) struct BoundedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: CapturedStream,
    pub(crate) stderr: CapturedStream,
}

#[derive(Debug)]
pub(crate) enum BoundedCommandError {
    Io(io::Error),
    Timeout,
}

pub(crate) async fn run_bounded<I, S>(
    program: &OsStr,
    args: I,
    operation_timeout: Duration,
    output_limit: usize,
) -> Result<BoundedOutput, BoundedCommandError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);

    let mut child = command.spawn().map_err(BoundedCommandError::Io)?;
    let Some(process_id) = child.id() else {
        let _ = child.start_kill();
        reap_child(child);
        return Err(BoundedCommandError::Io(io::Error::other(
            "helper process PID was unavailable",
        )));
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(child, process_id);
        return Err(BoundedCommandError::Io(io::Error::other(
            "helper stdout was not captured",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(child, process_id);
        return Err(BoundedCommandError::Io(io::Error::other(
            "helper stderr was not captured",
        )));
    };

    let capture = timeout(operation_timeout, async {
        let (status, stdout, stderr) = tokio::try_join!(
            wait_for_exit(&mut child, process_id),
            read_bounded(stdout, output_limit),
            read_bounded(stderr, output_limit),
        )?;
        Ok::<_, io::Error>((status, stdout, stderr))
    })
    .await;

    let (status, stdout, stderr) = match capture {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            terminate_process_group(child, process_id);
            return Err(BoundedCommandError::Io(error));
        }
        Err(_) => {
            terminate_process_group(child, process_id);
            return Err(BoundedCommandError::Timeout);
        }
    };

    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

async fn wait_for_exit(child: &mut Child, process_id: u32) -> io::Result<ExitStatus> {
    let status = child.wait().await?;
    signal_process_group(process_id);
    Ok(status)
}

fn signal_process_group(process_id: u32) {
    if let Ok(process_id) = i32::try_from(process_id) {
        let _ = killpg(Pid::from_raw(process_id), Signal::SIGKILL);
    }
}

fn terminate_process_group(mut child: Child, process_id: u32) {
    signal_process_group(process_id);
    let _ = child.start_kill();
    reap_child(child);
}

fn reap_child(mut child: Child) {
    std::mem::drop(tokio::spawn(async move {
        let _ = child.wait().await;
    }));
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    output_limit: usize,
) -> io::Result<CapturedStream> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 4 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let remaining = output_limit.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < count;
    }
    Ok(CapturedStream { bytes, truncated })
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, time::Duration};

    use super::{BoundedCommandError, run_bounded};

    #[tokio::test]
    async fn captures_and_limits_helper_output() {
        let output = run_bounded(
            OsStr::new("sh"),
            ["-c", "printf 12345; printf error >&2"],
            Duration::from_secs(1),
            4,
        )
        .await
        .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout.bytes, b"1234");
        assert!(output.stdout.truncated);
        assert_eq!(output.stderr.bytes, b"erro");
        assert!(output.stderr.truncated);
    }

    #[tokio::test]
    async fn times_out_a_helper_process_group() {
        let error = run_bounded(
            OsStr::new("sh"),
            ["-c", "sleep 2"],
            Duration::from_millis(10),
            64,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, BoundedCommandError::Timeout));
    }
}
