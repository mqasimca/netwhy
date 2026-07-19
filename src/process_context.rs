use std::{
    fs::File,
    io::{self, Read as _},
    os::unix::fs::MetadataExt,
};

use anyhow::{Context as _, Result};
use netwhy::{
    CapabilityStatus, ContextRelation, DiagnosticContext, ExecutionContextInfo,
    ExecutionContextSource, ProxyEnvironmentStatus,
};
use nix::{
    fcntl::{OFlag, openat},
    sched::{CloneFlags, setns},
    sys::stat::Mode,
    unistd::{chdir, chroot, fchdir},
};

const CAP_SYS_ADMIN: &str = "CAP_SYS_ADMIN";
const CAP_SYS_CHROOT: &str = "CAP_SYS_CHROOT";
const MAX_PROCESS_ENVIRONMENT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct PreparedProcessContext {
    target_network_namespace: File,
    target_mount_namespace: File,
    target_root: File,
    network_changed: bool,
    mount_changed: bool,
    root_changed: bool,
    diagnostic_context: DiagnosticContext,
}

impl PreparedProcessContext {
    pub fn prepare(pid: u32) -> Result<Self> {
        Self::prepare_with_environment(pid, read_process_environment)
    }

    pub fn prepare_container(
        pid: u32,
        source: ExecutionContextSource,
        container: String,
    ) -> Result<Self> {
        anyhow::ensure!(
            matches!(
                source,
                ExecutionContextSource::Docker | ExecutionContextSource::Podman
            ),
            "container context source must be Docker or Podman"
        );
        Self::prepare_selected(pid, source, Some(container), read_process_environment)
    }

    fn prepare_with_environment(
        pid: u32,
        read_environment: impl FnOnce(&File) -> io::Result<Vec<u8>>,
    ) -> Result<Self> {
        Self::prepare_selected(pid, ExecutionContextSource::Process, None, read_environment)
    }

    fn prepare_selected(
        pid: u32,
        source: ExecutionContextSource,
        target_container: Option<String>,
        read_environment: impl FnOnce(&File) -> io::Result<Vec<u8>>,
    ) -> Result<Self> {
        let current_process = open_process_directory(0)?;
        let target_process = open_process_directory(pid)?;
        let current_network_namespace = open_context_file(0, &current_process, "ns/net")?;
        let target_network_namespace = open_context_file(pid, &target_process, "ns/net")?;
        let current_mount_namespace = open_context_file(0, &current_process, "ns/mnt")?;
        let target_mount_namespace = open_context_file(pid, &target_process, "ns/mnt")?;
        let current_root = open_context_file(0, &current_process, "root")?;
        let target_root = open_context_file(pid, &target_process, "root")?;

        let network_changed = !same_object(
            &current_network_namespace,
            &target_network_namespace,
            "network namespace",
        )?;
        let mount_changed = !same_object(
            &current_mount_namespace,
            &target_mount_namespace,
            "mount namespace",
        )?;
        // A root inode is only meaningful in its mount namespace. Re-root after entering a
        // different mount namespace even when the pre-entry metadata happens to match.
        let root_changed =
            mount_changed || !same_object(&current_root, &target_root, "filesystem root")?;

        let environment_path = format!("/proc/{pid}/environ");
        let environment = read_environment(&target_process);
        let (proxy_environment, proxy_error) = match &environment {
            Ok(_) => (ProxyEnvironmentStatus::SelectedProcess, None),
            Err(error) => (
                ProxyEnvironmentStatus::Unavailable,
                Some(format!("could not read {environment_path}: {error}")),
            ),
        };

        let mut execution = execution_context(
            pid,
            network_changed,
            mount_changed,
            root_changed,
            proxy_environment,
            proxy_error,
        );
        execution.source = source;
        execution.target_container = target_container;
        let diagnostic_context = match environment {
            Ok(environment) => DiagnosticContext::selected_process_environ(execution, &environment),
            Err(_) => DiagnosticContext::selected_process(execution, &[]),
        };

        Ok(Self {
            target_network_namespace,
            target_mount_namespace,
            target_root,
            network_changed,
            mount_changed,
            root_changed,
            diagnostic_context,
        })
    }

    pub fn enter(self) -> Result<DiagnosticContext> {
        self.enter_with(&LinuxNamespaceOperations)
    }

    fn enter_with(self, operations: &impl NamespaceOperations) -> Result<DiagnosticContext> {
        if self.mount_changed {
            operations
                .enter_mount_namespace(&self.target_mount_namespace)
                .context(
                    "could not enter the selected mount namespace; CAP_SYS_ADMIN is required",
                )?;
        }
        if self.root_changed {
            operations.change_root(&self.target_root).context(
                "could not enter the selected filesystem root; CAP_SYS_CHROOT is required",
            )?;
        }
        if self.network_changed {
            operations
                .enter_network_namespace(&self.target_network_namespace)
                .context(
                    "could not enter the selected network namespace; CAP_SYS_ADMIN is required",
                )?;
        }

        Ok(self.diagnostic_context)
    }
}

fn open_process_directory(pid: u32) -> Result<File> {
    let path = process_path(pid, "");
    File::open(&path).with_context(|| {
        if pid == 0 {
            "could not open the current process context at /proc/self".to_owned()
        } else {
            format!("could not open process {pid} context at {path}")
        }
    })
}

fn open_context_file(pid: u32, process: &File, relative_path: &str) -> Result<File> {
    openat(
        process,
        relative_path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .with_context(|| {
        let path = process_path(pid, relative_path);
        if pid == 0 {
            format!("could not open current execution context at {path}")
        } else {
            format!("could not open execution context for process {pid} at {path}")
        }
    })
}

fn read_process_environment(process: &File) -> io::Result<Vec<u8>> {
    let environment = openat(
        process,
        "environ",
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    read_bounded_environment(File::from(environment), MAX_PROCESS_ENVIRONMENT_BYTES)
}

fn read_bounded_environment(
    mut environment: impl io::Read,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut contents = Vec::new();
    environment
        .by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut contents)?;
    if contents.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process environment exceeded the 8 MiB safety limit",
        ));
    }
    Ok(contents)
}

fn process_path(pid: u32, relative_path: &str) -> String {
    let base = if pid == 0 {
        "/proc/self".to_owned()
    } else {
        format!("/proc/{pid}")
    };
    if relative_path.is_empty() {
        base
    } else {
        format!("{base}/{relative_path}")
    }
}

fn same_object(left: &File, right: &File, description: &str) -> Result<bool> {
    let left = left
        .metadata()
        .with_context(|| format!("could not inspect the current {description}"))?;
    let right = right
        .metadata()
        .with_context(|| format!("could not inspect the selected {description}"))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

const fn relation(changed: bool) -> ContextRelation {
    if changed {
        ContextRelation::Entered
    } else {
        ContextRelation::Shared
    }
}

fn execution_context(
    pid: u32,
    network_changed: bool,
    mount_changed: bool,
    root_changed: bool,
    proxy_environment: ProxyEnvironmentStatus,
    proxy_error: Option<String>,
) -> ExecutionContextInfo {
    let mut required_capabilities = Vec::new();
    if network_changed || mount_changed {
        required_capabilities.push(CAP_SYS_ADMIN.to_owned());
    }
    if root_changed {
        required_capabilities.push(CAP_SYS_CHROOT.to_owned());
    }
    let capability_status = if required_capabilities.is_empty() {
        CapabilityStatus::NotRequired
    } else {
        CapabilityStatus::Available
    };

    ExecutionContextInfo {
        source: ExecutionContextSource::Process,
        target_pid: Some(pid),
        target_container: None,
        network_namespace: relation(network_changed),
        mount_namespace: relation(mount_changed),
        filesystem_root: relation(root_changed),
        proxy_environment,
        proxy_error,
        required_capabilities,
        capability_status,
    }
}

trait NamespaceOperations {
    fn enter_mount_namespace(&self, namespace: &File) -> Result<()>;
    fn change_root(&self, root: &File) -> Result<()>;
    fn enter_network_namespace(&self, namespace: &File) -> Result<()>;
}

struct LinuxNamespaceOperations;

impl NamespaceOperations for LinuxNamespaceOperations {
    fn enter_mount_namespace(&self, namespace: &File) -> Result<()> {
        setns(namespace, CloneFlags::CLONE_NEWNS).map_err(Into::into)
    }

    fn change_root(&self, root: &File) -> Result<()> {
        fchdir(root)?;
        chroot(".")?;
        chdir("/")?;
        Ok(())
    }

    fn enter_network_namespace(&self, namespace: &File) -> Result<()> {
        setns(namespace, CloneFlags::CLONE_NEWNET).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs::File, io::Cursor};

    use anyhow::{Result, bail};
    use netwhy::{
        CapabilityStatus, ContextRelation, ExecutionContextSource, ProxyEnvironmentStatus,
    };

    use super::{
        NamespaceOperations, PreparedProcessContext, execution_context, open_context_file,
        process_path, read_bounded_environment,
    };

    #[derive(Default)]
    struct RecordingOperations {
        calls: RefCell<Vec<&'static str>>,
        fail_on: Option<&'static str>,
    }

    impl NamespaceOperations for RecordingOperations {
        fn enter_mount_namespace(&self, _namespace: &File) -> Result<()> {
            self.record("mount")
        }

        fn change_root(&self, _root: &File) -> Result<()> {
            self.record("root")
        }

        fn enter_network_namespace(&self, _namespace: &File) -> Result<()> {
            self.record("network")
        }
    }

    impl RecordingOperations {
        fn record(&self, operation: &'static str) -> Result<()> {
            self.calls.borrow_mut().push(operation);
            if self.fail_on == Some(operation) {
                bail!("injected {operation} failure");
            }
            Ok(())
        }
    }

    #[test]
    fn process_environment_reads_are_bounded() {
        assert_eq!(
            read_bounded_environment(Cursor::new(b"HTTP_PROXY=value"), 16).unwrap(),
            b"HTTP_PROXY=value"
        );

        let error = read_bounded_environment(Cursor::new(b"12345"), 4).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("8 MiB safety limit"));
    }

    #[test]
    fn current_process_context_requires_no_privileged_operations() {
        let prepared = PreparedProcessContext::prepare(std::process::id()).unwrap();
        let operations = RecordingOperations::default();

        let context = prepared.enter_with(&operations).unwrap();

        assert!(operations.calls.borrow().is_empty());
        assert_eq!(context.execution().source, ExecutionContextSource::Process);
        assert_eq!(context.execution().target_pid, Some(std::process::id()));
        assert_eq!(
            context.execution().network_namespace,
            ContextRelation::Shared
        );
        assert_eq!(context.execution().mount_namespace, ContextRelation::Shared);
        assert_eq!(context.execution().filesystem_root, ContextRelation::Shared);
        assert_eq!(
            context.execution().proxy_environment,
            ProxyEnvironmentStatus::SelectedProcess
        );
        assert_eq!(
            context.execution().capability_status,
            CapabilityStatus::NotRequired
        );
        assert!(context.execution().required_capabilities.is_empty());
    }

    #[test]
    fn container_context_retains_runtime_identifier_and_resolved_pid() {
        for (source, container) in [
            (ExecutionContextSource::Docker, "web"),
            (ExecutionContextSource::Podman, "api"),
        ] {
            let prepared = PreparedProcessContext::prepare_container(
                std::process::id(),
                source,
                container.to_owned(),
            )
            .unwrap();

            let context = prepared
                .enter_with(&RecordingOperations::default())
                .unwrap();

            assert_eq!(context.execution().source, source);
            assert_eq!(context.execution().target_pid, Some(std::process::id()));
            assert_eq!(
                context.execution().target_container.as_deref(),
                Some(container)
            );
        }
    }

    #[test]
    fn container_context_rejects_a_non_container_source() {
        let error = PreparedProcessContext::prepare_container(
            std::process::id(),
            ExecutionContextSource::Process,
            "web".to_owned(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("must be Docker or Podman"));
    }

    #[test]
    fn unavailable_process_environment_is_recorded_without_blocking_probes() {
        let prepared = PreparedProcessContext::prepare_with_environment(std::process::id(), |_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .unwrap();

        let context = prepared
            .enter_with(&RecordingOperations::default())
            .unwrap();

        assert_eq!(
            context.execution().proxy_environment,
            ProxyEnvironmentStatus::Unavailable
        );
        assert!(
            context.execution().proxy_error.as_deref().is_some_and(
                |error| error.contains(&format!("/proc/{}/environ", std::process::id()))
            )
        );
    }

    #[test]
    fn changed_context_reports_each_required_capability_once() {
        let context = execution_context(
            42,
            true,
            true,
            true,
            ProxyEnvironmentStatus::SelectedProcess,
            None,
        );

        assert_eq!(context.network_namespace, ContextRelation::Entered);
        assert_eq!(context.mount_namespace, ContextRelation::Entered);
        assert_eq!(context.filesystem_root, ContextRelation::Entered);
        assert_eq!(
            context.required_capabilities,
            ["CAP_SYS_ADMIN", "CAP_SYS_CHROOT"]
        );
        assert_eq!(context.capability_status, CapabilityStatus::Available);
    }

    #[test]
    fn missing_process_fails_during_context_preparation() {
        let error = PreparedProcessContext::prepare(u32::MAX).unwrap_err();

        assert!(error.to_string().contains("process 4294967295"));
    }

    #[test]
    fn privileged_operations_run_in_mount_root_network_order() {
        let mut prepared = PreparedProcessContext::prepare(std::process::id()).unwrap();
        prepared.mount_changed = true;
        prepared.root_changed = true;
        prepared.network_changed = true;
        let operations = RecordingOperations::default();

        prepared.enter_with(&operations).unwrap();

        assert_eq!(*operations.calls.borrow(), ["mount", "root", "network"]);
    }

    #[test]
    fn a_failed_operation_stops_before_later_context_changes() {
        let mut prepared = PreparedProcessContext::prepare(std::process::id()).unwrap();
        prepared.mount_changed = true;
        prepared.root_changed = true;
        prepared.network_changed = true;
        let operations = RecordingOperations {
            fail_on: Some("root"),
            ..RecordingOperations::default()
        };

        let error = prepared.enter_with(&operations).unwrap_err();

        assert_eq!(*operations.calls.borrow(), ["mount", "root"]);
        assert!(error.to_string().contains("CAP_SYS_CHROOT"));
    }

    #[test]
    fn mount_and_network_failures_name_the_required_capability() {
        for operation in ["mount", "network"] {
            let mut prepared = PreparedProcessContext::prepare(std::process::id()).unwrap();
            prepared.mount_changed = operation == "mount";
            prepared.network_changed = operation == "network";
            let operations = RecordingOperations {
                fail_on: Some(operation),
                ..RecordingOperations::default()
            };

            let error = prepared.enter_with(&operations).unwrap_err();

            assert_eq!(*operations.calls.borrow(), [operation]);
            assert!(error.to_string().contains("CAP_SYS_ADMIN"));
        }
    }

    #[test]
    fn process_paths_cover_current_and_selected_processes() {
        assert_eq!(process_path(0, ""), "/proc/self");
        assert_eq!(process_path(0, "ns/net"), "/proc/self/ns/net");
        assert_eq!(process_path(42, ""), "/proc/42");
        assert_eq!(process_path(42, "root"), "/proc/42/root");
    }

    #[test]
    fn context_file_errors_identify_the_selected_process() {
        let process = File::open("/proc/self").unwrap();

        let current = open_context_file(0, &process, "not-a-real-context-file").unwrap_err();
        let selected = open_context_file(42, &process, "not-a-real-context-file").unwrap_err();

        assert!(current.to_string().contains("current execution context"));
        assert!(
            current
                .to_string()
                .contains("/proc/self/not-a-real-context-file")
        );
        assert!(selected.to_string().contains("process 42"));
        assert!(
            selected
                .to_string()
                .contains("/proc/42/not-a-real-context-file")
        );
    }
}
