use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child, Command};

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Strict read-write workspace root
    pub workspace: PathBuf,
    /// Fail closed if the host kernel doesn't support sandboxing (e.g. Linux < 5.13)
    pub strict: bool,
    /// Optional extra read-only runtime directories
    #[allow(dead_code)]
    pub extra_ro_paths: Vec<PathBuf>,
    /// Windows Job Object: max memory per child process (MB)
    pub max_memory_mb: usize,
    /// Windows Job Object: max concurrent processes in child tree (anti fork-bomb)
    pub max_processes: u32,
}

impl SandboxConfig {
    pub fn new(workspace: PathBuf) -> Self {
        Self {
            workspace,
            strict: false,
            extra_ro_paths: Vec::new(),
            max_memory_mb: 1024,
            max_processes: 32,
        }
    }
}

/// RAII guard kept alive for the lifetime of the child MCP server.
/// - On Windows: holds the Job Object handle (KILL_ON_JOB_CLOSE kills the entire tree on drop).
/// - On Unix: cleans up the isolated per-session temporary directory on drop.
pub struct SandboxGuard {
    #[allow(dead_code)]
    temp_dir: Option<PathBuf>,
    #[cfg(windows)]
    job_handle: isize,
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.job_handle != 0 {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(
                        self.job_handle as windows_sys::Win32::Foundation::HANDLE,
                    );
                }
            }
        }
        if let Some(dir) = &self.temp_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Spawns an MCP server process inside the strongest OS-native sandbox available.
pub fn spawn_sandboxed(
    cmd: &str,
    args: &[String],
    cfg: &SandboxConfig,
) -> Result<(Child, SandboxGuard)> {
    let workspace = std::fs::canonicalize(&cfg.workspace)
        .unwrap_or_else(|_| cfg.workspace.clone());

    #[cfg(target_os = "linux")]
    {
        return linux::spawn_landlock(cmd, args, &workspace, cfg);
    }

    #[cfg(target_os = "macos")]
    {
        return macos::spawn_seatbelt(cmd, args, &workspace, cfg);
    }

    #[cfg(windows)]
    {
        return windows::spawn_job_sandbox(cmd, args, &workspace, cfg);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        if cfg.strict {
            anyhow::bail!("OS kernel sandboxing is not supported on this platform");
        }
        let child = Command::new(cmd)
            .args(args)
            .current_dir(&workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok((child, SandboxGuard { temp_dir: None }))
    }
}

/// Resolves an executable in PATH so runtimes in ~/.nvm or ~/.local can still be executed
/// without exposing the rest of $HOME.
#[cfg(unix)]
fn resolve_executable_runtime_dir(cmd: &str) -> Option<PathBuf> {
    let candidate = Path::new(cmd);
    let resolved = if candidate.components().count() > 1 {
        std::fs::canonicalize(candidate).ok()
    } else {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(cmd))
                .find(|full| full.is_file())
                .and_then(|full| std::fs::canonicalize(full).ok())
        })
    }?;

    // Allow parent prefix (e.g., ~/.nvm/versions/node/v22.x) rather than just /bin
    let bin_dir = resolved.parent()?;
    if bin_dir.file_name().and_then(|n| n.to_str()) == Some("bin") {
        if let Some(prefix) = bin_dir.parent() {
            // Safety guard: never accidentally allow all of $HOME or /
            if prefix != Path::new("/") && Some(prefix.to_path_buf()) != crate::policy::home_dir() {
                return Some(prefix.to_path_buf());
            }
        }
    }
    Some(bin_dir.to_path_buf())
}

#[cfg(unix)]
fn create_sandbox_tmp(workspace: &Path) -> Option<PathBuf> {
    let base = std::env::temp_dir().join(format!(
        "agent-shield-sandbox-{}",
        std::process::id()
    ));
    let _ = workspace;
    std::fs::create_dir_all(&base).ok()?;
    Some(base)
}

// ============================================================================
// LINUX: Landlock LSM Kernel Filesystem Jail
// ============================================================================
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    const SYSTEM_RO_PATHS: &[&str] = &[
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/localtime",
        "/proc/self",
        "/dev/urandom",
        "/dev/random",
    ];

    const SYSTEM_RW_FILES: &[&str] = &["/dev/null", "/dev/zero", "/dev/full"];

    pub fn spawn_landlock(
        cmd: &str,
        args: &[String],
        workspace: &Path,
        cfg: &SandboxConfig,
    ) -> Result<(Child, SandboxGuard)> {
        let sandbox_tmp = create_sandbox_tmp(workspace);

        // Pre-compute allowlists BEFORE fork() so pre_exec stays minimal and predictable
        let mut ro_paths: Vec<PathBuf> = SYSTEM_RO_PATHS
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect();

        if let Some(rt_dir) = resolve_executable_runtime_dir(cmd) {
            ro_paths.push(rt_dir);
        }
        for extra in &cfg.extra_ro_paths {
            if extra.exists() {
                ro_paths.push(extra.clone());
            }
        }

        let mut rw_paths: Vec<PathBuf> = vec![workspace.to_path_buf()];
        if let Some(ref tmp) = sandbox_tmp {
            rw_paths.push(tmp.clone());
        }
        for dev in SYSTEM_RW_FILES {
            let p = PathBuf::from(dev);
            if p.exists() {
                rw_paths.push(p);
            }
        }

        let strict = cfg.strict;
        let mut command = Command::new(cmd);
        command
            .args(args)
            .current_dir(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if let Some(ref tmp) = sandbox_tmp {
            command.env("TMPDIR", tmp);
        }

        // Enforce Landlock LSM in the forked child process right before execve()
        unsafe {
            command.pre_exec(move || apply_landlock_rules(&ro_paths, &rw_paths, strict));
        }

        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn Landlock-sandboxed server '{}'", cmd))?;

        eprintln!(
            "[agent-shield] Linux Landlock LSM active — workspace jail: {}",
            workspace.display()
        );

        Ok((child, SandboxGuard { temp_dir: sandbox_tmp }))
    }

    fn apply_landlock_rules(
        ro_paths: &[PathBuf],
        rw_paths: &[PathBuf],
        strict: bool,
    ) -> std::io::Result<()> {
        let abi = ABI::V5;
        let compat = if strict {
            CompatLevel::HardRequirement
        } else {
            CompatLevel::BestEffort
        };

        let all_fs = AccessFs::from_all(abi);
        let read_fs = AccessFs::from_read(abi);
        let file_mask = AccessFs::from_file(abi);

        let mut ruleset = Ruleset::default()
            .set_compatibility(compat)
            .handle_access(all_fs)
            .map_err(to_io_err)?
            .create()
            .map_err(to_io_err)?;

        for path in ro_paths {
            let Ok(fd) = PathFd::new(path) else { continue };
            let access = if path.is_dir() {
                read_fs
            } else {
                read_fs & file_mask
            };
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(to_io_err)?;
        }

        for path in rw_paths {
            let Ok(fd) = PathFd::new(path) else { continue };
            let access = if path.is_dir() {
                all_fs
            } else {
                all_fs & file_mask
            };
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access))
                .map_err(to_io_err)?;
        }

        let status = ruleset.restrict_self().map_err(to_io_err)?;
        if strict && matches!(status.ruleset, RulesetStatus::NotEnforced) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Landlock LSM is not enabled on this Linux kernel",
            ));
        }

        Ok(())
    }

    fn to_io_err<E: std::fmt::Display>(err: E) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
    }
}

// ============================================================================
// MACOS: Seatbelt (sandbox-exec) Kernel Filesystem Jail
// ============================================================================
#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    pub fn spawn_seatbelt(
        cmd: &str,
        args: &[String],
        workspace: &Path,
        cfg: &SandboxConfig,
    ) -> Result<(Child, SandboxGuard)> {
        let sandbox_tmp = create_sandbox_tmp(workspace);
        let mut ro_extras = Vec::new();
        if let Some(rt_dir) = resolve_executable_runtime_dir(cmd) {
            ro_extras.push(rt_dir);
        }
        ro_extras.extend(cfg.extra_ro_paths.iter().cloned());

        let profile = build_seatbelt_profile(workspace, sandbox_tmp.as_deref(), &ro_extras);

        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .arg("-p")
            .arg(&profile)
            .arg(cmd)
            .args(args)
            .current_dir(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        if let Some(ref tmp) = sandbox_tmp {
            command.env("TMPDIR", tmp);
        }

        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn Seatbelt-sandboxed server '{}'", cmd))?;

        eprintln!(
            "[agent-shield] macOS Seatbelt sandbox active — workspace jail: {}",
            workspace.display()
        );

        Ok((child, SandboxGuard { temp_dir: sandbox_tmp }))
    }

    fn escape_sbpl(p: &Path) -> String {
        p.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }

    fn build_seatbelt_profile(
        workspace: &Path,
        tmp: Option<&Path>,
        ro_extras: &[PathBuf],
    ) -> String {
        let mut rules = String::from(
            "(version 1)\n\
             (deny default)\n\
             (allow process*)\n\
             (allow sysctl-read)\n\
             (allow mach-lookup)\n\
             (allow network*)\n\
             (allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") \
               (subpath \"/System\") (subpath \"/Library\") (subpath \"/opt/homebrew\") \
               (subpath \"/private/etc\") (subpath \"/dev\"))\n\
             (allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\"))\n",
        );

        rules.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            escape_sbpl(workspace)
        ));

        if let Some(t) = tmp {
            rules.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                escape_sbpl(t)
            ));
        }

        for extra in ro_extras {
            rules.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                escape_sbpl(extra)
            ));
        }

        rules
    }
}

// ============================================================================
// WINDOWS: Restricted Job Object + UI/Clipboard Containment
// ============================================================================
#[cfg(windows)]
mod windows {
    use super::*;
    use std::mem::{size_of, zeroed};
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS,
        JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };

    pub fn spawn_job_sandbox(
        cmd: &str,
        args: &[String],
        workspace: &Path,
        cfg: &SandboxConfig,
    ) -> Result<(Child, SandboxGuard)> {
        // 1. Create anonymous Windows Job Object with strict resource & breakout limits
        let job: HANDLE = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            anyhow::bail!("CreateJobObjectW failed: {}", std::io::Error::last_os_error());
        }

        if let Err(e) = configure_job_limits(job, cfg) {
            unsafe { CloseHandle(job) };
            return Err(e);
        }

        // 2. Spawn child MCP server inside workspace directory
        let mut child = Command::new(cmd)
            .args(args)
            .current_dir(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn MCP server '{}'", cmd))?;

        // 3. Bind child process (and all future descendants) to the Job Object
        let Some(pid) = child.id() else {
            unsafe { CloseHandle(job) };
            anyhow::bail!("child exited before Job Object assignment");
        };

        let proc_handle = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if proc_handle.is_null() {
            let _ = child.start_kill();
            unsafe { CloseHandle(job) };
            anyhow::bail!("OpenProcess(pid={}) failed: {}", pid, std::io::Error::last_os_error());
        }

        let assigned = unsafe { AssignProcessToJobObject(job, proc_handle) };
        unsafe { CloseHandle(proc_handle) };

        if assigned == 0 {
            let _ = child.start_kill();
            unsafe { CloseHandle(job) };
            anyhow::bail!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            );
        }

        eprintln!(
            "[agent-shield] Windows Job Object active (max_mem={}MB, max_procs={}, clipboard/UI isolated, kill-on-close). Note: NTFS paths enforced by PolicyEngine (use WSL2 for kernel Landlock jail).",
            cfg.max_memory_mb, cfg.max_processes
        );

        Ok((
            child,
            SandboxGuard {
                temp_dir: None,
                job_handle: job as isize,
            },
        ))
    }

    fn configure_job_limits(job: HANDLE, cfg: &SandboxConfig) -> Result<()> {
        unsafe {
            // A. Kill entire process tree on exit + memory cap + fork-bomb cap
            let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            ext.BasicLimitInformation.ActiveProcessLimit = cfg.max_processes;
            ext.ProcessMemoryLimit = cfg.max_memory_mb.saturating_mul(1024 * 1024);

            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &ext as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                anyhow::bail!(
                    "SetInformationJobObject(ExtendedLimit) failed: {}",
                    std::io::Error::last_os_error()
                );
            }

            // B. Block clipboard snooping, desktop switching, and window handle attacks
            let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: JOB_OBJECT_UILIMIT_READCLIPBOARD
                    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                    | JOB_OBJECT_UILIMIT_DESKTOP
                    | JOB_OBJECT_UILIMIT_EXITWINDOWS
                    | JOB_OBJECT_UILIMIT_GLOBALATOMS
                    | JOB_OBJECT_UILIMIT_HANDLES
                    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            };

            let ok_ui = SetInformationJobObject(
                job,
                JobObjectBasicUIRestrictions,
                &ui as *const _ as *const _,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            );
            if ok_ui == 0 {
                anyhow::bail!(
                    "SetInformationJobObject(UIRestrictions) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(())
    }
}
