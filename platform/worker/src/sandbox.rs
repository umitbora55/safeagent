#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use std::io;

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

#[cfg(target_os = "linux")]
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;

#[cfg(target_os = "linux")]
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[cfg(target_os = "linux")]
const _LINUX_CAPABILITY_U32S_3: usize = 2;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
fn to_io_error(message: &str) -> String {
    let err = io::Error::last_os_error();
    format!("{message}: {err}")
}

#[cfg(target_os = "linux")]
fn write_all(fd: RawFd, data: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let rc = {
            // SAFETY: data pointer is valid for the remaining range and fd is owned by caller.
            unsafe {
                libc::write(
                    fd,
                    data[written..].as_ptr() as *const _,
                    data.len() - written,
                )
            }
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            break;
        }
        written += rc as usize;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_all(fd: RawFd) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 512];
    loop {
        let rc = {
            // SAFETY: buffer is valid and writable for `buf.len()` bytes.
            unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) }
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            break;
        }
        let n = rc as usize;
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn prctl(
    option: libc::c_int,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
) -> Result<libc::c_long, String> {
    let rc = {
        // SAFETY: raw syscall arguments are forwarded directly to kernel as documented in libc.
        unsafe { libc::syscall(libc::SYS_prctl, option, arg2, arg3, arg4, arg5) }
    };
    if rc < 0 {
        return Err(to_io_error("prctl failed"));
    }
    Ok(rc)
}

#[cfg(target_os = "linux")]
fn run_isolated_child<T>(apply_sandbox: bool, task: T) -> Result<String, String>
where
    T: FnOnce() -> Result<String, String> + Send + 'static,
{
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(format!("pipe failed: {}", io::Error::last_os_error()));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            let _ = libc::close(fds[0]);
            let _ = libc::close(fds[1]);
        }
        return Err(format!("fork failed: {}", io::Error::last_os_error()));
    }

    if pid == 0 {
        // Child.
        let _ = unsafe { libc::close(fds[0]) };
        let status = if let Err(err) = if apply_sandbox {
            sandbox_setup()
        } else {
            Ok(())
        } {
            let _ = write_all(fds[1], format!("sandbox setup failed: {err}").as_bytes());
            1
        } else {
            match task() {
                Ok(output) => {
                    if !output.is_empty() {
                        let _ = write_all(fds[1], output.as_bytes());
                    }
                    0
                }
                Err(err) => {
                    let _ = write_all(fds[1], err.as_bytes());
                    1
                }
            }
        };

        let _ = unsafe { libc::close(fds[1]) };
        unsafe {
            let _ = libc::syscall(libc::SYS_exit, status);
        }
    }

    // Parent.
    let _ = unsafe { libc::close(fds[1]) };
    let buffer = read_all(fds[0]).map_err(|err| format!("read pipe failed: {err}"))?;
    let _ = unsafe { libc::close(fds[0]) };

    let mut status = 0i32;
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        return Err(format!("waitpid failed: {}", io::Error::last_os_error()));
    }

    if (status & 0x7f) != 0 {
        return Err(format!(
            "sandbox child terminated by signal; status={status}"
        ));
    }

    let exit_code = (status >> 8) & 0xff;
    if exit_code != 0 {
        return Err(String::from_utf8_lossy(&buffer).trim().to_string());
    }

    String::from_utf8(buffer).map_err(|err| format!("child output decode failed: {err}"))
}

#[cfg(target_os = "linux")]
fn sandbox_setup() -> Result<(), String> {
    apply_user_namespace()?;
    apply_no_new_privs()?;
    drop_capabilities()?;
    apply_rlimits()?;
    apply_seccomp()?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_no_new_privs() -> Result<(), String> {
    let _ = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn is_no_new_privs_set() -> Result<bool, String> {
    let rc = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)?;
    Ok(rc == 1)
}

#[cfg(target_os = "linux")]
pub fn drop_capabilities() -> Result<(), String> {
    let mut header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; _LINUX_CAPABILITY_U32S_3];

    let rc = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) };
    if rc < 0 {
        return Err(to_io_error("capset failed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_rlimits() -> Result<(), String> {
    let cpu_limit = libc::rlimit {
        rlim_cur: 2,
        rlim_max: 2,
    };
    let as_limit = libc::rlimit {
        rlim_cur: 256 * 1024 * 1024,
        rlim_max: 256 * 1024 * 1024,
    };
    let fsize_limit = libc::rlimit {
        rlim_cur: 10 * 1024 * 1024,
        rlim_max: 10 * 1024 * 1024,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) } < 0 {
        return Err(format!(
            "setrlimit(RLIMIT_CPU) failed: {}",
            io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &as_limit) } < 0 {
        return Err(format!(
            "setrlimit(RLIMIT_AS) failed: {}",
            io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &fsize_limit) } < 0 {
        return Err(format!(
            "setrlimit(RLIMIT_FSIZE) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_user_namespace() -> Result<(), String> {
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
        return Err(format!(
            "unshare(CLONE_NEWUSER) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply_seccomp() -> Result<(), String> {
    let allowed_syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_exit,
        libc::SYS_fstat,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_close,
        libc::SYS_clock_gettime,
    ];

    let mut filter = Vec::with_capacity(allowed_syscalls.len() * 2 + 1);
    filter.push(libc::sock_filter {
        code: (libc::BPF_LD + libc::BPF_W + libc::BPF_ABS) as libc::c_ushort,
        jt: 0,
        jf: 0,
        k: 0,
    });

    for syscall in allowed_syscalls {
        filter.push(libc::sock_filter {
            code: (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as libc::c_ushort,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: (libc::BPF_RET + libc::BPF_K) as libc::c_ushort,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        });
    }

    filter.push(libc::sock_filter {
        code: (libc::BPF_RET + libc::BPF_K) as libc::c_ushort,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
    });

    let mut prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u64,
            &mut prog as *mut libc::sock_fprog,
        )
    };
    if rc < 0 {
        return Err(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run_sandboxed_skill(
    skill_id: &str,
    input: &str,
    request_id: &str,
) -> Result<String, String> {
    let output = match skill_id {
        "echo" => input.to_string(),
        "health" => "ok".to_string(),
        "admin_op" => format!("admin-op:{}:approved", request_id),
        _ => return Err("unknown skill".to_string()),
    };
    run_isolated_child(true, move || Ok(output))
}

#[cfg(not(target_os = "linux"))]
pub fn run_sandboxed_skill(
    skill_id: &str,
    input: &str,
    request_id: &str,
) -> Result<String, String> {
    let output = match skill_id {
        "echo" => input.to_string(),
        "health" => "ok".to_string(),
        "admin_op" => format!("admin-op:{}:approved", request_id),
        _ => return Err("unknown skill".to_string()),
    };
    Ok(output)
}

#[cfg(target_os = "linux")]
pub fn run_probe_task<T>(task: T) -> Result<String, String>
where
    T: FnOnce() -> Result<String, String> + Send + 'static,
{
    run_isolated_child(true, task)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn run_probe_task<T>(_task: T) -> Result<String, String>
where
    T: FnOnce() -> Result<String, String> + Send + 'static,
{
    Err("sandbox probes are Linux-only".to_string())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn apply_no_new_privs() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn is_no_new_privs_set() -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn drop_capabilities() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn apply_rlimits() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn apply_user_namespace() -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn apply_seccomp() -> Result<(), String> {
    Ok(())
}
