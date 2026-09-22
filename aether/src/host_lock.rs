//! One OS-level lock around mutating the host's network state.
//!
//! Two engines can be alive at once without anyone meaning it: the GUI's child and
//! a `aether.exe` started by hand, a scan child that also brings TUN up, or a
//! previous session that is still tearing down while a new one connects. Each
//! installs the same split-default prefixes and each writes its own journal, so the
//! second journal wins while the first process goes on believing the routes it is
//! holding are described by the file it wrote. The removal side is then deleting
//! against a state it no longer owns.
//!
//! The lock is deliberately not a lock file whose *contents* are a pid: that design
//! needs a staleness heuristic, and the previous one (`mtime > 5 s`) stole the lock
//! from live holders and treated an `elapsed()` error as "always stale". Here the
//! OS owns the liveness question — a named mutex reports `WAIT_ABANDONED_0` when its
//! holder died, and an advisory `flock` is released by the kernel on exit — so
//! nothing has to guess, and a crashed engine cannot wedge the host forever.
//!
//! Failing to take the lock is a **refusal to mutate**, never a mutation without it.
//!
//! Scope matters as much as the primitive, because the thing being guarded — the
//! host routing table — is machine-wide: the lock is the `Global\` namespace on
//! Windows (degrading to session scope, loudly, for a process that cannot create
//! a global object) and a uid-owned directory everywhere else. A per-session or
//! world-shared lock excludes the wrong set of processes.

use std::time::{Duration, Instant};

use crate::error::{AetherError, Result};

/// How long to wait for another session to finish before refusing. Long enough for
/// a teardown on a slow link, short enough that Connect does not look hung.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// Machine-wide, and tried first. `Local\` is scoped to one terminal session, so
/// an engine running as a service (session 0) or as another user took its *own*
/// mutex and installed the same split-default prefixes alongside the interactive
/// one — the exact doubled state this module exists to close, since routes are a
/// machine-wide resource.
#[cfg(windows)]
const GLOBAL_MUTEX_NAME: &str = "Global\\AetherNext.HostMutation.v1";

/// Fallback for a process without `SeCreateGlobalPrivilege`, which is what a
/// standard interactive account is: the `Global\` namespace cannot even be
/// created there, so the lock degrades to session scope and says so in the log
/// rather than quietly claiming machine scope.
#[cfg(windows)]
const LOCAL_MUTEX_NAME: &str = "Local\\AetherNext.HostMutation.v1";

/// Held for as long as the caller is mutating host state.
pub struct HostMutationGuard {
    imp: Imp,
}

/// The platform's lock primitive, as a type alias rather than an enum: there is
/// exactly one per target, and matching on a single-variant enum only hides that.
#[cfg(windows)]
type Imp = windows_sys::Win32::Foundation::HANDLE;
#[cfg(not(windows))]
type Imp = std::fs::File;

impl HostMutationGuard {
    /// Take the lock or explain why the mutation will not happen.
    pub fn acquire(timeout: Duration) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        loop {
            match Self::try_acquire() {
                TryAcquired::Held(guard) => return Ok(guard),
                TryAcquired::Busy => {
                    if Instant::now() >= deadline {
                        return Err(AetherError::Other(format!(
                            "another Aether session is mutating host network state; refusing to                              install routes concurrently (waited {timeout:?})"
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                TryAcquired::Failed(why) => return Err(AetherError::Other(why)),
            }
        }
    }

    #[cfg(windows)]
    fn try_acquire() -> TryAcquired {
        match acquire_mutex(GLOBAL_MUTEX_NAME) {
            // Not being able to *create* it is a privilege fact about this
            // process, not about another session. Degrade, and make the reduced
            // coverage visible: the residual window — a service-instance engine
            // racing an interactive one — is exactly what the log says.
            TryAcquired::Failed(why) => {
                log::warn!(
                    "[host-lock] {why}; using the session-local mutex instead, which does not \
                     exclude an engine running as a service or under another account"
                );
                acquire_mutex(LOCAL_MUTEX_NAME)
            }
            // A `Global\` mutex that exists but is held is the answer we want:
            // contention across sessions and accounts. Held is returned as-is.
            held_or_busy => held_or_busy,
        }
    }

    /// Create (or open) one named mutex and take it, without pretending that a
    /// creation failure is the same thing as a busy lock.
    #[cfg(windows)]
    fn acquire_mutex(name: &str) -> TryAcquired {
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let wide: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(once(0))
            .collect();
        // `bInitialOwner = FALSE` plus an explicit wait: claiming the mutex at create
        // time cannot report abandonment, and abandonment is the whole point.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
        if handle.is_null() {
            return TryAcquired::Failed(format!(
                "CreateMutexW({name}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let wait = unsafe { WaitForSingleObject(handle, WAIT_INTERVAL.as_millis() as u32) };
        match wait {
            // WAIT_ABANDONED_0: the previous holder exited without releasing. The
            // kernel says so, so taking over is a fact rather than an mtime guess.
            r if r == WAIT_OBJECT_0 || r == WAIT_ABANDONED_0 => {
                TryAcquired::Held(HostMutationGuard { imp: handle })
            }
            r if r == WAIT_TIMEOUT => {
                unsafe {
                    CloseHandle(handle);
                }
                TryAcquired::Busy
            }
            other => {
                let gle = unsafe { GetLastError() };
                unsafe {
                    CloseHandle(handle);
                }
                TryAcquired::Failed(format!(
                    "WaitForSingleObject({name}) returned {other}                      (gle {gle}) after {}",
                    if other == WAIT_FAILED { "WAIT_FAILED" } else { "an unexpected code" }
                ))
            }
        }
    }

    #[cfg(not(windows))]
    fn try_acquire() -> TryAcquired {
        use fs2::FileExt;
        use std::os::unix::fs::OpenOptionsExt;
        let path = match lock_file_path() {
            Ok(p) => p,
            Err(why) => return TryAcquired::Failed(why),
        };
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => return TryAcquired::Failed(format!("cannot open {}: {e}", path.display())),
        };
        match file.try_lock_exclusive() {
            Ok(()) => TryAcquired::Held(HostMutationGuard { imp: file }),
            // The two codes that mean "a live process is holding it":
            // `EWOULDBLOCK` (== `EAGAIN`) from `flock`, `EACCES` from a POSIX
            // record lock. Anything else — `EROFS`, `ENOSPC`, `EDQUOT`, a
            // directory in the way — is a broken lock, and folding it into
            // `Busy` both burns the whole acquire timeout against a session that
            // does not exist and tells the operator the wrong thing.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                TryAcquired::Busy
            }
            Err(e) => TryAcquired::Failed(format!("cannot lock {}: {e}", path.display())),
        }
    }
}

#[cfg(windows)]
impl Drop for HostMutationGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        unsafe {
            // ReleaseMutex only works from the owning thread. If the guard was
            // moved, CloseHandle still frees the object and the next waiter sees
            // WAIT_ABANDONED_0 rather than blocking forever.
            ReleaseMutex(self.imp);
            CloseHandle(self.imp);
        }
    }
}

#[cfg(not(windows))]
impl Drop for HostMutationGuard {
    fn drop(&mut self) {
        use fs2::FileExt;
        // The file stays behind: unlinking "the" lock file is how two writers each
        // end up holding their own.
        let _ = self.imp.unlock();
    }
}

enum TryAcquired {
    Held(HostMutationGuard),
    Busy,
    Failed(String),
}

/// How long a single wait inside the acquire loop lasts. Short enough that the
/// overall `timeout` stays honest, long enough not to spin.
#[cfg(windows)]
const WAIT_INTERVAL: Duration = Duration::from_millis(300);

/// File name inside the per-user directory chosen below.
#[cfg(not(windows))]
const LOCK_FILE_NAME: &str = "aether-host-mutation.lock";

/// Where the non-Windows lock lives: a directory this uid owns and nobody else
/// can write into.
///
/// It used to be a fixed `temp_dir()/aether-host-mutation.lock`. A world-shared
/// name in a world-writable directory is a cross-user refusal — any account can
/// open that file, sit on the flock, and make every other session wait out the
/// timeout before declining to touch routes — and it made "I could not create
/// the lock" indistinguishable from "someone else holds it". Candidates are
/// tried in order so a stale `XDG_RUNTIME_DIR` that is no longer usable cannot
/// wedge a host that has a perfectly good `$HOME`.
#[cfg(not(windows))]
fn lock_file_path() -> std::result::Result<std::path::PathBuf, String> {
    let mut problems = Vec::new();
    for dir in lock_dir_candidates() {
        match ensure_private_dir(&dir) {
            Ok(()) => return Ok(dir.join(LOCK_FILE_NAME)),
            Err(why) => problems.push(why),
        }
    }
    Err(format!(
        "no private directory is usable for the host-mutation lock: {}",
        problems.join("; ")
    ))
}

/// OS environment facts, not app configuration: `runtime_env` owns only
/// `AETHER_*` keys, so routing these through it would return `None`.
#[cfg(not(windows))]
#[allow(clippy::disallowed_methods)]
fn lock_dir_candidates() -> Vec<std::path::PathBuf> {
    let uid = unsafe { libc::getuid() };
    let mut out = Vec::new();
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !rt.is_empty() && std::path::Path::new(&rt).is_absolute() {
            // Created by systemd/logind per user, mode 0700, on tmpfs.
            out.push(std::path::PathBuf::from(rt).join("aether-host-lock"));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            out.push(
                std::path::Path::new(&home)
                    .join(".cache")
                    .join("aether-host-lock"),
            );
        }
    }
    // Nothing per-user to hide in: name the world-writable fallback after the
    // uid so two accounts cannot reach for the same file, and let the ownership
    // check below refuse a directory somebody else pre-created.
    out.push(std::env::temp_dir().join(format!("aether-host-lock-{uid}")));
    out
}

/// Create the directory as `0700` and confirm this uid owns it.
#[cfg(not(windows))]
fn ensure_private_dir(dir: &std::path::Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let uid = unsafe { libc::getuid() };
    // `recursive` reports Ok for an existing directory, which is the normal
    // second-run case; the mode applies to everything it creates.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let md = std::fs::metadata(dir).map_err(|e| format!("{}: cannot stat: {e}", dir.display()))?;
    if md.uid() != uid {
        return Err(format!(
            "{} is owned by uid {}, not {uid}: refusing to share a host-mutation lock with \
             another account",
            dir.display(),
            md.uid()
        ));
    }
    // An existing directory is created with whatever mode whoever made it chose,
    // and `DirBuilder::create` will not revisit it: insist on 0700 every time,
    // since the whole point of the per-uid name is that no other account can
    // put a held lock file inside it.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: cannot make private: {e}", dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// A guard that cannot actually exclude anyone is worse than none: it converts
    /// a doubled session into a silent race that looks protected in the code.
    #[test]
    fn a_held_lock_makes_the_second_holder_wait_and_then_refuse() {
        let guard = HostMutationGuard::acquire(Duration::from_secs(2)).expect("first acquire");

        // Same thread: Windows mutexes are re-entrant for the owning thread, so the
        // contention has to come from a different thread to mean anything.
        let (tx, rx) = mpsc::channel();
        let blocker = std::thread::spawn(move || {
            let res = HostMutationGuard::acquire(Duration::from_millis(300));
            let _ = tx.send(res.is_err());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap_or(false),
            "a second thread took the host-mutation lock while it was held"
        );
        blocker.join().unwrap();

        drop(guard);
        HostMutationGuard::acquire(Duration::from_secs(2)).expect("lock is free after release");
    }

    /// A holder that dies without releasing must not wedge the host. This is the
    /// property the pid-in-a-file design got wrong, and only a real process exit
    /// exercises it (destructors do not run on `exit`).
    #[test]
    fn a_dead_holder_does_not_wedge_the_lock() {
        const CHILD_ENV: &str = "HOST_LOCK_TEST_CHILD";

        #[allow(clippy::disallowed_methods)]
        if std::env::var(CHILD_ENV).is_ok() {
            let held = HostMutationGuard::acquire(Duration::from_secs(5)).expect("child acquires");
            // Say it is held, then leave without running the destructor.
            println!("HELD");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            std::mem::forget(held);
            std::process::exit(0);
        }

        let exe = std::env::current_exe().expect("test binary");
        for slot in 0..2 {
            let mut child = std::process::Command::new(&exe)
                .arg("--exact")
                // The full module path, or libtest filters the child's only test
                // out and it exits having done nothing (which reads as success).
                .arg("host_lock::tests::a_dead_holder_does_not_wedge_the_lock")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn holder");
            {
                let mut buf = String::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = std::io::Read::read_to_string(&mut out, &mut buf);
                }
                assert!(buf.contains("HELD"), "child never took the lock: {buf:?}");
            }
            let status = child.wait().expect("child exits");
            assert!(status.success(), "child slot {slot} failed");
            let _reacquired = HostMutationGuard::acquire(Duration::from_secs(5))
                .unwrap_or_else(|e| panic!("attempt {slot}: a dead holder wedged the lock: {e}"));
        }
    }

    /// The non-Windows lock must be unreachable to any other account. A name in
    /// a world-writable directory is not: whoever gets there first decides when
    /// everyone else is allowed to touch the routing table.
    #[cfg(not(windows))]
    #[test]
    fn the_lock_lives_in_a_directory_only_this_uid_can_write() {
        use std::os::unix::fs::MetadataExt;
        let path = lock_file_path().expect("a usable private directory");
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(LOCK_FILE_NAME)
        );
        let dir = path.parent().expect("a directory component");
        let md = std::fs::metadata(dir).expect("the directory exists");
        assert_eq!(
            md.uid(),
            unsafe { libc::getuid() },
            "the directory is not ours"
        );
        assert_eq!(md.mode() & 0o077, 0, "group or other can write into it");
        assert_ne!(
            dir,
            std::env::temp_dir().as_path(),
            "world-shared directory"
        );
        assert_eq!(path, lock_file_path().expect("stable across calls"));
    }
}
