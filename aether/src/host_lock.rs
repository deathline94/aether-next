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

use std::time::{Duration, Instant};

use crate::error::{AetherError, Result};

/// How long to wait for another session to finish before refusing. Long enough for
/// a teardown on a slow link, short enough that Connect does not look hung.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(windows)]
const MUTEX_NAME: &str = "Local\\AetherNext.HostMutation.v1";

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
        use std::iter::once;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            CloseHandle, GetLastError, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let name: Vec<u16> = std::ffi::OsStr::new(MUTEX_NAME).encode_wide().chain(once(0)).collect();
        // `bInitialOwner = FALSE` plus an explicit wait: claiming the mutex at create
        // time cannot report abandonment, and abandonment is the whole point.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return TryAcquired::Failed(format!(
                "CreateMutexW({MUTEX_NAME}) failed: {}",
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
                    "WaitForSingleObject({MUTEX_NAME}) returned {other}                      (gle {gle}) after {}",
                    if other == WAIT_FAILED { "WAIT_FAILED" } else { "an unexpected code" }
                ))
            }
        }
    }

    #[cfg(not(windows))]
    fn try_acquire() -> TryAcquired {
        use fs2::FileExt;
        let path = lock_file_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => return TryAcquired::Failed(format!("cannot open {}: {e}", path.display())),
        };
        match file.try_lock_exclusive() {
            Ok(()) => TryAcquired::Held(HostMutationGuard { imp: file }),
            Err(_) => TryAcquired::Busy,
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

#[cfg(not(windows))]
fn lock_file_path() -> std::path::PathBuf {
    std::env::temp_dir().join("aether-host-mutation.lock")
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
}
