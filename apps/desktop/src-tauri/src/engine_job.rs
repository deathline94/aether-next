//! M8: the kill-on-close Job Object the engine child runs inside, so the engine
//! cannot outlive a crashed or force-killed GUI holding ports 1819/1820 and the
//! system-proxy registry.

use crate::CommandError;

use std::os::windows::io::AsRawHandle;
use std::process::Child;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// Stored as isize so `Job` stays Send+Sync (HANDLE is a raw pointer in
/// windows-sys 0.61, which would poison AppState's Send bound).
pub struct Job(isize);

impl Job {
    pub fn create() -> Result<Self, CommandError> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err("CreateJobObjectW failed".into());
        }
        let mut info = unsafe { std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            unsafe { CloseHandle(handle) };
            return Err("SetInformationJobObject failed".into());
        }
        Ok(Job(handle as isize))
    }

    pub fn assign_child(&self, child: &Child) -> Result<(), CommandError> {
        let ok =
            unsafe { AssignProcessToJobObject(self.0 as HANDLE, child.as_raw_handle() as HANDLE) };
        if ok == 0 {
            Err("AssignProcessToJobObject failed".into())
        } else {
            Ok(())
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Closing the job handle kills any process still inside it.
        unsafe { CloseHandle(self.0 as HANDLE) };
    }
}
