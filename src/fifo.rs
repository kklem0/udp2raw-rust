//! `--fifo`: a named pipe for runtime commands (`echo reconnect > fifo.file`).

use crate::consts::BUF_LEN;
use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;

pub fn create_fifo(path: &str) -> io::Result<RawFd> {
    let c = CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad fifo path"))?;
    if unsafe { libc::mkfifo(c.as_ptr(), 0o666) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EEXIST) {
            log::warn!("warning fifo file {path} exist");
        } else {
            return Err(io::Error::new(e.kind(), format!("create fifo file {path} failed: {e}")));
        }
    }
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::other(format!("create fifo file {path} failed: {}", io::Error::last_os_error())));
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::other(format!("fstat failed for fifo file {path}")));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(io::Error::other(format!("{path} is not a fifo")));
    }
    Ok(fd)
}

/// Read one command (trailing newlines stripped).
pub fn read_command(fd: RawFd) -> Option<String> {
    let mut buf = vec![0u8; BUF_LEN];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() - 1) };
    if n < 0 {
        log::warn!("fifo read failed,errno={}", io::Error::last_os_error());
        return None;
    }
    let mut n = n as usize;
    while n > 0 && buf[n - 1] == b'\n' {
        n -= 1;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}
