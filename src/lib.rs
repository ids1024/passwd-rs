//! This modules provides a wrapper around the libc functions in `pwd.h` for
//! handling the `/etc/passwd` file, which stores information about users.
//!
//! # Examples
//!
//! ```
//! use passwd::Passwd;
//!
//! println!("{:?}", Passwd::from_name("root"));
//! println!("{:?}", Passwd::from_uid(0));
//! ```


extern crate libc;


use std::ffi::CString;
use std::ffi::CStr;


/// Represents an entry in `/etc/passwd`
#[derive(Debug)]
pub struct Passwd {
    /// username
    pub name: String,
    /// user password
    pub password: String,
    /// user ID
    pub uid: libc::uid_t,
    /// group ID
    pub gid: libc::gid_t,
    /// user information
    pub gecos: String,
    /// home directory
    pub home_dir: String,
    /// shell program
    pub shell: String,
}

impl Passwd {
    unsafe fn from_ptr(pwd: *const libc::passwd) -> Passwd {
        Passwd {
            name: CStr::from_ptr((*pwd).pw_name).to_str().unwrap().to_owned(),
            password: CStr::from_ptr((*pwd).pw_passwd).to_str().unwrap().to_owned(),
            uid: (*pwd).pw_uid,
            gid: (*pwd).pw_gid,

            #[cfg(not(target_os = "android"))]
            gecos: CStr::from_ptr((*pwd).pw_gecos).to_str().unwrap().to_owned(),
            #[cfg(target_os = "android")]
            gecos: String::new(),

            home_dir: CStr::from_ptr((*pwd).pw_dir).to_str().unwrap().to_owned(),
            shell: CStr::from_ptr((*pwd).pw_shell).to_str().unwrap().to_owned(),
        }
    }

    /// Gets a `Passwd` entry for the given username, or returns `None`
    pub fn from_name(user: &str) -> Option<Passwd> {
        let c_user = CString::new(user).unwrap();

        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = Vec::with_capacity(getpw_r_size_max());
        let mut result = std::ptr::null_mut();
        unsafe {
            libc::getpwnam_r(c_user.as_ptr(),
                             &mut pwd,
                             buf.as_mut_ptr(),
                             buf.capacity(),
                             &mut result);
        }

        if result.is_null() {
            None
        } else {
            Some(unsafe { Passwd::from_ptr(result) })
        }
    }

    /// Gets a `Passwd` entry for the given uid, or returns `None`
    pub fn from_uid(uid: libc::uid_t) -> Option<Passwd> {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = Vec::with_capacity(getpw_r_size_max());
        let mut result = std::ptr::null_mut();
        unsafe {
            libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.capacity(), &mut result);
        }

        if result.is_null() {
            None
        } else {
            Some(unsafe { Passwd::from_ptr(result) })
        }
    }
}

fn getpw_r_size_max() -> usize {
    // Borrowed from libstd/sys/unix/os.rs
    // (As are a few lines elsewhere)
    match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n < 0 => 512 as usize,
        n => n as usize,
    }
}
