//! Linux TUN virtual network device.
//!
//! A TUN (layer-3) device lets user-space read raw IP packets that applications
//! route into it, and inject packets back out onto the real network. This is
//! the foundation of the aggregator: apps send traffic to `netmux0`; we read it,
//! attach a flow policy, and forward each flow over a chosen physical interface.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};

use libc as c;

use crate::error::{NetmuxError, Result};

const TUNSETIFF: c::c_ulong = 0x4004_54ca; // _IOW('T', 202, int)
const SIOCGIFFLAGS: c::c_ulong = 0x8913;
const SIOCSIFFLAGS: c::c_ulong = 0x8914;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_UP: i16 = 0x0001;

/// Maximum IP packet we are willing to read from the TUN (64 KiB).
pub const MAX_PACKET: usize = 65536;

/// An opened TUN device.
pub struct Tun {
    file: File,
    pub name: String,
}

impl Tun {
    /// Create (or open) a TUN device named `name` (e.g. "netmux0").
    ///
    /// Requires the process to have `CAP_NET_ADMIN` (normally: run as root).
    pub fn create(name: &str) -> Result<Tun> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| NetmuxError::Config("interface name contains NUL byte".into()))?;

        let dev = std::ffi::CString::new("/dev/net/tun")
            .map_err(|_| NetmuxError::Internal("static path".into()))?;
        let dev_str = dev.to_str().map_err(|_| NetmuxError::Internal("path".into()))?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dev_str)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    NetmuxError::permission(
                        "cannot open /dev/net/tun — run as root or grant CAP_NET_ADMIN",
                    )
                } else {
                    NetmuxError::Io {
                        context: "opening /dev/net/tun".into(),
                        source: e,
                    }
                }
            })?;

        // Structure mirroring `struct ifreq`.
        let mut ifr = [0u8; 40];
        let ifname = cname.as_bytes();
        ifr[..ifname.len()].copy_from_slice(&ifname[..16.min(ifname.len())]);
        // `ifr_flags` is a `short` at offset 16 of `struct ifreq`.
        let flags = (IFF_TUN | IFF_NO_PI).to_ne_bytes();
        ifr[16..18].copy_from_slice(&flags);

        let rc = unsafe { c::ioctl(file.as_raw_fd(), TUNSETIFF, ifr.as_ptr()) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(NetmuxError::permission(
                    "ioctl(TUNSETIFF) needs CAP_NET_ADMIN — run as root, or grant: sudo setcap cap_net_admin+ep <netmux-app>",
                ));
            }
            return Err(NetmuxError::Io {
                context: format!("ioctl(TUNSETIFF) for {name}"),
                source: err,
            });
        }

        // Extract the actual interface name the kernel assigned.
        let assigned = ifr[..16]
            .split(|&b| b == 0)
            .next()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_else(|| name.to_string());

        Ok(Tun {
            file,
            name: assigned,
        })
    }

    /// Read one raw IP packet into `buf`. Returns the number of bytes read.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.file.as_raw_fd();
        let n = unsafe { c::read(fd, buf.as_mut_ptr() as *mut c::c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Write a raw IP packet out through the TUN (towards the applications).
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let fd = self.file.as_raw_fd();
        let n = unsafe { c::write(fd, buf.as_ptr() as *const c::c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// File descriptor for integrating with poll/epoll.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Switch the device into non-blocking mode so `read` returns `WouldBlock`
    /// (EAGAIN) instead of blocking when no packet is available.
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let fd = self.file.as_raw_fd();
        let flags = unsafe { c::fcntl(fd, c::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = unsafe { c::fcntl(fd, c::F_SETFL, flags | c::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        self.file.into_raw_fd()
    }
}

/// Bring the interface administratively up via `SIOCSIFFLAGS`.
///
/// Uses an ioctl on an AF_INET datagram socket instead of shelling out to
/// `ip`, so the process's own `CAP_NET_ADMIN` capability is honored (file
/// capabilities do not survive an exec of `ip`).
pub fn set_up(name: &str) -> Result<()> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| NetmuxError::Config("interface name contains NUL byte".into()))?;
    let fd = unsafe { c::socket(c::AF_INET, c::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(NetmuxError::Io {
            context: "socket(AF_INET, SOCK_DGRAM)".into(),
            source: io::Error::last_os_error(),
        });
    }

    let result = (|| {
        let mut ifr = [0u8; 40];
        ifr[..cname.as_bytes().len()].copy_from_slice(cname.as_bytes());
        // Read current flags.
        if unsafe { c::ioctl(fd, SIOCGIFFLAGS, ifr.as_ptr()) } < 0 {
            return Err(NetmuxError::Io {
                context: format!("ioctl(SIOCGIFFLAGS) for {name}"),
                source: io::Error::last_os_error(),
            });
        }
        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]) | IFF_UP;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        if unsafe { c::ioctl(fd, SIOCSIFFLAGS, ifr.as_ptr()) } < 0 {
            return Err(NetmuxError::Io {
                context: format!("ioctl(SIOCSIFFLAGS) for {name}"),
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    })();

    unsafe { c::close(fd) };
    result
}