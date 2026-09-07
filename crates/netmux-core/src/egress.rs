//! Raw-socket egress and per-interface capture for the userspace NAT
//! forwarder.
//!
//! * [`RawEgress`] sends an already-NATed IPv4 packet out a specific physical
//!   interface. It uses an `AF_INET` `SOCK_RAW` socket with `IP_HDRINCL` and
//!   `SO_BINDTODEVICE`, so the kernel handles ARP and on-link routing for the
//!   bound device (no L2 framing needed in userspace).
//! * [`RawCapture`] binds an `AF_PACKET` socket to a physical interface and
//!   yields inbound IPv4 packets (Ethernet header stripped) — this is how we
//!   see the reply traffic that must be reverse-NATed back into the TUN.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};

use libc as c;

use crate::error::{NetmuxError, Result};

/// An egress socket pinned to one physical interface.
pub struct RawEgress {
    fd: RawFd,
    pub ifname: String,
}

impl RawEgress {
    /// Open a raw IPv4 socket bound to `ifname`. Requires `CAP_NET_RAW`.
    pub fn open(ifname: &str) -> Result<Self> {
        let fd = unsafe { c::socket(c::AF_INET, c::SOCK_RAW, c::IPPROTO_RAW) };
        if fd < 0 {
            return Err(NetmuxError::io("socket(AF_INET, SOCK_RAW)", io::Error::last_os_error()));
        }

        // Deliver the raw IP header unmodified; the kernel fills nothing.
        let one: c::c_int = 1;
        let rc = unsafe {
            c::setsockopt(
                fd,
                c::IPPROTO_IP,
                c::IP_HDRINCL,
                &one as *const _ as *const c::c_void,
                std::mem::size_of::<c::c_int>() as c::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { c::close(fd) };
            return Err(NetmuxError::io("setsockopt(IP_HDRINCL)", io::Error::last_os_error()));
        }

        // Force this socket onto `ifname` so the kernel routes via that device.
        let cname = std::ffi::CString::new(ifname)
            .map_err(|_| NetmuxError::Config("ifname contains NUL".into()))?;
        let rc = unsafe {
            c::setsockopt(
                fd,
                c::SOL_SOCKET,
                c::SO_BINDTODEVICE,
                cname.as_ptr() as *const c::c_void,
                (ifname.len() + 1) as c::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { c::close(fd) };
            return Err(NetmuxError::io("setsockopt(SO_BINDTODEVICE)", io::Error::last_os_error()));
        }

        Ok(RawEgress {
            fd,
            ifname: ifname.to_string(),
        })
    }

    /// Send one IPv4 packet (complete, valid IP header) toward `dst`.
    pub fn send(&self, pkt: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
        let mut sa: c::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = c::AF_INET as c::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr = c::in_addr {
            s_addr: u32::from_ne_bytes(dst.octets()).to_be(),
        };
        let n = unsafe {
            c::sendto(
                self.fd,
                pkt.as_ptr() as *const c::c_void,
                pkt.len(),
                0,
                &sa as *const _ as *const c::sockaddr,
                std::mem::size_of::<c::sockaddr_in>() as c::socklen_t,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Drop for RawEgress {
    fn drop(&mut self) {
        unsafe { c::close(self.fd) };
    }
}

/// An AF_PACKET capture socket pinned to one physical interface.
pub struct RawCapture {
    fd: RawFd,
    pub ifname: String,
}

impl RawCapture {
    /// Open an `AF_PACKET` socket bound to `ifname`, receiving IPv4 frames.
    /// Requires `CAP_NET_RAW`.
    pub fn open(ifname: &str) -> Result<Self> {
        let fd = unsafe { c::socket(c::AF_PACKET, c::SOCK_RAW, (c::ETH_P_IP as u16).to_be() as c::c_int) };
        if fd < 0 {
            return Err(NetmuxError::io("socket(AF_PACKET)", io::Error::last_os_error()));
        }

        let cname = std::ffi::CString::new(ifname)
            .map_err(|_| NetmuxError::Config("ifname contains NUL".into()))?;
        let ifindex = unsafe { c::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            unsafe { c::close(fd) };
            return Err(NetmuxError::io(
                "if_nametoindex",
                io::Error::last_os_error(),
            ));
        }

        let mut sll: c::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = c::AF_PACKET as c::sa_family_t;
        sll.sll_protocol = (c::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = ifindex as c::c_int;
        let rc = unsafe {
            c::bind(
                fd,
                &sll as *const _ as *const c::sockaddr,
                std::mem::size_of::<c::sockaddr_ll>() as c::socklen_t,
            )
        };
        if rc < 0 {
            unsafe { c::close(fd) };
            return Err(NetmuxError::io("bind(AF_PACKET)", io::Error::last_os_error()));
        }

        Ok(RawCapture {
            fd,
            ifname: ifname.to_string(),
        })
    }

    /// Receive one frame; returns the IPv4 packet with the 14-byte Ethernet
    /// header stripped. `buf` must be large enough (MTU + 14).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { c::recv(self.fd, buf.as_mut_ptr() as *mut c::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n > 14 {
            buf.copy_within(14..n, 0);
            Ok(n - 14)
        } else {
            Ok(0)
        }
    }
}

impl Drop for RawCapture {
    fn drop(&mut self) {
        unsafe { c::close(self.fd) };
    }
}

impl AsRawFd for RawCapture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
