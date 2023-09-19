use netlink_sys::Socket;
use nix::sys::socket::SockProtocol;

use crate::error::QueryError;

pub trait Essence {
    fn essentialize(&mut self) {
        // do nothing
    }
}

/// Creates a new socket appropriate for this lib
pub fn new_socket() -> std::io::Result<Socket> {
    Socket::new(SockProtocol::NetlinkNetFilter as isize)
}
