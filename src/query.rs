use std::mem::size_of;

use crate::{
    nlmsg::NfNetlinkWriter,
    parser::{nft_nlmsg_maxsize, Nfgenmsg},
    sys, ProtoFamily,
};
use libc::{
    nlmsgerr, nlmsghdr, NFNETLINK_V0, NFNL_SUBSYS_NFTABLES, NLMSG_DONE, NLMSG_ERROR,
    NLMSG_MIN_TYPE, NLMSG_NOOP, NLM_F_DUMP_INTR,
};

/// Returns a buffer containing a netlink message which requests a list of all the netfilter
/// matching objects (e.g. tables, chains, rules, ...).
/// Supply the type of objects to retrieve (e.g. libc::NFT_MSG_GETTABLE), and optionally a callback
/// to execute on the header, to set parameters for example.
/// To pass arbitrary data inside that callback, please use a closure.
pub fn get_list_of_objects<Error>(
    msg_type: u16,
    seq: u32,
    setup_cb: Option<&dyn Fn(&mut libc::nlmsghdr) -> Result<(), Error>>,
) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0; nft_nlmsg_maxsize() as usize];
    let mut writer = &mut NfNetlinkWriter::new(&mut buffer);
    writer.write_header(
        msg_type,
        ProtoFamily::Unspec,
        (libc::NLM_F_ROOT | libc::NLM_F_MATCH) as u16,
        seq,
        None,
    );
    if let Some(cb) = setup_cb {
        cb(writer
            .get_current_header()
            .expect("Fatal error: mising header"))?;
    }
    Ok(buffer)
}

#[cfg(feature = "query")]
mod inner {
    use std::os::unix::prelude::RawFd;

    use nix::{
        errno::Errno,
        sys::socket::{self, AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType},
    };

    //use crate::FinalizedBatch;

    use crate::nlmsg::{parse_nlmsg, DecodeError, NlMsg};

    use super::*;

    #[derive(thiserror::Error, Debug)]
    pub enum Error {
        #[error("Unable to open netlink socket to netfilter")]
        NetlinkOpenError(#[source] nix::Error),

        #[error("Unable to send netlink command to netfilter")]
        NetlinkSendError(#[source] nix::Error),

        #[error("Error while reading from netlink socket")]
        NetlinkRecvError(#[source] nix::Error),

        #[error("Error while processing an incoming netlink message")]
        ProcessNetlinkError(#[from] DecodeError),

        #[error("Error received from the kernel")]
        NetlinkError(nlmsgerr),

        #[error("Custom error when customizing the query")]
        InitError(#[from] Box<dyn std::error::Error + Send + 'static>),

        #[error("Couldn't allocate a netlink object, out of memory ?")]
        NetlinkAllocationFailed,

        #[error("This socket is not a netlink socket")]
        NotNetlinkSocket,

        #[error("Couldn't retrieve information on a socket")]
        RetrievingSocketInfoFailed,

        #[error("Only a part of the message was sent")]
        TruncatedSend,

        #[error("Couldn't close the socket")]
        CloseFailed(#[source] Errno),
    }

    fn recv_and_process<'a, T>(
        sock: RawFd,
        cb: &dyn Fn(&nlmsghdr, &Nfgenmsg, &[u8], &mut T) -> Result<(), Error>,
        working_data: &'a mut T,
        seq: u32,
        portid: u32,
    ) -> Result<(), Error> {
        let mut msg_buffer = vec![0; nft_nlmsg_maxsize() as usize];

        loop {
            let nb_recv = socket::recv(sock, &mut msg_buffer, MsgFlags::empty())
                .map_err(Error::NetlinkRecvError)?;
            if nb_recv <= 0 {
                return Ok(());
            }
            let mut buf = &msg_buffer.as_slice()[0..nb_recv];
            loop {
                let (nlmsghdr, msg) = unsafe { parse_nlmsg(&buf, seq, portid) }?;
                match msg {
                    NlMsg::Done => {
                        return Ok(());
                    }
                    NlMsg::Error(e) => {
                        if e.error != 0 {
                            return Err(Error::NetlinkError(e));
                        }
                    }
                    NlMsg::Noop => {}
                    NlMsg::NfGenMsg(genmsg, data) => cb(&nlmsghdr, &genmsg, &data, working_data)?,
                }

                // netlink messages are 4bytes aligned
                let aligned_length = ((nlmsghdr.nlmsg_len + 3) & !3u32) as usize;

                // retrieve the next message
                buf = &buf[aligned_length..];

                // exit the loop when we consumed all the buffer
                if buf.len() == 0 {
                    break;
                }
            }
        }
    }

    fn socket_close_wrapper(
        sock: RawFd,
        cb: impl FnOnce(RawFd) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let ret = cb(sock);

        // we don't need to shutdown the socket (in fact, Linux doesn't support that operation;
        // and return EOPNOTSUPP if we try)
        nix::unistd::close(sock).map_err(Error::CloseFailed)?;

        ret
    }

    /// Lists objects of a certain type (e.g. libc::NFT_MSG_GETTABLE) with the help of a helper
    /// function called by mnl::cb_run2.
    /// The callback expects a tuple of additional data (supplied as an argument to this function)
    /// and of the output vector, to which it should append the parsed object it received.
    pub fn list_objects_with_data<'a, T>(
        data_type: u16,
        cb: &dyn Fn(&libc::nlmsghdr, &Nfgenmsg, &[u8], &mut T) -> Result<(), Error>,
        working_data: &'a mut T,
        req_hdr_customize: Option<&dyn Fn(&mut libc::nlmsghdr) -> Result<(), Error>>,
    ) -> Result<(), Error> {
        debug!("listing objects of kind {}", data_type);
        let sock = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkNetFilter,
        )
        .map_err(Error::NetlinkOpenError)?;

        let seq = 0;
        let portid = 0;

        let chains_buf = get_list_of_objects(data_type, seq, req_hdr_customize)?;
        socket::send(sock, &chains_buf, MsgFlags::empty()).map_err(Error::NetlinkSendError)?;

        Ok(socket_close_wrapper(sock, move |sock| {
            recv_and_process(sock, cb, working_data, seq, portid)
        })?)
    }

    /*
    pub fn send_batch(batch: &mut FinalizedBatch) -> Result<(), Error> {
        let sock = socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkNetFilter,
        )
        .map_err(Error::NetlinkOpenError)?;

        let seq = 0;
        let portid = 0;

        // while this bind() is not strictly necessary, strace have trouble decoding the messages
        // if we don't
        let addr = SockAddr::Netlink(NetlinkAddr::new(portid, 0));
        socket::bind(sock, &addr).expect("bind");
        //match socket::getsockname(sock).map_err(|_| Error::RetrievingSocketInfoFailed)? {
        //    SockAddr::Netlink(addr) => addr.0.nl_pid,
        //    _ => return Err(Error::NotNetlinkSocket),
        //};

        for data in batch {
            if socket::send(sock, data, MsgFlags::empty()).map_err(Error::NetlinkSendError)?
                < data.len()
            {
                return Err(Error::TruncatedSend);
            }
        }

        Ok(socket_close_wrapper(sock, move |sock| {
            recv_and_process(sock, &|_, _, _, _| Ok(()), &mut (), seq, portid)
        })?)
    }
    */
}

#[cfg(feature = "query")]
pub use inner::*;
