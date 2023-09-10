// use crate::tcp_parse::parse_tcp_raw::*;
use crate::{
    ip_parse::{parse_ip_utilities, parse_ipv4_raw},
    tcp_parse::{parse_tcp_raw, parse_tcp_utilities},
};

enum State {
    LISTEN,
    SYNSENT,
    SYNRECEIVED,
    ESTABLISHED,
    FINWAIT1,
    FINWAIT2,
    CLOSEWAIT,
    CLOSING,
    LASTACK,
    TIMEWAIT,
    CLOSED,
}

struct TCB {
    /// The state of the TCB
    state: State,

    local_ip_addr: u32,
    remote_ip_addr: u32,

    local_port: u16,
    remote_port: u16,
    // Send sequence variables
    /// send unacknowledged
    snd_una: u32,
    /// Send next
    snd_nxt: u32,
    /// Send window
    snd_wnd: u32,
    /// Send urgent pointer
    snd_up: u32,
    /// Segment sequence number used for last window update
    snd_wl1: u32,
    /// Segment acknowledgment number used for last window update
    snd_wl2: u32,
    /// Initial send sequence number
    snd_iss: u32,

    // Receive sequence variables
    /// Eeceive next
    rcv_nxt: u32,
    /// Receive window
    rcv_wnd: u32,
    /// Receive urgent pointer
    rcv_up: u32,
    /// Initial receive sequence number
    rcv_irs: u32,

    // Segment sequence variables
    /// segment sequence number
    seg_seq: u32,
    /// segment acknowledgment number
    seg_ack: u32,
    /// segment length
    seg_len: u32,
    /// segment window
    seg_wnd: u32,
    /// segment urgent pointer
    seg_up: u32,
    /// segment precedence value
    seg_prc: u32,
}

impl TCB {
    pub fn new(
        state: State,
        local_ip_addr: u32,
        remote_ip_addr: u32,
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        TCB {
            state: State::LISTEN,
            local_ip_addr,
            remote_ip_addr,
            local_port,
            remote_port,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            snd_up: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_iss: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            rcv_up: 0,
            rcv_irs: 0,
            seg_seq: 0,
            seg_ack: 0,
            seg_len: 0,
            seg_wnd: 0,
            seg_up: 0,
            seg_prc: 0,
        }
    }
}

pub struct TCPContext {
    active_connections: Vec<TCB>,
    /// Representation of an open port. Open ports can accept communication requests.
    listening_ports: Vec<u16>,
}

impl TCPContext {
    pub fn new() -> Self {
        return TCPContext {
            active_connections: Vec::new(),
            listening_ports: Vec::new(),
        };
    }

    /// Sets `new_port_number` to listening. Returns empty error if the port number is already listening.  
    pub fn set_port_to_listening(&mut self, new_port_number: u16) -> Result<(), ()> {
        if self.listening_ports.contains(&new_port_number) {
            return Err(());
        }
        self.listening_ports.push(new_port_number);
        Ok(())
    }

    fn create_rst_datagram(ip_datagram: &[u8], tcp_packet: &[u8]) -> Vec<u8> {
        unimplemented!()
    }
    /// Start of the logic flow when receiving a TCP packet. If the program should respond something to the incoming TCP packet, an IP datagram that contains the response is returned.
    /// Otherwise None is returned.
    pub fn handle_tcp_packet(&self, ip_datagram: &[u8]) -> Option<Vec<u8>> {
        if let Err(e) = parse_ip_utilities::validate_ip_datagram(&ip_datagram) {
            e.print_all_errors();
            return None;
        }

        let tcp_packet = parse_ipv4_raw::get_ip_data(ip_datagram);
        if let Err(e) = parse_tcp_utilities::validate_tcp_packet(&tcp_packet) {
            e.print_all_errors();
            return None;
        }

        let src_ip_addr = parse_ipv4_raw::get_ip_src_addr(&ip_datagram);
        let dst_ip_addr = parse_ipv4_raw::get_ip_dst_addr(&ip_datagram);
        let ip_protocol = parse_ipv4_raw::get_ip_protocol(&ip_datagram);

        if !parse_tcp_utilities::check_tcp_checksum(
            &src_ip_addr,
            &dst_ip_addr,
            &[0],
            &ip_protocol,
            &tcp_packet,
        ) {
            println!("TCP checksum doesn't match");
            return None;
        }

        parse_ip_utilities::print_ip_data(&ip_datagram);
        println!();
        parse_tcp_utilities::print_tcp_data(&tcp_packet);
        println!();

        // Check if the port is listening. If not, return RST.
        if !self
            .listening_ports
            .contains(&u16::from_be_bytes(parse_tcp_raw::get_tcp_dst_port(
                &tcp_packet,
            )))
        {
            println!("Port number is not open");
            return Some(Self::create_rst_datagram(&ip_datagram, &tcp_packet));
        }

        // Start TCP functionality
        if parse_tcp_raw::get_tcp_syn_flag(&tcp_packet)[0] == 1 {
            let tcb = TCB::new(
                State::LISTEN,
                u32::from_be_bytes(src_ip_addr),
                u32::from_be_bytes(dst_ip_addr),
                u16::from_be_bytes(parse_tcp_raw::get_tcp_dst_port(&tcp_packet)),
                u16::from_be_bytes(parse_tcp_raw::get_tcp_src_port(&tcp_packet)),
            );
        }

        None
    }
}
