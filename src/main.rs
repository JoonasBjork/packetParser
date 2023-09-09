use std::io;
mod ether_parse;
mod ip_parse;
mod tcp;
mod tcp_parse;

use ether_parse::parse_ether::*;
use ip_parse::{parse_ip_utilities::*, parse_ipv4_raw::*};
use tcp::tcb::TCPContext;
use tcp_parse::parse_tcp_utilities::*;

use crate::tcp_parse::parse_tcp_raw::get_tcp_checksum;

fn main() -> io::Result<()> {
    println!("Hello, world!");
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create TUN");
    let mut frame_buf = [0u8; 1504];
    let mut tcp_context = TCPContext::new();

    loop {
        let nbytes = nic.recv(&mut frame_buf[..])?;
        let ether_type_bytes = get_ether_type(&mut frame_buf);
        let ether_type: u32 = u32::from_be_bytes(ether_type_bytes);

        let ether_data_size = nbytes - 4;

        let (ether_payload, ether_payload_size) = get_ether_data(&frame_buf, ether_data_size);

        eprintln!("{:x?}", ether_type);
        eprintln!("Read {} bytes: {:x?}", nbytes, &frame_buf[..nbytes]);
        eprintln!("Ether payload: {:x?}", &ether_payload[..ether_payload_size]);

        let ip_datagram = ether_payload[..ether_payload_size].to_vec();

        match get_ip_version(&ip_datagram)[0] {
            4 => (),
            6 => {
                println!("IPv6 Not supported");
                continue;
            }
            v @ _ => println!("Unknown version number: {}", v),
        }

        let ip_datagram_protocol = get_ip_protocol(&ip_datagram)[0];

        let returned_packet = match ip_datagram_protocol {
            6 => tcp_context.handle_tcp_packet(&ip_datagram),
            p @ _ => {
                println!("Unsupported protocol: {}", p);
                None
            }
        };

        // tcp_context.handle
        // let mut ip_buf = [0u8; 65535];
        // ip_buf[..1500].copy_from_slice(&ether_payload);

        // println!();

        // print_ip_data(&ip_buf);

        // println!();
        // let tcp_packet = get_ip_data(&ip_buf);

        // print_tcp_data(&tcp_packet);

        // println!(
        //     "calculate_tcp_checksum_from_ip_datagram: {:x?}",
        //     calculate_tcp_checksum_from_ip_datagram(&ip_buf)
        // );
        // println!("get_tcp_checksum: {:x?}", get_tcp_checksum(&tcp_packet));
    }
    /* Ok(()) */
}
