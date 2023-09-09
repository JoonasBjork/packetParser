use std::io;
mod ether_parse;
mod ip_parse;
mod tcp;
mod tcp_parse;

use ether_parse::parse_ether::*;
use ip_parse::{parse_ip_utilities::*, parse_ipv4_raw::*};
use tcp_parse::parse_tcp_utilities::*;

use crate::tcp_parse::parse_tcp_raw::get_tcp_checksum;

fn main() -> io::Result<()> {
    println!("Hello, world!");
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create TUN");
    let mut frame_buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut frame_buf[..])?;
        let ether_type_bytes = get_ether_type(&mut frame_buf);
        let ether_type: u32 = u32::from_be_bytes(ether_type_bytes);

        let ether_data_size = nbytes - 4;

        let (ether_payload, ether_payload_size) = get_ether_data(&frame_buf, ether_data_size);

        eprintln!("{:x?}", ether_type);
        eprintln!("Read {} bytes: {:x?}", nbytes, &frame_buf[..nbytes]);
        eprintln!("Ether payload: {:x?}", &ether_payload[..ether_payload_size]);

        let mut ip_buf = [0u8; 65535];
        ip_buf[..1500].copy_from_slice(&ether_payload);

        println!();

        match validate_full_ip_datagram(&ip_buf) {
            Ok(_) => (),
            Err(de) => {
                eprintln!("Found errors in datagram\n{:?}", de.0);
                continue;
            }
        }
        print_ip_data(&ip_buf);

        println!();
        let tcp_packet = get_ip_data(&ip_buf);

        print_tcp_data(&tcp_packet);

        println!(
            "calculate_tcp_checksum_from_ip_datagram: {:x?}",
            calculate_tcp_checksum_from_ip_datagram(&ip_buf)
        );
        println!("get_tcp_checksum: {:x?}", get_tcp_checksum(&tcp_packet));
    }
    /* Ok(()) */
}
