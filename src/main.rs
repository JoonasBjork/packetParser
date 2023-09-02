use std::io;
mod ether_parse;
mod ip_parse;

use ether_parse::parse_ether::*;
use ip_parse::parse_ip::*;

fn main() -> io::Result<()> {
    println!("Hello, world!");
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create TUN");
    let mut frame_buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut frame_buf[..])?;
        let ether_type_bytes = get_ether_type(&mut frame_buf);
        let ether_type: u32 = u32::from_be_bytes(ether_type_bytes);

        let data_size = nbytes - 4;

        let (ether_payload, ether_payload_size) = get_ether_data(&frame_buf, data_size);

        eprintln!("{:x?}", ether_type);
        eprintln!("Read {} bytes: {:x?}", nbytes, &frame_buf[..nbytes]);
        eprintln!("Ether payload: {:x?}", &ether_payload[..ether_payload_size]);

        let mut ip_buf = [0u8; 65535];
        println!("Hello");

        ip_buf[..1500].copy_from_slice(&ether_payload);
        println!("Hello");

        let ip_version = u8::from_be_bytes(get_ip_version(&ip_buf));
        let ip_ihl = u8::from_be_bytes(get_ip_ihl(&ip_buf));
        let ip_tos = u8::from_be_bytes(get_ip_tos(&ip_buf));
        let ip_dscp = u8::from_be_bytes(get_ip_dscp(&ip_buf));
        let ip_ecn = u8::from_be_bytes(get_ip_ecn(&ip_buf));
        let ip_tl = u16::from_be_bytes(get_ip_tl(&ip_buf));
        let ip_id = u16::from_be_bytes(get_ip_identification(&ip_buf));
        let ip_df = u8::from_be_bytes(get_ip_df_flag(&ip_buf));
        let ip_mf = u8::from_be_bytes(get_ip_mf_flag(&ip_buf));
        let ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&ip_buf));
        let ip_ttl = u8::from_be_bytes(get_ip_ttl(&ip_buf));
        let ip_proto = u8::from_be_bytes(get_ip_protocol(&ip_buf));
        let ip_checksum = u16::from_be_bytes(get_ip_checksum(&ip_buf));
        let ip_src_addr = get_ip_src_addr(&ip_buf);
        let ip_dst_addr = get_ip_dst_addr(&ip_buf);
        let ip_opts = get_ip_options(&ip_buf);
        let (ip_data, ip_data_len) = get_ip_data(&ip_buf, data_size);

        println!("ip_version: {:x?}", ip_version);
        println!("ip_ihl: {:x?}", ip_ihl);
        println!("ip_tos: {:x?}", ip_tos);
        println!("ip_dscp: {:x?}", ip_dscp);
        println!("ip_ecn: {:x?}", ip_ecn);
        println!("ip_tl: {:x?}", ip_tl);
        println!("ip_id: {:x?}", ip_id);
        println!("ip_df: {:x?}", ip_df);
        println!("ip_mf: {:x?}", ip_mf);
        println!("ip_fragment_offset: {:x?}", ip_fragment_offset);
        println!("ip_ttl: {:x?}", ip_ttl);
        println!("ip_proto: {:x?}", ip_proto);
        println!("ip_checksum: {:x?}", ip_checksum);
        println!("ip_src_addr: {:?}", ip_src_addr);
        println!("ip_dst_addr: {:?}", ip_dst_addr);
        println!("ip_opts: {:x?}", ip_opts);
        println!("ip_data: {:x?}", ip_data[..ip_data_len].to_vec());
    }
    /* Ok(()) */
}
