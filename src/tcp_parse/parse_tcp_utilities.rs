use crate::tcp_parse::parse_tcp_raw::*;

/// Prints out information about the supplied TCP packet.
pub fn print_tcp_data(buf: &[u8]) -> () {
    let src_port = u16::from_be_bytes(get_tcp_src_port(&buf));
    let dst_port = u16::from_be_bytes(get_tcp_dst_port(&buf));
    let seqn = u32::from_be_bytes(get_tcp_seqn(&buf));
    let acknum = u32::from_be_bytes(get_tcp_acknum(&buf));
    let data_offset = u8::from_be_bytes(get_tcp_data_offset(&buf));
    let reserved = u8::from_be_bytes(get_tcp_reserved(&buf));
    let urg_flag = u8::from_be_bytes(get_tcp_urg_flag(&buf));
    let ack_flag = u8::from_be_bytes(get_tcp_ack_flag(&buf));
    let psh_flag = u8::from_be_bytes(get_tcp_psh_flag(&buf));
    let rst_flag = u8::from_be_bytes(get_tcp_rst_flag(&buf));
    let syn_flag = u8::from_be_bytes(get_tcp_syn_flag(&buf));
    let fin_flag = u8::from_be_bytes(get_tcp_fin_flag(&buf));
    let window = u16::from_be_bytes(get_tcp_window(&buf));
    let checksum = u16::from_be_bytes(get_tcp_checksum(&buf));
    let urg_ptr = u16::from_be_bytes(get_tcp_urg_ptr(&buf));
    let options_bytes = get_tcp_options(&buf);
    let packet_data = get_tcp_data(&buf);

    println!("TCP PACKET INFO:");

    println!("src_port: {}", src_port);
    println!("dst_port: {}", dst_port);
    println!("seqn: {}", seqn);
    println!("acknum: {}", acknum);
    println!(
        "data_offset: {} * 32 bits = {} bytes",
        data_offset,
        data_offset * 4
    );
    println!("reserved: {}", reserved);
    println!("urg_flag: {}", urg_flag);
    println!("ack_flag: {}", ack_flag);
    println!("psh_flag: {}", psh_flag);
    println!("rst_flag: {}", rst_flag);
    println!("syn_flag: {}", syn_flag);
    println!("fin_flag: {}", fin_flag);
    println!("window: {}", window);
    println!("checksum: {}", checksum);
    println!("urg_ptr: {}", urg_ptr);
    println!(
        "options: {:x?}, length: {} bytes",
        options_bytes,
        options_bytes.len()
    );
    println!(
        "data: {:x?}, length: {} bytes",
        packet_data.to_vec(),
        packet_data.len()
    );
}

/// Returns true if the checksum field matches the header's checksum. Otherwise returns false.
pub fn check_tcp_checksum(buf: &[u8]) -> bool {
    let mut cumulative_sum: u32 = 0;
    let mut current_field = [0; 2];
    for k in (0..20).step_by(2) {
        current_field.copy_from_slice(&buf[k..(k + 2)]);
        cumulative_sum += u16::from_be_bytes(current_field) as u32;
    }

    let checksum: u16 =
        (((cumulative_sum & 0x11110000) >> 4) + (cumulative_sum & 0x00001111)) as u16;
    checksum == 0
}

/* #[cfg(test)]
mod ipv4_tests {
    // use crate::ip_parse::ip_implementation::{
    //     check_ip_checksum, create_ip_datagrams, parse_ip_string_to_bytes,
    // };

    // #[test]
    // fn test_valid_string_to_ipv4_addr() {
}
 */
