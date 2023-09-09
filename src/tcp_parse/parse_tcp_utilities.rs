use crate::ip_parse::parse_ip_utilities::{validate_full_ip_datagram, DatagramError};
use crate::ip_parse::parse_ipv4_raw::{
    get_ip_data, get_ip_dst_addr, get_ip_protocol, get_ip_src_addr,
};
use crate::tcp_parse::parse_tcp_raw::*;

pub struct TCPError(pub Vec<String>);

impl TCPError {
    pub fn new() -> Self {
        TCPError(Vec::new())
    }

    pub fn push(&mut self, error_message: &str) {
        self.0.push(error_message.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Validates that the TCP packet has correct structure
pub fn validate_tcp_packet(tcp_packet: &[u8]) -> Result<(), TCPError> {
    let mut tcp_error = TCPError::new();
    if tcp_packet.len() < 20 {
        tcp_error.push("TCP packet is too short (<20 bytes)")
    }
    if check_tcp_checksum(tcp_packet) {
        tcp_error.push("TCP packet checksum doesn't match")
    }

    if tcp_error.is_empty() {
        return Ok(());
    }
    if u8::from_be_bytes(get_tcp_data_offset(tcp_packet)) < 5 {
        tcp_error.push("Data offset is less than 5")
    }
    Err(tcp_error)
}
// pub fn create_tcp_packet() -> Vec<u8> {

// }

/// Prints out information about the supplied TCP packet.
pub fn print_tcp_data(buf: &[u8]) -> () {
    let src_port = u16::from_be_bytes(get_tcp_src_port(&buf));
    let dst_port = u16::from_be_bytes(get_tcp_dst_port(&buf));
    let seqn = u32::from_be_bytes(get_tcp_seqnum(&buf));
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

/// Returns the value that the checksum field should be set to with the current header

/// Returns true if the checksum field matches the header's checksum. Otherwise returns false.
pub fn check_tcp_checksum(buf: &[u8]) -> bool {
    // let mut sum: u16 = 0;
    // let mut current_field = [0; 2];
    // for k in (0..20).step_by(2) {
    //     current_field.copy_from_slice(&buf[k..k + 2]);

    //     let next_field_value = u16::from_be_bytes(current_field);
    //     sum = match sum.checked_add(next_field_value) {
    //         Some(s) => s,
    //         None => sum.wrapping_add(next_field_value.wrapping_add(1)),
    //     }
    // }

    // let checksum = !sum;
    // checksum == 0
    false
}

/// Calculates and returns the checksum field of the tcp header.
/// * NOTE: Skips over the checksum field of the `tcp_packet` parameter
pub fn calculate_tcp_checksum(
    src_ip_addr: &[u8; 4],
    dst_ip_addr: &[u8; 4],
    reserved: &[u8; 1],
    protocol: &[u8; 1],
    tcp_packet: &[u8],
) -> Result<[u8; 2], TCPError> {
    let mut tcp_error = TCPError::new();
    if protocol[0] != 6 {
        tcp_error.push("TCP packet protocol is not 6")
    }
    if reserved[0] != 0 {
        tcp_error.push("TCP reserved is not 0")
    }
    if tcp_packet.len() < 20 {
        tcp_error.push("TCP packet is less that 20 bytes")
    }

    if !tcp_error.is_empty() {
        return Err(tcp_error);
    }

    let pseudo_ip_header: Vec<u8> = [
        src_ip_addr.as_slice(),
        dst_ip_addr.as_slice(),
        reserved.as_slice(),
        protocol.as_slice(),
        tcp_packet.len().to_be_bytes().as_slice(),
    ]
    .concat()
    .into_iter()
    .collect();

    let mut sum: u16 = 0;
    let mut current_field = [0; 2];
    for k in (0..12).step_by(2) {
        current_field.copy_from_slice(&pseudo_ip_header[k..k + 2]);

        let next_field_value = u16::from_be_bytes(current_field);
        sum = match sum.checked_add(next_field_value) {
            Some(s) => s,
            None => sum.wrapping_add(next_field_value.wrapping_add(1)),
        }
    }

    // Pad the tcp_packet if needed
    let mut tcp_packet_iter = tcp_packet.iter().chain(std::iter::once(&0));
    // Set the iterator lengths based on if the length of data is even.
    let tcp_packet_iter_len = if tcp_packet.len() % 2 == 1 {
        tcp_packet.len() + 1
    } else {
        tcp_packet.len()
    };

    for k in (0..tcp_packet_iter_len).step_by(2) {
        let current_bytes: [u8; 2] = [
            *(tcp_packet_iter.next().unwrap()),
            *(tcp_packet_iter.next().unwrap()),
        ];
        current_field.copy_from_slice(&current_bytes);

        let next_field_value = u16::from_be_bytes(current_field);
        sum = match sum.checked_add(next_field_value) {
            Some(s) => s,
            None => sum.wrapping_add(next_field_value.wrapping_add(1)),
        }
    }

    Ok(sum.to_be_bytes())
}

/// Returns the calculated TCP checksum
/// * `ip_datagram` - Full IP datagram with ip header and ip data
pub fn calculate_tcp_checksum_from_ip_datagram(
    ip_datagram: &[u8],
) -> Result<[u8; 2], DatagramError> {
    if let Err(validation) = validate_full_ip_datagram(ip_datagram) {
        return Err(validation);
    }
    let checksum = calculate_tcp_checksum(
        &get_ip_src_addr(ip_datagram),
        &get_ip_dst_addr(ip_datagram),
        &[0],
        &get_ip_protocol(ip_datagram),
        &get_ip_data(ip_datagram),
    );
    match checksum {
        Ok(cs) => return Ok(cs),
        Err(err) => {
            let mut dge = DatagramError::new();
            dge.push("Found errors in TCP packet");
            // Add all found TCP errors to the returned DatagramError
            err.0.iter().for_each(|e| dge.push(e));
            return Err(dge);
        }
    }
}

#[cfg(test)]
mod ipv4_tests {
    use crate::{
        ip_parse::parse_ip_utilities::create_ip_datagrams,
        tcp_parse::parse_tcp_utilities::calculate_tcp_checksum_from_ip_datagram,
    };

    #[test]
    fn test_valid_string_to_ipv4_addr() {
        let mut identifier = 10;
        let mut ip_datagrams = match create_ip_datagrams(
            0b00000000,
            false,
            30,
            6,
            &[192, 168, 0, 2],
            &[192, 168, 0, 3],
            &Vec::new(), // Add after support for options exists
            &"Hello world!".as_bytes().to_vec(),
            5000,
            &mut identifier,
        ) {
            Ok(datagrams) => datagrams,
            Err(e) => {
                let errors = e.0.join("\n");
                panic!("Faced errors in datagram creation: \n{}", errors)
            }
        };

        assert!(ip_datagrams.len() == 1);
        let datagram = ip_datagrams.remove(0);
        match calculate_tcp_checksum_from_ip_datagram(&datagram) {
            Ok(cs) => println!("Found checksum: {}", u16::from_be_bytes(cs)),
            Err(err) => {
                err.0.iter().for_each(|e| println!("{}", e));
                panic!("Calculating checksum for good datagram should not throw error")
            }
        }
    }
}
