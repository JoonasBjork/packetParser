/// Returns an array with the source port number
pub fn get_tcp_src_port(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[0..2]);
    result
}

/// Returns an array with the destination port number
pub fn get_tcp_dst_port(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

/// Returns an array with the sequence number of the first byte in this segment
/// If SYN bit is present, the sequence number is the initial sequence number (ISN)
pub fn get_tcp_seqn(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[4..8]);
    result
}

/// Return an array with the next sequence number the sender of the segment is expecting
/// if the ACK control bit is 1.
pub fn get_tcp_acknum(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[8..12]);
    result
}

/// Returns an array with the number of 32 bit words in the TCP Header
pub fn get_tcp_data_offset(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [(buf[12] & 0b11110000) >> 4];
    result
}

/// Returns an array with the reserved field. Must be set to zeros.
pub fn get_tcp_reserved(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [((buf[12] & 0b00001111) << 2) + ((buf[13] & 0b11000000) >> 6)];
    result
}

/// Returns an array with the URG flag
pub fn get_tcp_urg_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00100000 >> 5];
    result
}

/// Returns an array with the ACK flag
pub fn get_tcp_ack_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00010000 >> 4];
    result
}

/// Returns an array with the PSH flag
pub fn get_tcp_psh_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00001000 >> 3];
    result
}

/// Returns an array with the RST flag
pub fn get_tcp_rst_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00000100 >> 2];
    result
}

/// Returns an array with the SYN flag
pub fn get_tcp_syn_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00000010 >> 1];
    result
}

/// Returns an array with the FIN flag
pub fn get_tcp_fin_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00000001];
    result
}

/// Returns an array with the number of bytes that the the receiver is currently prepared to accept.
/// Simply the a omount of available space in the receiver's buffer for incoming data.
pub fn get_tcp_window(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[14..16]);
    result
}

/// Returns an array with the checksum of the TCP header
pub fn get_tcp_checksum(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[16..18]);
    result
}

/// Returns an array with the value of the urgent pointer field.
/// Used to inform the recipient about there being urgent data bytes in the segment and that the receiver
/// should prioritize processing these bytes.
/// Indicates the position of the next byte of data that is not considered urgent.
pub fn get_tcp_urg_ptr(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[18..20]);
    result
}

/// Returns an array with the value of the options field and the size of the options included in the header.
pub fn get_tcp_options(buf: &[u8; 65535]) -> ([u8; 40], usize) {
    let header_len_in_bytes = (get_tcp_data_offset(&buf)[0] as u32 * 4) as usize;
    let option_len = header_len_in_bytes - 20 as usize;

    let mut result = [0; 40];
    result[..option_len].copy_from_slice(&buf[20..header_len_in_bytes]);
    (result, option_len)
}

pub fn print_tcp_data(buf: &[u8; 65535]) -> () {
    let src_port = u16::from_be_bytes(get_tcp_src_port(&buf));
    let dst_port = u16::from_be_bytes(get_tcp_src_port(&buf));
    let seqn = u32::from_be_bytes(get_tcp_seqn(&buf));
    let acknum = u32::from_be_bytes(get_tcp_acknum(&buf));
    let data_offset = u8::from_be_bytes(get_tcp_data_offset(&buf));
    let urg_flag = u8::from_be_bytes(get_tcp_urg_flag(&buf));
    let ack_flag = u8::from_be_bytes(get_tcp_ack_flag(&buf));
    let psh_flag = u8::from_be_bytes(get_tcp_psh_flag(&buf));
    let rst_flag = u8::from_be_bytes(get_tcp_rst_flag(&buf));
    let syn_flag = u8::from_be_bytes(get_tcp_syn_flag(&buf));
    let fin_flag = u8::from_be_bytes(get_tcp_fin_flag(&buf));
    let window = u16::from_be_bytes(get_tcp_window(&buf));
    let checksum = u16::from_be_bytes(get_tcp_checksum(&buf));
    let urg_ptr = u16::from_be_bytes(get_tcp_urg_ptr(&buf));
    let (options_bytes, options_bytes_length) = get_tcp_options(&buf);

    println!("TCP PACKET INFO:");

    println!("src_port: {}", src_port);
    println!("dst_port: {}", dst_port);
    println!("seqn: {}", seqn);
    println!("acknum: {}", acknum);
    println!("data_offset: {}", data_offset);
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
        "options: {:x?}, length: {}",
        options_bytes, options_bytes_length
    );
}
