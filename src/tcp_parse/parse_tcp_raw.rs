pub fn create_raw_tcp_packet(
    src_port: u16,
    dst_port: u16,
    seq_no: u32,
    ack_no: u32,
    data_offset: u8,
    reserved: u8,
    cwr_flag: bool,
    ece_flag: bool,
    urg_flag: bool,
    ack_flag: bool,
    psh_flag: bool,
    rst_flag: bool,
    syn_flag: bool,
    fin_flag: bool,
    window_size: u16,
    checksum: u16,
    urg_ptr: u16,
    options: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut header = create_raw_tcp_header(
        src_port,
        dst_port,
        seq_no,
        ack_no,
        data_offset,
        reserved,
        cwr_flag,
        ece_flag,
        urg_flag,
        ack_flag,
        psh_flag,
        rst_flag,
        syn_flag,
        fin_flag,
        window_size,
        checksum,
        urg_ptr,
        options,
    );
    header.extend(data);

    header
}

pub fn create_raw_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq_no: u32,
    ack_no: u32,
    data_offset: u8,
    reserved: u8,
    cwr_flag: bool,
    ece_flag: bool,
    urg_flag: bool,
    ack_flag: bool,
    psh_flag: bool,
    rst_flag: bool,
    syn_flag: bool,
    fin_flag: bool,
    window_size: u16,
    checksum: u16,
    urg_ptr: u16,
    options: &[u8],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(20 + options.len());
    header.extend(src_port.to_be_bytes());
    header.extend(dst_port.to_be_bytes());
    header.extend(seq_no.to_be_bytes());
    header.extend(ack_no.to_be_bytes());
    header.push((data_offset << 4) | (reserved & 0b00001111));
    header.push(
        (cwr_flag as u8) << 7
            | (ece_flag as u8) << 6
            | (urg_flag as u8) << 5
            | (ack_flag as u8) << 4
            | (psh_flag as u8) << 3
            | (rst_flag as u8) << 2
            | (syn_flag as u8) << 1
            | (fin_flag as u8),
    );
    header.extend(window_size.to_be_bytes());
    header.extend(checksum.to_be_bytes());
    header.extend(urg_ptr.to_be_bytes());
    header.extend(options);

    header
}

/// Returns an array with the source port number
pub fn get_tcp_src_port(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[0..2]);
    result
}

/// Returns an array with the destination port number
pub fn get_tcp_dst_port(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

/// Returns an array with the sequence number of the first byte in this segment
/// If SYN bit is present, the sequence number is the initial sequence number (ISN)
pub fn get_tcp_seqnum(buf: &[u8]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[4..8]);
    result
}

/// Return an array with the next sequence number the sender of the segment is expecting
/// if the ACK control bit is 1.
pub fn get_tcp_acknum(buf: &[u8]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[8..12]);
    result
}

/// Returns an array with the number of 32 bit words in the TCP Header
pub fn get_tcp_data_offset(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[12] & 0b11110000) >> 4];
    result
}

/// Returns an array with the reserved field. Must be set to zeros.
pub fn get_tcp_4bit_reserved(buf: &[u8]) -> [u8; 1] {
    let result = [((buf[12] & 0b00001111) << 2)];
    result
}

pub fn get_tcp_6bit_reserved(buf: &[u8]) -> [u8; 1] {
    let result = [((buf[12] & 0b00001111) << 2) + ((buf[13] & 0b11000000) >> 6)];
    result
}

/// Returns an array with the URG flag
pub fn get_tcp_cwr_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b10000000) >> 7];
    result
}

/// Returns an array with the URG flag
pub fn get_tcp_ece_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b01000000) >> 6];
    result
}

/// Returns an array with the URG flag
pub fn get_tcp_urg_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b00100000) >> 5];
    result
}

/// Returns an array with the ACK flag
pub fn get_tcp_ack_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b00010000) >> 4];
    result
}

/// Returns an array with the PSH flag
pub fn get_tcp_psh_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b00001000) >> 3];
    result
}

/// Returns an array with the RST flag
pub fn get_tcp_rst_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b00000100) >> 2];
    result
}

/// Returns an array with the SYN flag
pub fn get_tcp_syn_flag(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[13] & 0b00000010) >> 1];
    result
}

/// Returns an array with the FIN flag
pub fn get_tcp_fin_flag(buf: &[u8]) -> [u8; 1] {
    let result = [buf[13] & 0b00000001];
    result
}

/// Returns an array with the number of bytes that the the receiver is currently prepared to accept.
/// Simply the a omount of available space in the receiver's buffer for incoming data.
pub fn get_tcp_window(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[14..16]);
    result
}

/// Returns an array with the checksum of the TCP header
pub fn get_tcp_checksum(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[16..18]);
    result
}

/// Returns an array with the value of the urgent pointer field.
/// Used to inform the recipient about there being urgent data bytes in the segment and that the receiver
/// should prioritize processing these bytes.
/// Indicates the position of the next byte of data that is not considered urgent.
pub fn get_tcp_urg_ptr(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[18..20]);
    result
}

/// Returns an array with the value of the options field and the size of the options included in the header.
pub fn get_tcp_options(buf: &[u8]) -> Vec<u8> {
    let header_len_in_bytes = (get_tcp_data_offset(&buf)[0] as u32 * 4) as usize;
    let option_len_in_bytes = header_len_in_bytes - 20 as usize;

    let mut result = Vec::with_capacity(option_len_in_bytes);
    result.extend(&buf[20..header_len_in_bytes]);
    result
}

/// Takes as arguemnts the TCP packet as an array of bytes and the number of bytes in the TCP packet
/// calculated as total length in IP header - length of IP header.
/// Returns an array containing the data field of the TCP packet and the length of data in the data field.
pub fn get_tcp_data(buf: &[u8]) -> Vec<u8> {
    let header_len_in_bytes = (get_tcp_data_offset(&buf)[0] as u32 * 4) as usize;
    let packet_len_in_bytes = buf.len();

    let mut result = Vec::with_capacity(packet_len_in_bytes - header_len_in_bytes);
    result.extend(&buf[header_len_in_bytes..packet_len_in_bytes]);
    result
}

/// Sets the value of the checksum field in the provided tcp packet to `new_checksum`
pub fn set_tcp_checksum(buf: &mut [u8], new_checksum: &[u8; 2]) -> () {
    buf[16..18].copy_from_slice(new_checksum)
}

#[cfg(test)]
mod ipv4_tests {
    use crate::tcp_parse::parse_tcp_raw::*;

    #[test]
    fn test_tcp_getters() {
        let tcp_packet = create_raw_tcp_packet(
            1234,
            2345,
            100,
            200,
            5,
            0,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            false,
            8000,
            0,
            0,
            "".as_bytes(),
            "Hello world!".as_bytes(),
        );
        let src_port = u16::from_be_bytes(get_tcp_src_port(&tcp_packet));
        assert!(src_port == 1234);
        let dst_port = u16::from_be_bytes(get_tcp_dst_port(&tcp_packet));
        assert!(dst_port == 2345);

        let seq_no = u32::from_be_bytes(get_tcp_seqnum(&tcp_packet));
        assert!(seq_no == 100);
        let ack_no = u32::from_be_bytes(get_tcp_acknum(&tcp_packet));
        assert!(ack_no == 200);

        let data_offset = u8::from_be_bytes(get_tcp_data_offset(&tcp_packet));
        assert!(data_offset == 5);
        let reserved1 = u8::from_be_bytes(get_tcp_4bit_reserved(&tcp_packet));
        assert!(reserved1 == 0);
        let reserved2 = u8::from_be_bytes(get_tcp_6bit_reserved(&tcp_packet));
        assert!(reserved2 == 2);

        let cwr_flag = u8::from_be_bytes(get_tcp_cwr_flag(&tcp_packet));
        assert!(cwr_flag == 1);
        let ece_flag = u8::from_be_bytes(get_tcp_ece_flag(&tcp_packet));
        assert!(ece_flag == 0);
        let urg_flag = u8::from_be_bytes(get_tcp_urg_flag(&tcp_packet));
        assert!(urg_flag == 1);
        let ack_flag = u8::from_be_bytes(get_tcp_ack_flag(&tcp_packet));
        assert!(ack_flag == 0);
        let psh_flag = u8::from_be_bytes(get_tcp_psh_flag(&tcp_packet));
        assert!(psh_flag == 1);
        let rst_flag = u8::from_be_bytes(get_tcp_rst_flag(&tcp_packet));
        assert!(rst_flag == 0);
        let syn_flag = u8::from_be_bytes(get_tcp_syn_flag(&tcp_packet));
        assert!(syn_flag == 1);
        let fin_flag = u8::from_be_bytes(get_tcp_fin_flag(&tcp_packet));
        assert!(fin_flag == 0);

        let window_size = u16::from_be_bytes(get_tcp_window(&tcp_packet));
        assert!(window_size == 8000);
        let checksum = u16::from_be_bytes(get_tcp_checksum(&tcp_packet));
        assert!(checksum == 0);
        let urg_ptr = u16::from_be_bytes(get_tcp_urg_ptr(&tcp_packet));
        assert!(urg_ptr == 0);

        let options = get_tcp_options(&tcp_packet);
        assert!(options.len() == 0);
        let data = get_tcp_data(&tcp_packet);
        assert!(data == "Hello world!".as_bytes());
    }
}
