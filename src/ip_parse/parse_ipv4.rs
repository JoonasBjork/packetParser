use crate::ip_parse::parse_tables;

/// Returns an array with ip version in the datagram
pub fn get_ip_version(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[0] & 0b11110000) >> 4];
    result
}

/// Returns an array with the header size of the ip datagram
pub fn get_ip_ihl(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [buf[0] & 0b00001111];
    result
}

/// Returns an array with the type of service field
pub fn get_ip_tos(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[1]];
    result
}

/// Returns an array with the DSCP field,
/// which contains information about differentiated services
pub fn get_ip_dscp(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [(buf[1] & 0b11111100) >> 2];
    result
}

/// Return an array with the ECN field,
/// which contains end-to-end notification of network congestion
/// without dropping datagrams
pub fn get_ip_ecn(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[1] & 0b00000011];
    result
}

/// Returns an array with the total length field,
/// which contains information about what the total size of the ip datagram is.
pub fn get_ip_total_len(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

/// Returns an array with the
pub fn get_ip_identification(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[4..6]);
    result
}

/// Returns an array with the DF flag (Don't Fragment) as either 1 or 0.
/// If set, and fragmentation is required to route the datagram, the datagram is dropped.
pub fn get_ip_df_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [buf[6] & 0b01000000 >> 6];
    result
}

/// Returns an array with the MF flag (More Fragments) as either 1 or 0.
/// For unfragmented datagrams, the MF flag is 0. For fragmented datagrams, all fragments
/// except the last one have the MF flag as 1. The last fragment has a non-zero Fragment Offset field,
/// differentiating it from an unfragmented datagram.
pub fn get_ip_mf_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [buf[6] & 0b00100000 >> 5];
    result
}

/// Return an array with the fragment offset field.
/// The fragment offset field specifies the offset of a particular fragment
/// relative to the beginning of the original unfragmented IP datagram.
/// Always 0 for the first fragment.
pub fn get_ip_fragment_offset(buf: &[u8; 65535]) -> [u8; 2] {
    let result: [u8; 2] = [((buf[6]) & 0b00011111), buf[7]];
    result
}

/// Returns an array with the time to live field.
/// Limits the nubmer of hops that a datagram can travel
pub fn get_ip_ttl(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[8]];
    result
}

/// Returns an array with the protocol used in the data portion of the ip datagram.
/// For reference https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
pub fn get_ip_protocol(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[9]];
    result
}

/// Returns an array with the IPv4 header checksum field.  
pub fn get_ip_checksum(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[10..12]);
    result
}

/// Returns an array with the senders IPv4 address
pub fn get_ip_src_addr(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[12..16]);
    result
}

/// Returns an array with the recipients IPv4 address
pub fn get_ip_dst_addr(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[16..20]);
    result
}

/// Returns an array with the options field in the header
/// and the number of bytes that are a part of the options field
pub fn get_ip_options(buf: &[u8; 65535]) -> ([u8; 60], usize) {
    let ihl_value = get_ip_ihl(buf)[0];

    if ihl_value < 5 {
        return ([0; 60], 0 as usize);
    }
    let options_bytes = ihl_value as usize * 4;

    let mut result = [0; 60];
    result[..options_bytes].copy_from_slice(&buf[20..(20 + options_bytes)]);
    return (result, options_bytes);
}

/// Returns an array with the datagrams data section and the data section's size.
pub fn get_ip_data(buf: &[u8; 65535]) -> ([u8; 65535], usize) {
    let header_len = (get_ip_ihl(buf)[0] * 4) as usize;
    let datagram_len = u16::from_be_bytes(get_ip_total_len(buf)) as usize;
    let data_len = datagram_len - header_len;

    let mut result: [u8; 65535] = [0; 65535];
    result[..(data_len)].copy_from_slice(&buf[header_len..(datagram_len)]);
    (result, data_len)
}

pub fn print_ip_data(buf: &[u8; 65535]) -> () {
    let ip_version = u8::from_be_bytes(get_ip_version(&buf));
    let ip_ihl = u8::from_be_bytes(get_ip_ihl(&buf));
    let ip_tos = u8::from_be_bytes(get_ip_tos(&buf));
    let ip_dscp = u8::from_be_bytes(get_ip_dscp(&buf));
    let ip_ecn = u8::from_be_bytes(get_ip_ecn(&buf));
    let ip_total_len = u16::from_be_bytes(get_ip_total_len(&buf));
    let ip_id = u16::from_be_bytes(get_ip_identification(&buf));
    let ip_df = u8::from_be_bytes(get_ip_df_flag(&buf));
    let ip_mf = u8::from_be_bytes(get_ip_mf_flag(&buf));
    let ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&buf));
    let ip_ttl = u8::from_be_bytes(get_ip_ttl(&buf));
    let ip_proto = u8::from_be_bytes(get_ip_protocol(&buf));
    let ip_checksum = u16::from_be_bytes(get_ip_checksum(&buf));
    let ip_src_addr = get_ip_src_addr(&buf);
    let ip_dst_addr = get_ip_dst_addr(&buf);
    let ip_opts = get_ip_options(&buf);
    let (ip_data, ip_data_len) = get_ip_data(&buf);

    println!("IP DATAGRAM INFO:");

    println!("ip_version: {:x?}", ip_version);
    println!("ip_ihl: {:x?}", ip_ihl);
    println!("ip_tos: {:x?}", ip_tos);
    println!("ip_dscp: {:x?}", ip_dscp);
    println!("ip_ecn: {:x?}", ip_ecn);
    println!("ip_tl: {:?}", ip_total_len);
    println!("ip_id: {:x?}", ip_id);
    println!("ip_df: {:x?}", ip_df);
    println!("ip_mf: {:x?}", ip_mf);
    println!("ip_fragment_offset: {:x?}", ip_fragment_offset);
    println!("ip_ttl: {:x?}", ip_ttl);
    println!(
        "ip_proto: {:x?}, {:?}",
        ip_proto,
        parse_tables::get_proto_name(ip_proto)
    );
    println!("ip_checksum: {:x?}", ip_checksum);
    println!("ip_src_addr: {:?}", ip_src_addr);
    println!("ip_dst_addr: {:?}", ip_dst_addr);
    println!("ip_opts: {:x?}", ip_opts);
    println!("ip_data: {:x?}", ip_data[..ip_data_len].to_vec());
}

/// Returns True if the checksum field matches the header's checksum
pub fn check_ip_checksum(buf: &[u8; 65535]) -> bool {
    let mut cumulative_sum: u32 = 0;
    let mut current_field = [0; 2];
    for k in (0..20).step_by(2) {
        current_field.copy_from_slice(&buf[k..(k + 2)]);
        cumulative_sum += u16::from_be_bytes(current_field) as u32;
    }

    let checksum: u16 = ((cumulative_sum & 0x11110000) >> 4 + (cumulative_sum & 0x00001111)) as u16;
    checksum == 0
}

pub struct DatagramError(pub Vec<String>);

impl DatagramError {
    fn new() -> Self {
        DatagramError(Vec::new())
    }

    fn push(&mut self, error_message: &str) {
        self.0.push(error_message.to_string());
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Validates the entire datagram for if it is valid
pub fn validate_full_ip_datagram(buf: &[u8; 65535]) -> Result<(), DatagramError> {
    let mut datagram_errors = DatagramError::new();
    if !check_ip_checksum(buf) {
        datagram_errors.push("Datagram header checksum doesn't match");
    }

    if get_ip_version(&buf)[0] != 4 as u8 {
        datagram_errors.push("Datagram ip version doesn't match 4");
    }

    if get_ip_ttl(&buf)[0] < 1 as u8 {
        datagram_errors.push("Datagram Time to live is less than 1");
    }

    match parse_tables::get_proto_name(u8::from_be_bytes(get_ip_protocol(&buf))) {
        None => datagram_errors.push("Datagram protocol is unknown"),
        Some(_) => (),
    }

    if u8::from_be_bytes(get_ip_df_flag(&buf)) == 1 as u8
        && u16::from_be_bytes(get_ip_fragment_offset(&buf)) == 0
    {
        datagram_errors
            .push("Datagram Don't fragment flag is set to 1 but fragment offset is not zero")
    }

    if datagram_errors.is_empty() {
        return Ok(());
    }
    Err(datagram_errors)
}
