//! This is a pure ipv4 datagram parsing library. It doesn't require the parsing to make sense and doesn't
//! use many error checks, unless required for implementaion.
//! the get functions for getting the values of the fields or creating a datagram without any limitations on its correctness.
//!  
//! The implementational library would instead contain implementations for things such as printing ipv4 data, checking checksum,
//! creating ipv4 datagrams by making sure that its fields are correct, parsing datagrams based on the ip version, ...

// pub fn create_ip_header()

/// Returns a full IPv4 datagram as an array of bytes.
pub fn create_raw_ip_datagram(
    version: u8,
    ihl: u8,
    dscp_ecn: u8,
    total_length: u8,
    identification: u16,
    reserved_flag: bool,
    df_flag: bool,
    mf_flag: bool,
    fragment_offset: u16,
    time_to_live: u8,
    protocol: u8,
    header_checksum: u16,
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
    options: &Vec<u8>,
    data: &Vec<u8>,
) -> [u8; 65535] {
    let mut header: [u8; 20] = [0; 20];
    header[0] = (version << 4) | (ihl & 0b00001111); // Ip version and ihl
    header[1] = dscp_ecn;
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(
        &(fragment_offset
            | ((reserved_flag as u16) << 15)
            | ((df_flag as u16) << 14)
            | ((mf_flag as u16) << 13))
            .to_be_bytes(),
    );
    header[8] = time_to_live;
    header[9] = protocol;
    header[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    header[12..16].copy_from_slice(src_addr);
    header[16..20].copy_from_slice(dst_addr);

    let mut result: [u8; 65535] = [0; 65535];
    result[0..20].copy_from_slice(&header);
    result[20..20 + options.len()].copy_from_slice(&options);
    result[20 + options.len()..20 + options.len() + data.len()].copy_from_slice(&data);
    result
}

/// Returns an array of bytes with the created ip datagram.
///
/// * `version` - sets the value of the version field
/// * `ihl` - sets the value of the ihl field
/// * `dscp_ecn` - sets the DSCP and ECN fields. The first six bits correspond to DSCP. The last two bits correspond to ECN.
/// * `total_length` - sets the value total_length field
/// * `identification` - sets the value of the identification field.
/// * `reserved_flag` - sets the value of the reserved field
/// * `df_flag` - sets the Don't fragment bit to 1 if true, 0 if false
/// * `mf_flag` - sets the Don't fragment bit to 1 if true, 0 if false
/// * `fragment_offset` - sets the fragment offset field
/// * `time_to_live` - sets the time to live field
/// * `protocol` - sets the value of the protocol field
/// * `header_checksum` - sets the value of the header checksum field
/// * The `src_addr` and `dst_addr` - sets ip addresses with octets corresponding to the bytes in big endian.
///
/// NOTE: The function doesn't check if the values are correct. The user should make sure that fields such as IHL and total_length match the datagram.
pub fn create_raw_ip_header(
    version: u8,
    ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    reserved_flag: bool,
    df_flag: bool,
    mf_flag: bool,
    fragment_offset: u16,
    time_to_live: u8,
    protocol: u8,
    header_checksum: u16,
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
) -> [u8; 20] {
    let mut header: [u8; 20] = [0; 20];
    header[0] = (version << 4) | (ihl & 0b00001111); // Ip version and ihl
    header[1] = dscp_ecn;
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(
        &(fragment_offset
            | ((reserved_flag as u16) << 15)
            | ((df_flag as u16) << 14)
            | ((mf_flag as u16) << 13))
            .to_be_bytes(),
    );
    header[8] = time_to_live;
    header[9] = protocol;
    header[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    header[12..16].copy_from_slice(src_addr);
    header[16..20].copy_from_slice(dst_addr);

    header
}

/// Returns a full IPv4 datagram as an array of bytes.
/// * `header` - The datagram's header as an array of bytes. Can be created with `create_raw_ip_header`.
/// * `options` - The datagram's options field as an array of bytes.
/// * `data` - The datagram's data field as an array of bytes.
///
/// NOTE: The function doesn't check if the values are correct. The user should make sure that fields such as IHL and total_length match the datagram.
pub fn create_raw_ip_datagram_from_header(
    header: [u8; 20],
    options: &Vec<u8>,
    data: &Vec<u8>,
) -> [u8; 65535] {
    let mut result: [u8; 65535] = [0; 65535];
    result[0..20].copy_from_slice(&header);
    result[20..20 + options.len()].copy_from_slice(&options);
    result[20 + options.len()..20 + options.len() + data.len()].copy_from_slice(&data);
    result
}

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

/// Returns an array with the total length field.
/// Total length is expressed in the number of bytes.
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

/// Returns an array with the reserved flag. Should always be 0.
pub fn get_ip_reserved_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[6] & 0b10000000) >> 7];
    result
}

/// Returns an array with the DF flag (Don't Fragment) as either 1 or 0.
/// If set, prevents fragmentation of the packet. If fragmentation is required to route the datagram through the network,
/// the datagram is dropped.
pub fn get_ip_df_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[6] & 0b01000000) >> 6];
    result
}

/// Returns an array with the MF flag (More Fragments) as either 1 or 0.
/// For unfragmented datagrams, the MF flag is 0. For fragmented datagrams, all fragments
/// except the last one have the MF flag as 1. The last fragment has a non-zero Fragment Offset field,
/// differentiating it from an unfragmented datagram.
pub fn get_ip_mf_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[6] & 0b00100000) >> 5];
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

/// Returns an array in a Result with the options field in the header
/// and the number of bytes that are a part of the options field
/// If the ihl field of the provided header is less than 5, returns an error as the datagram is malformed.
pub fn get_ip_options(buf: &[u8; 65535]) -> (Result<[u8; 60], ()>, usize) {
    let ihl_value = u8::from_be_bytes(get_ip_ihl(buf));

    if ihl_value < 5 {
        return (Err(()), 0);
    }
    let options_bytes = ihl_value as usize * 4 - 20;

    let mut result = [0; 60];
    result[..options_bytes].copy_from_slice(&buf[20..(20 + options_bytes)]);
    return (Ok(result), options_bytes);
}

/// Returns an array with the datagrams data section and the data section's size in bytes.
pub fn get_ip_data(buf: &[u8; 65535]) -> ([u8; 65535], usize) {
    let header_len_in_bytes = (get_ip_ihl(buf)[0] * 4) as usize;
    let datagram_len_in_bytes = u16::from_be_bytes(get_ip_total_len(buf)) as usize;
    let data_len_in_bytes = datagram_len_in_bytes - header_len_in_bytes;

    let mut result: [u8; 65535] = [0; 65535];
    result[..data_len_in_bytes].copy_from_slice(&buf[header_len_in_bytes..datagram_len_in_bytes]);
    (result, data_len_in_bytes)
}

/* pub fn set_header_version(buf: &[u8; 20], new_ver: [u8; 1]) -> () {
    let new_field = buf[&];
    buf[].copy_from_slice(new_ver);
    let result: [u8; 1] = [(buf[0] & 0b11110000) >> 4];
    result
}

pub fn set_header_ihl(buf: &[u8; 20]) -> () {
    let result: [u8; 1] = [buf[0] & 0b00001111];
    result
}

pub fn set_header_tos(buf: &[u8; 20]) -> () {
    let result = [buf[1]];
    result
}

pub fn set_header_dscp(buf: &[u8; 20]) -> () {
    let result = [(buf[1] & 0b11111100) >> 2];
    result
}

pub fn set_header_ecn(buf: &[u8; 20]) -> () {
    let result = [buf[1] & 0b00000011];
    result
}

pub fn set_header_total_len(buf: &[u8; 20]) -> () {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

pub fn set_header_identification(buf: &[u8; 20]) -> () {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[4..6]);
    result
}

pub fn set_header_reserved_flag(buf: &[u8; 20]) -> () {
    let result: [u8; 1] = [(buf[6] & 0b10000000) >> 7];
    result
}

pub fn set_header_df_flag(buf: &[u8; 20]) -> () {
    let result: [u8; 1] = [(buf[6] & 0b01000000) >> 6];
    result
}

pub fn set_header_mf_flag(buf: &[u8; 20]) -> () {
    let result: [u8; 1] = [(buf[6] & 0b00100000) >> 5];
    result
}

pub fn set_header_fragment_offset(buf: &[u8; 20]) -> () {
    let result: [u8; 2] = [((buf[6]) & 0b00011111), buf[7]];
    result
}

pub fn set_header_ttl(buf: &[u8; 20]) -> () {
    let result = [buf[8]];
    result
}

pub fn set_header_protocol(buf: &[u8; 20]) -> () {
    let result = [buf[9]];
    result
} */

pub fn set_header_checksum(header: &mut [u8; 20], checksum: &[u8; 2]) -> () {
    header[10..12].copy_from_slice(checksum);
}

/* pub fn set_header_src_addr(buf: &[u8; 20]) -> () {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[12..16]);
    result
}

pub fn set_header_dst_addr(buf: &[u8; 20]) -> () {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[16..20]);
    result
}

 */
