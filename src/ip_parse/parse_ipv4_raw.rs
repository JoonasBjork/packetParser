//! This is a pure ipv4 datagram parsing library. It doesn't require the parsing to make sense and doesn't
//! use many error checks, unless required for implementaion.
//! the get functions for getting the values of the fields or creating a datagram without any limitations on its correctness.
//!  
//! The implementational library would instead contain implementations for things such as printing ipv4 data, checking checksum,
//! creating ipv4 datagrams by making sure that its fields are correct, parsing datagrams based on the ip version, ...
/// Error data structure, can contain many errors so that all known errors can be returned at once.

/// Returns a full IPv4 datagram as an array of bytes.
pub fn create_raw_ip_datagram(
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
    options: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut header = create_raw_ip_header(
        version,
        ihl,
        dscp_ecn,
        total_length,
        identification,
        reserved_flag,
        df_flag,
        mf_flag,
        fragment_offset,
        time_to_live,
        protocol,
        header_checksum,
        src_addr,
        dst_addr,
        options,
    );

    header.extend(data);
    header
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
    options: &[u8],
) -> Vec<u8> {
    let mut header: Vec<u8> = Vec::with_capacity(20 + options.len());
    header.push((version << 4) | (ihl & 0b00001111)); // Ip version and ihl, idx 0
    header.push(dscp_ecn); // idx 1
    header.extend(&total_length.to_be_bytes());
    header.extend(&identification.to_be_bytes());
    header.extend(
        &(fragment_offset
            | ((reserved_flag as u16) << 15)
            | ((df_flag as u16) << 14)
            | ((mf_flag as u16) << 13))
            .to_be_bytes(),
    );
    header.push(time_to_live); // idx 8
    header.push(protocol); // idx 9
    header.extend(&header_checksum.to_be_bytes());
    header.extend(src_addr);
    header.extend(dst_addr);
    header.extend(options);

    header
}

/* /// Returns a full IPv4 datagram as an array of bytes.
/// * `header` - The datagram's header as an array of bytes. Can be created with `create_raw_ip_header`.
/// * `options` - The datagram's options field as an array of bytes.
/// * `data` - The datagram's data field as an array of bytes.
///
/// NOTE: The function doesn't check if the values are correct. The user should make sure that fields such as IHL and total_length match the datagram.
pub fn create_raw_ip_datagram_from_header(
    header: &[u8; 20],
    options: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(20 + options.len() + data.len());
    result.extend(header);
    result.extend(options);
    result.extend(data);
    result
} */

/// Returns an array with ip version in the datagram
pub fn get_ip_version(buf: &[u8]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[0] & 0b11110000) >> 4];
    result
}

/// Returns an array with the header size of the ip datagram
pub fn get_ip_ihl(buf: &[u8]) -> [u8; 1] {
    let result: [u8; 1] = [buf[0] & 0b00001111];
    result
}

/// Returns an array with the type of service field
pub fn get_ip_tos(buf: &[u8]) -> [u8; 1] {
    let result = [buf[1]];
    result
}

/// Returns an array with the DSCP field,
/// which contains information about differentiated services
pub fn get_ip_dscp(buf: &[u8]) -> [u8; 1] {
    let result = [(buf[1] & 0b11111100) >> 2];
    result
}

/// Return an array with the ECN field,
/// which contains end-to-end notification of network congestion
/// without dropping datagrams
pub fn get_ip_ecn(buf: &[u8]) -> [u8; 1] {
    let result = [buf[1] & 0b00000011];
    result
}

/// Returns an array with the total length field.
/// Total length is expressed in the number of bytes.
pub fn get_ip_total_len(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

/// Returns an array with the
pub fn get_ip_identification(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[4..6]);
    result
}

/// Returns an array with the reserved flag. Should always be 0.
pub fn get_ip_reserved_flag(buf: &[u8]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[6] & 0b10000000) >> 7];
    result
}

/// Returns an array with the DF flag (Don't Fragment) as either 1 or 0.
/// If set, prevents fragmentation of the packet. If fragmentation is required to route the datagram through the network,
/// the datagram is dropped.
pub fn get_ip_df_flag(buf: &[u8]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[6] & 0b01000000) >> 6];
    result
}

/// Returns an array with the MF flag (More Fragments) as either 1 or 0.
/// For unfragmented datagrams, the MF flag is 0. For fragmented datagrams, all fragments
/// except the last one have the MF flag as 1. The last fragment has a non-zero Fragment Offset field,
/// differentiating it from an unfragmented datagram.
pub fn get_ip_mf_flag(buf: &[u8]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[6] & 0b00100000) >> 5];
    result
}

/// Return an array with the fragment offset field.
/// The fragment offset field specifies the offset of a particular fragment
/// relative to the beginning of the original unfragmented IP datagram.
/// Always 0 for the first fragment.
pub fn get_ip_fragment_offset(buf: &[u8]) -> [u8; 2] {
    let result: [u8; 2] = [((buf[6]) & 0b00011111), buf[7]];
    result
}

/// Returns an array with the time to live field.
/// Limits the nubmer of hops that a datagram can travel
pub fn get_ip_ttl(buf: &[u8]) -> [u8; 1] {
    let result = [buf[8]];
    result
}

/// Returns an array with the protocol used in the data portion of the ip datagram.
/// For reference https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
pub fn get_ip_protocol(buf: &[u8]) -> [u8; 1] {
    let result = [buf[9]];
    result
}

/// Returns an array with the IPv4 header checksum field.  
pub fn get_ip_checksum(buf: &[u8]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[10..12]);
    result
}

/// Returns an array with the senders IPv4 address
pub fn get_ip_src_addr(buf: &[u8]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[12..16]);
    result
}

/// Returns an array with the recipients IPv4 address
pub fn get_ip_dst_addr(buf: &[u8]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[16..20]);
    result
}

/// Returns an array in a Result with the options field in the header
/// and the number of bytes that are a part of the options field
/// If the ihl field of the provided header is less than 5, returns an error as the datagram is malformed.
pub fn get_ip_options(buf: &[u8]) -> (Result<[u8; 60], ()>, usize) {
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
pub fn get_ip_data(buf: &[u8]) -> Vec<u8> {
    let header_len_in_bytes = (get_ip_ihl(buf)[0] * 4) as usize;
    let datagram_len_in_bytes = u16::from_be_bytes(get_ip_total_len(buf)) as usize;

    let mut result: Vec<u8> = Vec::with_capacity(datagram_len_in_bytes - header_len_in_bytes);
    result.extend(&buf[header_len_in_bytes..datagram_len_in_bytes]);
    result
}

pub fn set_header_version(header: &mut [u8], new_ver: &[u8; 1]) -> () {
    header[0] = (new_ver[0] << 4) | (header[0] & 0b00001111);
}

pub fn set_header_ihl(header: &mut [u8], new_ihl: &[u8; 1]) -> () {
    header[0] = (header[0] & 0b11110000) | (new_ihl[0] & 0b00001111);
}

pub fn set_header_tos(header: &mut [u8], new_tos: &[u8; 1]) -> () {
    header[1] = new_tos[0];
}

pub fn set_header_dscp(header: &mut [u8], new_dscp: &[u8; 1]) -> () {
    header[1] = (new_dscp[0] << 2) | (header[1] & 0b00000011)
}

pub fn set_header_ecn(header: &mut [u8], new_ecn: &[u8; 1]) -> () {
    header[1] = (header[1] & 0b11111100) | (new_ecn[0] & 0b00000011);
}

pub fn set_header_total_len(header: &mut [u8], new_total_len: &[u8; 2]) -> () {
    header[2..4].copy_from_slice(new_total_len);
}

pub fn set_header_identification(header: &mut [u8], new_identification: &[u8; 2]) -> () {
    header[4..6].copy_from_slice(new_identification);
}

pub fn set_header_reserved_flag(header: &mut [u8], new_res_flag: bool) -> () {
    header[6] = if new_res_flag {
        header[6] | 0b10000000
    } else {
        header[6] & 0b01111111
    };
}

pub fn set_header_df_flag(header: &mut [u8], new_df_flag: bool) -> () {
    header[6] = if new_df_flag {
        header[6] | 0b01000000
    } else {
        header[6] & 0b10111111
    };
}

pub fn set_header_mf_flag(header: &mut [u8], new_mf_flag: bool) -> () {
    header[6] = if new_mf_flag {
        header[6] | 0b00100000
    } else {
        header[6] & 0b11011111
    };
}

/// Only modifies the bits that belong to the fragment offset field. Doesn't leak into other fields.
pub fn set_header_fragment_offset(header: &mut [u8], new_fragment_offset: &[u8; 2]) -> () {
    let current_flags = header[6] & 0b11100000;
    header[6..8].copy_from_slice(&[
        current_flags | (new_fragment_offset[0] & 0b00011111),
        new_fragment_offset[1],
    ]);
}

pub fn set_header_ttl(header: &mut [u8], new_time_to_live: &[u8; 1]) -> () {
    header[8] = new_time_to_live[0];
}

pub fn set_header_protocol(header: &mut [u8], new_protocol: &[u8; 1]) -> () {
    header[9] = new_protocol[0];
}

pub fn set_header_checksum(header: &mut [u8], checksum: &[u8; 2]) -> () {
    header[10..12].copy_from_slice(checksum);
}

pub fn set_header_src_addr(header: &mut [u8], new_src_addr: &[u8; 4]) -> () {
    header[12..16].copy_from_slice(new_src_addr);
}

pub fn set_header_dst_addr(header: &mut [u8], new_dst_addr: &[u8; 4]) -> () {
    header[16..20].copy_from_slice(new_dst_addr);
}

#[cfg(test)]
mod ipv4_raw_tests {

    use crate::ip_parse::parse_ipv4_raw::*;

    #[test]
    fn test_raw_ipv4_header() {
        let mut header = create_raw_ip_header(
            4,
            5,
            5,
            20,
            10,
            false,
            false,
            false,
            0,
            30,
            6,
            123,
            &[192, 168, 0, 2],
            &[192, 168, 0, 3],
            &Vec::new(),
        );
        let mut version = u8::from_be_bytes(get_ip_version(&header));
        assert!(version == 4);
        set_header_version(&mut header, &[5]);
        version = u8::from_be_bytes(get_ip_version(&header));
        assert!(version == 5);

        let mut ihl = u8::from_be_bytes(get_ip_ihl(&header));
        assert!(ihl == 5);
        set_header_ihl(&mut header, &[3]);
        ihl = u8::from_be_bytes(get_ip_ihl(&header));
        assert!(ihl == 3);

        let mut dscp = u8::from_be_bytes(get_ip_dscp(&header));
        assert!(dscp == 1);

        let mut ecn = u8::from_be_bytes(get_ip_ecn(&header));
        assert!(ecn == 1);

        let mut tos = u8::from_be_bytes(get_ip_tos(&header));
        assert!(tos == 5);

        set_header_dscp(&mut header, &[8]);
        dscp = u8::from_be_bytes(get_ip_dscp(&header));
        assert!(dscp == 8);

        set_header_ecn(&mut header, &[3]);
        ecn = u8::from_be_bytes(get_ip_ecn(&header));
        assert!(ecn == 3);

        set_header_tos(&mut header, &[25]);
        tos = u8::from_be_bytes(get_ip_tos(&header));
        assert!(tos == 25);

        let mut total_len = u16::from_be_bytes(get_ip_total_len(&header));
        assert!(total_len == 20);
        set_header_total_len(&mut header, &[1, 1]);
        total_len = u16::from_be_bytes(get_ip_total_len(&header));
        assert!(total_len == 257);

        let mut identification = u16::from_be_bytes(get_ip_identification(&header));
        assert!(identification == 10);
        set_header_identification(&mut header, &[1, 2]);
        identification = u16::from_be_bytes(get_ip_identification(&header));
        assert!(identification == 258);

        let mut reserved = u8::from_be_bytes(get_ip_reserved_flag(&header));
        assert!(reserved == 0);
        set_header_reserved_flag(&mut header, true);
        reserved = u8::from_be_bytes(get_ip_reserved_flag(&header));
        assert!(reserved == 1);

        let mut df_flag = u8::from_be_bytes(get_ip_df_flag(&header));
        assert!(df_flag == 0);
        set_header_df_flag(&mut header, true);
        df_flag = u8::from_be_bytes(get_ip_df_flag(&header));
        assert!(df_flag == 1);

        let mut mf_flag = u8::from_be_bytes(get_ip_mf_flag(&header));
        assert!(mf_flag == 0);
        set_header_mf_flag(&mut header, true);
        mf_flag = u8::from_be_bytes(get_ip_mf_flag(&header));
        assert!(mf_flag == 1);

        let mut fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&header));
        assert!(fragment_offset == 0);
        set_header_fragment_offset(&mut header, &[1, 4]);
        fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&header));
        assert!(fragment_offset == 260);

        let mut time_to_live = u8::from_be_bytes(get_ip_ttl(&header));
        assert!(time_to_live == 30);
        set_header_ttl(&mut header, &[12]);
        time_to_live = u8::from_be_bytes(get_ip_ttl(&header));
        assert!(time_to_live == 12);

        let mut protocol = u8::from_be_bytes(get_ip_protocol(&header));
        assert!(protocol == 6);
        set_header_protocol(&mut header, &[20]);
        protocol = u8::from_be_bytes(get_ip_protocol(&header));
        assert!(protocol == 20);

        let mut checksum = u16::from_be_bytes(get_ip_checksum(&header));
        assert!(checksum == 123);
        set_header_checksum(&mut header, &[1, 5]);
        checksum = u16::from_be_bytes(get_ip_checksum(&header));
        assert!(checksum == 261);

        let mut src_addr = get_ip_src_addr(&header);
        assert!(src_addr == [192, 168, 0, 2]);
        set_header_src_addr(&mut header, &[2, 2, 2, 2]);
        src_addr = get_ip_src_addr(&header);
        assert!(src_addr == [2, 2, 2, 2]);

        let mut dst_addr: [u8; 4] = get_ip_dst_addr(&header);
        assert!(dst_addr == [192, 168, 0, 3]);
        set_header_dst_addr(&mut header, &[3, 3, 3, 3]);
        dst_addr = get_ip_dst_addr(&header);
        assert!(dst_addr == [3, 3, 3, 3]);
    }
}
