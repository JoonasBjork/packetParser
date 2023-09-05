//! The parse_ipv4.rs file contains operations to access, and create IPv4 datagrams
//! IPv4 datagrams are represented as fixed size arrays of the form [u8; 65535].

use crate::ip_parse::parse_tables;

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

/// Returns an array with the checksum field's bytes
///
/// * The `header` parameter is the ip datagram header excluding the options field.
/// Helper function for creating an ip datagram. Skips over the checksum bytes in the header.
#[allow(unused)]
fn calculate_checksum(header: &[u8; 20]) -> [u8; 2] {
    let mut sum: u16 = 0;
    let mut current_field = [0; 2];
    for k in (0..20).step_by(2) {
        if k == 10 {
            continue;
        }
        current_field.copy_from_slice(&header[k..k + 2]);
        let next_field_value = u16::from_be_bytes(current_field);
        sum = match sum.checked_add(next_field_value) {
            Some(s) => s,
            None => sum.wrapping_add(next_field_value.wrapping_add(1)),
        };
    }
    sum = !sum;

    current_field.copy_from_slice(&sum.to_be_bytes());
    current_field
}

/// Returns an array with the IP's bytes
///
/// * The `ip` is a string representation of the ip address with periods as separators of the octets.  
#[allow(unused)]
pub fn parse_ip_string_to_bytes(ip: &str) -> Result<[u8; 4], ()> {
    let split_ip = ip
        .split(".")
        .map(|octet| octet.parse::<u8>())
        .collect::<Vec<Result<_, _>>>();
    if split_ip.len() != 4 || !split_ip.iter().all(|octet| octet.is_ok()) {
        return Err(());
    }

    let mut result: [u8; 4] = [0; 4];
    result.copy_from_slice(
        &split_ip
            .into_iter()
            .map(|oct| oct.unwrap())
            .collect::<Vec<u8>>(),
    );
    Ok(result)
}

/// Returns an array of bytes with the created ip datagram.
///
/// The two least significant bits are the ecn.
/// * `identification` sets the value of the identification field.
/// * `df_flag` sets the Don't fragment bit to 1 if true, 0 if false
/// * `mf_flag` sets the Don't fragment bit to 1 if true, 0 if false
/// * `fragment_offset` sets the fragment offset field
/// * `time_to_live` sets the time to live field
/// * `protocol` sets the protocol field
/// * The `src_addr` and `dst_addr` fields are ip addresses with octets corresponding to the bytes in big endian.
/// * The `dscp_ecn` field is 8 bits long and uses big endian. The six most significant bits are the dscp.
/// * `options` sets the options field.
/// * `data` sets the data field.
#[allow(unused)]
pub fn create_ip_datagram(
    dscp_ecn: u8,
    identification: u16,
    df_flag: bool,
    mf_flag: bool,
    fragment_offset: u16,
    time_to_live: u8,
    protocol: u8,
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
    options: &Vec<u8>,
    data: &Vec<u8>,
) -> Result<[u8; 65535], DatagramError> {
    let mut datagram_errors = DatagramError::new();
    if options.len() > 40 {
        datagram_errors.push("The options field is over 40 bytes");
    }
    if 20 + options.len() + data.len() > 65535 {
        datagram_errors.push("The joint length of options and data is over 65535");
    }
    if fragment_offset > 0b0001111111111111 {
        datagram_errors.push("Fragment_offset is over 15 bits")
    }
    if time_to_live <= 0 {
        datagram_errors.push("Time_to_live <= 0")
    }
    // It can be checked that the protocol is known with get_proto_name but someone might also be testing their own protocol so that check isn't added.
    if !datagram_errors.is_empty() {
        return Err(datagram_errors);
    }

    let mut header: [u8; 20] = [0; 20];
    let ihl: u8 = (5 + (options.len() + 3) / 4) as u8; // Small arithmetic trick to always get a large enough ihl.
    header[0] = (4 << 4) | ihl; // Ip version and ihl
    header[1] = dscp_ecn;
    let total_len: u16 = 20 + options.len() as u16 + data.len() as u16;
    header[2..4].copy_from_slice(&total_len.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(
        &(fragment_offset | ((df_flag as u16) << 14) | ((mf_flag as u16) << 13)).to_be_bytes(),
    );
    header[8] = time_to_live;
    header[9] = protocol;
    header[12..16].copy_from_slice(src_addr);
    header[16..20].copy_from_slice(dst_addr);

    let checksum = calculate_checksum(&header);
    header[10..12].copy_from_slice(&checksum);

    let mut result: [u8; 65535] = [0; 65535];
    result[0..20].copy_from_slice(&header);
    result[20..20 + options.len()].copy_from_slice(&options);
    result[20 + options.len()..20 + options.len() + data.len()].copy_from_slice(&data);

    Ok(result)
}

/// Validates the entire datagram. Returns an empty Ok if the datagram is valid and Err with a DatagramError if it isn't valid.
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
        // return ([0; 60], 0 as usize);
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

pub fn print_ip_data(buf: &[u8; 65535]) -> () {
    let ip_version = u8::from_be_bytes(get_ip_version(&buf));
    let ip_ihl = u8::from_be_bytes(get_ip_ihl(&buf));
    let ip_tos = u8::from_be_bytes(get_ip_tos(&buf));
    let ip_dscp = u8::from_be_bytes(get_ip_dscp(&buf));
    let ip_ecn = u8::from_be_bytes(get_ip_ecn(&buf));
    let ip_total_len = u16::from_be_bytes(get_ip_total_len(&buf));
    let ip_id = u16::from_be_bytes(get_ip_identification(&buf));
    let ip_res_flag = u8::from_be_bytes(get_ip_reserved_flag(&buf));
    let ip_df_flag = u8::from_be_bytes(get_ip_df_flag(&buf));
    let ip_mf_flag = u8::from_be_bytes(get_ip_mf_flag(&buf));
    let ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&buf));
    let ip_ttl = u8::from_be_bytes(get_ip_ttl(&buf));
    let ip_proto = u8::from_be_bytes(get_ip_protocol(&buf));
    let ip_checksum = u16::from_be_bytes(get_ip_checksum(&buf));
    let ip_src_addr = get_ip_src_addr(&buf);
    let ip_dst_addr = get_ip_dst_addr(&buf);
    let (ip_opts, ip_opts_len) = get_ip_options(&buf);
    let (ip_data, ip_data_len) = get_ip_data(&buf);

    println!("IP DATAGRAM INFO:");

    println!("Header as bytes: {:x?}", buf[..20].to_vec());

    println!("ip_version: {:x?}", ip_version);
    println!("ip_ihl: {:x?}", ip_ihl);
    println!("ip_tos: {:x?}", ip_tos);
    println!("ip_dscp: {:x?}", ip_dscp);
    println!("ip_ecn: {:x?}", ip_ecn);
    println!("ip_total_len: {:?}", ip_total_len);
    println!("ip_identification: {:?}", ip_id);
    println!("ip_reserved_flag: {:x?}", ip_res_flag);
    println!("ip_dont_fragment_flag: {:x?}", ip_df_flag);
    println!("ip_more_fragments_flag: {:x?}", ip_mf_flag);
    println!("ip_fragment_offset: {:x?}", ip_fragment_offset);
    println!("ip_ttl: {:x?}", ip_ttl);
    println!(
        "ip_proto: {:x?}, proto_name: {:?}",
        ip_proto,
        parse_tables::get_proto_name(ip_proto).get_or_insert("UNKNOWN")
    );
    println!("ip_checksum: {:x?}", ip_checksum);
    println!("ip_src_addr: {:?}", ip_src_addr);
    println!("ip_dst_addr: {:?}", ip_dst_addr);
    match ip_opts {
        Ok(opts) => println!(
            "ip_opts: {:x?}, opts_len: {}",
            opts[..ip_opts_len].to_vec(),
            ip_opts_len
        ),
        Err(()) => println!("ip_opts couldn't be found as the ihl field < 5"),
    }
    println!(
        "ip_data: {:x?}, data_len: {}",
        ip_data[..ip_data_len].to_vec(),
        ip_data_len
    );
}

/// Returns True if the checksum field matches the header's checksum
pub fn check_ip_checksum(buf: &[u8; 65535]) -> bool {
    let mut sum: u16 = 0;
    let mut current_field = [0; 2];
    for k in (0..20).step_by(2) {
        current_field.copy_from_slice(&buf[k..k + 2]);

        let next_field_value = u16::from_be_bytes(current_field);
        sum = match sum.checked_add(next_field_value) {
            Some(s) => s,
            None => sum.wrapping_add(next_field_value.wrapping_add(1)),
        }
    }

    let checksum = !sum;
    checksum == 0
}

/// Unit tests for the parse_ipv4 file
#[cfg(test)]
mod ipv4_tests {
    use crate::ip_parse::parse_ipv4::{
        check_ip_checksum, create_ip_datagram, get_ip_checksum, get_ip_data, get_ip_df_flag,
        get_ip_dscp, get_ip_dst_addr, get_ip_ecn, get_ip_fragment_offset, get_ip_identification,
        get_ip_ihl, get_ip_mf_flag, get_ip_options, get_ip_protocol, get_ip_reserved_flag,
        get_ip_src_addr, get_ip_tos, get_ip_total_len, get_ip_ttl, get_ip_version,
        parse_ip_string_to_bytes,
    };

    #[test]
    fn test_valid_string_to_ipv4_addr() {
        match parse_ip_string_to_bytes("10.10.10.10") {
            Ok(_a) => (),
            Err(_) => panic!("Valid ip panic"),
        }
    }

    #[test]
    fn test_short_string_to_ipv4_addr() {
        match parse_ip_string_to_bytes("10.10.10") {
            Ok(a) => panic!("Invalid ip returned Ok. {:?}", a),
            Err(_) => (),
        }
    }

    #[test]
    fn test_incorrect_string_to_ipv4_addr() {
        match parse_ip_string_to_bytes("10.10.257.10") {
            Ok(a) => panic!("Invalid ip returned Ok. {:?}", a),
            Err(_) => (),
        }
    }

    #[test]
    fn test_ip_datagram_and_parsing() {
        let ip_datagram = match create_ip_datagram(
            0b00000000,
            10 as u16,
            false,
            false,
            0 as u16,
            30,
            6,
            &[192, 168, 0, 2],
            &[192, 168, 0, 3],
            &Vec::new(), // Add after support for options exists
            &"Hello world!".as_bytes().to_vec(),
        ) {
            Ok(a) => a,
            Err(e) => {
                let errors = e.0.join("\n");
                panic!("Faced errors in datagram creation: \n{}", errors)
            }
        };

        let ip_version = u8::from_be_bytes(get_ip_version(&ip_datagram));
        assert!(ip_version == 4);

        let ip_ihl = u8::from_be_bytes(get_ip_ihl(&ip_datagram));
        assert!(ip_ihl == 5);

        let ip_tos = u8::from_be_bytes(get_ip_tos(&ip_datagram));
        assert!(ip_tos == 0);

        let ip_dscp = u8::from_be_bytes(get_ip_dscp(&ip_datagram));
        assert!(ip_dscp == 0);

        let ip_ecn = u8::from_be_bytes(get_ip_ecn(&ip_datagram));
        assert!(ip_ecn == 0);

        let ip_total_len = u16::from_be_bytes(get_ip_total_len(&ip_datagram));
        assert!(ip_total_len == 20 + 12); // header + "Hello world!"

        let ip_id = u16::from_be_bytes(get_ip_identification(&ip_datagram));
        assert!(ip_id == 10);

        let ip_res_flag = u8::from_be_bytes(get_ip_reserved_flag(&ip_datagram));
        assert!(ip_res_flag == 0);

        let ip_df_flag = u8::from_be_bytes(get_ip_df_flag(&ip_datagram));
        assert!(ip_df_flag == 0);

        let ip_mf_flag = u8::from_be_bytes(get_ip_mf_flag(&ip_datagram));
        assert!(ip_mf_flag == 0);

        let ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&ip_datagram));
        assert!(ip_fragment_offset == 0);

        let ip_ttl = u8::from_be_bytes(get_ip_ttl(&ip_datagram));
        assert!(ip_ttl == 30);

        let ip_proto = u8::from_be_bytes(get_ip_protocol(&ip_datagram));
        assert!(ip_proto == 6);

        let ip_checksum = u16::from_be_bytes(get_ip_checksum(&ip_datagram));
        assert!(ip_checksum == 0x1b79);

        assert!(
            check_ip_checksum(&ip_datagram),
            "Checksum doesn't match with check_ip_checksum"
        );

        let ip_src_addr = get_ip_src_addr(&ip_datagram);
        assert!(ip_src_addr == [192, 168, 0, 2]);

        let ip_dst_addr = get_ip_dst_addr(&ip_datagram);
        assert!(ip_dst_addr == [192, 168, 0, 3]);

        let (ip_opts, ip_opts_len) = get_ip_options(&ip_datagram);
        assert!(ip_opts_len == 0);
        assert!(
            ip_opts.is_ok(),
            "ip_opts couldn't be found and the packet is malformed as the ihl field is less than 5"
        );
        assert!(ip_opts.unwrap().into_iter().all(|x| x == 0));

        let (ip_data, ip_data_len) = get_ip_data(&ip_datagram);
        assert!(ip_data_len == 12);
        let hello_bytes = "Hello world!".as_bytes().to_vec();
        let data_vec = ip_data.into_iter().take(ip_data_len).collect::<Vec<_>>();
        assert!(data_vec == hello_bytes);
    }
}
