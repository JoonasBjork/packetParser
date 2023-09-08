//! Contains implementational details that make using the IPv4 protocol as easy for the user as possible.

// Possibly create another file for working specifically with TCP (or any other protocol).

use crate::ip_parse::parse_ipv4::*;
use crate::ip_parse::parse_tables;

pub struct DatagramError(pub Vec<String>);

impl DatagramError {
    pub fn new() -> Self {
        DatagramError(Vec::new())
    }

    pub fn push(&mut self, error_message: &str) {
        self.0.push(error_message.to_string());
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Returns a vector of ip datagrams. The ip datagrams are arrays of bytes. Automatically fragments the packets if allowed by the DF flag,
/// otherwise returns error.
///
/// The two least significant bits are the ecn.
/// * `dscp_ecn` - sets the DSCP and ECN fields. The first six bits correspond to DSCP. The last two bits correspond to ECN.
/// * `identification` sets the value of the identification field.
/// * `df_flag` sets the Don't fragment bit to 1 if true, 0 if false
/// * `time_to_live` sets the time to live field
/// * `protocol` sets the protocol field
/// * The `src_addr` and `dst_addr` fields are ip addresses with octets corresponding to the bytes in big endian.
/// * `options` sets the options field. The size of the options field is assumed from the length of the provided vector.
/// * `data` sets the data field. The size of the data field is assumed from the length of the provided vector.
/// * `max_fragment_size` sets the maximum size for a single fragment
/// * `first_ip_identification` mutable reference to an u16 integer. Gets incremented for every datagram created. The user is responsible
/// for supplying values so that there aren't duplicate identifications when calling the function multiple times. The mutable reference is
/// incremented, and can be used again as is.
#[allow(unused)]
pub fn create_ip_datagrams(
    dscp_ecn: u8,
    df_flag: bool,
    time_to_live: u8,
    protocol: u8,
    src_addr: &[u8; 4],
    dst_addr: &[u8; 4],
    options: &Vec<u8>,
    data: &Vec<u8>,
    max_fragment_size: u32,
    first_ip_identification: &mut u16,
) -> Result<Vec<Vec<u8>>, DatagramError> {
    let mut datagram_errors = DatagramError::new();
    let max_data_field_size: u32 = max_fragment_size - 60; // Remove size of header

    if max_data_field_size < 100 {
        datagram_errors.push("The max_fragment_size is too small (< 160)");
    }

    if max_fragment_size > 65535 {
        datagram_errors.push("Max_fragment_size cannot exceed 65535");
    }

    if options.len() > 40 {
        datagram_errors.push("The options field is over 40 bytes");
    }
    if 20 + options.len() + data.len() > 65535 {
        datagram_errors.push("The joint length of options and data is over 65535");
    }
    if time_to_live <= 0 {
        datagram_errors.push("Time_to_live <= 0");
    }

    if (df_flag == true && data.len() as u32 > max_data_field_size) {
        datagram_errors.push(
            "Don't fragment flag is set but the amount of data surpasses limit of 1400 bytes",
        );
    }

    if !datagram_errors.is_empty() {
        return Err(datagram_errors);
    }

    let mut created_datagrams: Vec<Vec<u8>> = Vec::new();

    let ihl: u8 = (5 + (options.len() + 3) / 4) as u8; // Small arithmetic trick to always get just large enough ihl.
    let single_datagram_len: u32 = 20 + options.len() as u32 + data.len() as u32;
    let number_of_datagrams = (single_datagram_len / max_data_field_size) + 1;

    if (number_of_datagrams == 1) {
        let mut header = create_raw_ip_header(
            4,
            ihl,
            dscp_ecn,
            single_datagram_len as u16,
            *first_ip_identification, // Placeholder, in the future an automatic algorithm
            false,
            df_flag,
            false,
            0,
            time_to_live,
            protocol,
            0,
            src_addr,
            dst_addr,
        );
        let checksum = calculate_checksum(&header);
        set_header_checksum(&mut header, &checksum);
        let datagram = create_raw_ip_datagram_from_header(&header, options, data);
        created_datagrams.push(datagram);
        *first_ip_identification += 1;
    } else {
        for k in 1..=number_of_datagrams {
            let mf_flag = k != number_of_datagrams;
            let data_start = ((k - 1) * max_data_field_size) as usize;
            let data_end = if k != number_of_datagrams {
                (k * max_data_field_size) as usize
            } else {
                data.len()
            };
            let current_datagram_len = data_end - data_start + 20 + options.len();
            let current_datagram_data = &data[data_start..data_end].to_vec(); // figure out something to remove this cloning
            let mut header = create_raw_ip_header(
                4,
                ihl,
                dscp_ecn,
                current_datagram_len as u16,
                *first_ip_identification, // Placeholder, in the future an automatic algorithm
                false,
                false,
                mf_flag,
                data_start as u16,
                time_to_live,
                protocol,
                0,
                src_addr,
                dst_addr,
            );
            let checksum = calculate_checksum(&header);
            set_header_checksum(&mut header, &checksum);
            let datagram =
                create_raw_ip_datagram_from_header(&header, options, current_datagram_data);
            created_datagrams.push(datagram);
            *first_ip_identification += 1;
        }
    }

    Ok(created_datagrams)
}

/// Returns an array with the checksum field's bytes
///
/// * The `header` parameter is the ip datagram header excluding the options field.
/// Helper function for creating an ip datagram. Skips over the checksum bytes in the header.
#[allow(unused)]
pub fn calculate_checksum(header: &[u8; 20]) -> [u8; 2] {
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

/// Validates the entire datagram. Returns an empty Ok if the datagram is valid and Err with a DatagramError if it isn't valid.
pub fn validate_full_ip_datagram(buf: &[u8]) -> Result<(), DatagramError> {
    let mut datagram_errors = DatagramError::new();
    if !check_ip_checksum(buf) {
        datagram_errors.push("Datagram header checksum doesn't match");
    }

    if get_ip_version(&buf[..])[0] != 4 as u8 {
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

/// Returns True if the checksum field matches the header's checksum
pub fn check_ip_checksum(buf: &[u8]) -> bool {
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

/// Prints out all data of the IP datagram.
pub fn print_ip_data(buf: &[u8]) -> () {
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
    let ip_data = get_ip_data(&buf);

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
    println!("ip_data: {:x?}, data_len: {}", ip_data, ip_data.len(),);
}

/// Unit tests for the parse_ipv4 file
#[cfg(test)]
mod ipv4_tests {
    use crate::ip_parse::ip_implementation::{
        check_ip_checksum, create_ip_datagrams, parse_ip_string_to_bytes,
    };
    use crate::ip_parse::parse_ipv4::{
        get_ip_checksum, get_ip_data, get_ip_df_flag, get_ip_dscp, get_ip_dst_addr, get_ip_ecn,
        get_ip_fragment_offset, get_ip_identification, get_ip_ihl, get_ip_mf_flag, get_ip_options,
        get_ip_protocol, get_ip_reserved_flag, get_ip_src_addr, get_ip_tos, get_ip_total_len,
        get_ip_ttl, get_ip_version,
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
    fn test_ip_datagram_fragmentation_and_parsing() {
        let mut identifier = 25;
        let data = [
            vec![5; 1000].as_slice(),
            vec![10; 1000].as_slice(),
            vec![5; 1000].as_slice(),
        ]
        .concat();
        let mut ip_datagrams = match create_ip_datagrams(
            0b00000000,
            false,
            30,
            6,
            &[192, 168, 0, 2],
            &[192, 168, 0, 3],
            &Vec::new(), // Add after support for options exists
            &data,
            1400,
            &mut identifier,
        ) {
            Ok(datagrams) => datagrams,
            Err(e) => {
                let errors = e.0.join("\n");
                panic!("Faced errors in datagram creation: \n{}", errors)
            }
        };

        assert!(ip_datagrams.len() == 3);

        let d3 = ip_datagrams.remove(2);
        let d2 = ip_datagrams.remove(1);
        let d1 = ip_datagrams.remove(0);

        let d1_total_len = u16::from_be_bytes(get_ip_total_len(&d1));
        let d2_total_len = u16::from_be_bytes(get_ip_total_len(&d2));
        let d3_total_len = u16::from_be_bytes(get_ip_total_len(&d3));
        assert!(d1_total_len == 1360);
        assert!(d2_total_len == 1360);
        assert!(d3_total_len == 340);

        let d1_ip_id = u16::from_be_bytes(get_ip_identification(&d1));
        let d2_ip_id = u16::from_be_bytes(get_ip_identification(&d2));
        let d3_ip_id = u16::from_be_bytes(get_ip_identification(&d3));

        assert!(d1_ip_id == 25);
        assert!(d2_ip_id == 26);
        assert!(d3_ip_id == 27);
        assert!(identifier == 28);

        let d1_ip_ihl = u8::from_be_bytes(get_ip_ihl(&d1));
        let d2_ip_ihl = u8::from_be_bytes(get_ip_ihl(&d2));
        let d3_ip_ihl = u8::from_be_bytes(get_ip_ihl(&d3));
        assert!(d1_ip_ihl == 5);
        assert!(d2_ip_ihl == 5);
        assert!(d3_ip_ihl == 5);

        let d1_ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&d1));
        let d2_ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&d2));
        let d3_ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&d3));
        assert!(d1_ip_fragment_offset == 0);
        assert!(d2_ip_fragment_offset == 1340);
        assert!(d3_ip_fragment_offset == 2680);

        let d1_ip_mf_flag = u8::from_be_bytes(get_ip_mf_flag(&d1));
        let d2_ip_mf_flag = u8::from_be_bytes(get_ip_mf_flag(&d2));
        let d3_ip_mf_flag = u8::from_be_bytes(get_ip_mf_flag(&d3));
        assert!(d1_ip_mf_flag == 1);
        assert!(d2_ip_mf_flag == 1);
        assert!(d3_ip_mf_flag == 0);

        assert!(check_ip_checksum(&d1));
        assert!(check_ip_checksum(&d2));
        assert!(check_ip_checksum(&d3));
    }

    #[test]
    fn test_ip_datagram_and_parsing() {
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

        let ip_version = u8::from_be_bytes(get_ip_version(&datagram));
        assert!(ip_version == 4);

        let ip_ihl = u8::from_be_bytes(get_ip_ihl(&datagram));
        assert!(ip_ihl == 5);

        let ip_tos = u8::from_be_bytes(get_ip_tos(&datagram));
        assert!(ip_tos == 0);

        let ip_dscp = u8::from_be_bytes(get_ip_dscp(&datagram));
        assert!(ip_dscp == 0);

        let ip_ecn = u8::from_be_bytes(get_ip_ecn(&datagram));
        assert!(ip_ecn == 0);

        let ip_total_len = u16::from_be_bytes(get_ip_total_len(&datagram));
        assert!(ip_total_len == 20 + 12); // header + "Hello world!"

        let ip_id = u16::from_be_bytes(get_ip_identification(&datagram));
        assert!(ip_id == 10);
        assert!(identifier == 11);

        let ip_res_flag = u8::from_be_bytes(get_ip_reserved_flag(&datagram));
        assert!(ip_res_flag == 0);

        let ip_df_flag = u8::from_be_bytes(get_ip_df_flag(&datagram));
        assert!(ip_df_flag == 0);

        let ip_mf_flag = u8::from_be_bytes(get_ip_mf_flag(&datagram));
        assert!(ip_mf_flag == 0);

        let ip_fragment_offset = u16::from_be_bytes(get_ip_fragment_offset(&datagram));
        assert!(ip_fragment_offset == 0);

        let ip_ttl = u8::from_be_bytes(get_ip_ttl(&datagram));
        assert!(ip_ttl == 30);

        let ip_proto = u8::from_be_bytes(get_ip_protocol(&datagram));
        assert!(ip_proto == 6);

        let ip_checksum = u16::from_be_bytes(get_ip_checksum(&datagram));
        assert!(ip_checksum == 0x1b79, "Checksum doesn't match");

        assert!(
            check_ip_checksum(&datagram),
            "Checksum doesn't match with check_ip_checksum"
        );

        let ip_src_addr = get_ip_src_addr(&datagram);
        assert!(ip_src_addr == [192, 168, 0, 2]);

        let ip_dst_addr = get_ip_dst_addr(&datagram);
        assert!(ip_dst_addr == [192, 168, 0, 3]);

        let (ip_opts, ip_opts_len) = get_ip_options(&datagram);
        assert!(ip_opts_len == 0);
        assert!(
            ip_opts.is_ok(),
            "ip_opts couldn't be found and the packet is malformed as the ihl field is less than 5"
        );
        assert!(ip_opts.unwrap().into_iter().all(|x| x == 0));

        let ip_data = get_ip_data(&datagram);
        assert!(ip_data.len() == 12);
        let hello_bytes = "Hello world!".as_bytes().to_vec();
        assert!(ip_data == hello_bytes);
    }
}
