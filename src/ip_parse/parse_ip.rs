pub fn get_ip_version(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [(buf[0] & 0b11110000) >> 4];
    result
}

pub fn get_ip_ihl(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [buf[0] & 0b00001111];
    result
}

pub fn get_ip_tos(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[1]];
    result
}

pub fn get_ip_dscp(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [(buf[1] & 0b11111100) >> 2];
    result
}

pub fn get_ip_ecn(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[1] & 0b00000011];
    result
}

pub fn get_ip_tl(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

pub fn get_ip_identification(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[4..6]);
    result
}

pub fn get_ip_df_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [buf[6] & 0b01000000 >> 6];
    result
}

pub fn get_ip_mf_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result: [u8; 1] = [buf[6] & 0b00100000 >> 5];
    result
}

pub fn get_ip_fragment_offset(buf: &[u8; 65535]) -> [u8; 2] {
    let result: [u8; 2] = [((buf[6]) & 0b00011111), buf[7]];
    result
}

pub fn get_ip_ttl(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[8]];
    result
}

pub fn get_ip_protocol(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[9]];
    result
}

pub fn get_ip_checksum(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[10..12]);
    result
}

pub fn get_ip_src_addr(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[12..16]);
    result
}

pub fn get_ip_dst_addr(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[16..20]);
    result
}

pub fn get_ip_options(buf: &[u8; 65535]) -> Option<([u8; 60], usize)> {
    let ihl_value = get_ip_ihl(buf)[0];

    if ihl_value < 5 {
        return None;
    }
    let options_bytes = ihl_value as usize * 4;

    let mut result = [0; 60];
    result[..options_bytes].copy_from_slice(&buf[20..(20 + options_bytes)]);
    return Some((result, options_bytes));
}

pub fn get_ip_data(buf: &[u8; 65535], datagram_len: usize) -> ([u8; 65515], usize) {
    let header_len = (get_ip_ihl(buf)[0] * 4) as usize;
    let data_len = datagram_len - header_len;

    let mut result = [0; 65515];
    result[..(data_len)].copy_from_slice(&buf[header_len..(datagram_len)]);
    (result, data_len)
}
