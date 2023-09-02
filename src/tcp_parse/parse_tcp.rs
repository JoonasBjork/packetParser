pub fn get_tcp_src_port(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[0..2]);
    result
}

pub fn get_tcp_dst_port(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[2..4]);
    result
}

pub fn get_tcp_seqn(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[4..8]);
    result
}

pub fn get_tcp_acknum(buf: &[u8; 65535]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[8..12]);
    result
}

pub fn get_tcp_data_offset(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [(buf[12] & 0b11110000) >> 4];
    result
}

pub fn get_tcp_reserved(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [((buf[12] & 0b00001111) << 2) + ((buf[13] & 0b11000000) >> 6)];
    result
}

pub fn get_tcp_urg_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00100000 >> 5];
    result
}

pub fn get_tcp_ack_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00010000 >> 4];
    result
}

pub fn get_tcp_psh_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00001000 >> 3];
    result
}

pub fn get_tcp_rst_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00000100 >> 2];
    result
}

pub fn get_tcp_syn_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00000010 >> 1];
    result
}

pub fn get_tcp_fin_flag(buf: &[u8; 65535]) -> [u8; 1] {
    let result = [buf[13] & 0b00000001];
    result
}

pub fn get_tcp_window(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[14..16]);
    result
}

pub fn get_tcp_checksum(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[16..18]);
    result
}

pub fn get_tcp_urg_ptr(buf: &[u8; 65535]) -> [u8; 2] {
    let mut result = [0; 2];
    result.copy_from_slice(&buf[18..20]);
    result
}

pub fn get_tcp_options(buf: &[u8; 65535]) -> [u8; 40] {
    let data_offset = get_tcp_data_offset(&buf)[0];

    unimplemented!();
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
    // let options = get_tcp_options(&buf);

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
}
