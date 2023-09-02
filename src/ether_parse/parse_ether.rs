pub fn get_ether_type(buf: &[u8; 1504]) -> [u8; 4] {
    let mut result = [0; 4];
    result.copy_from_slice(&buf[0..4]);
    result
}

/// get_ether_data(buf: &[u8; 1504], data_size: usize) -> [u8; 1500]
///
/// Returns an array with the data and the length of the data
pub fn get_ether_data(buf: &[u8; 1504], data_size: usize) -> ([u8; 1500], usize) {
    assert!(
        data_size <= 1500 && data_size >= 46,
        "data_size in get_ether_data should be <= 1500 and >= 46. Was supplied: {}",
        data_size
    );
    let mut result = [0; 1500];
    result[..data_size].copy_from_slice(&buf[4..(4 + data_size)]);
    (result, data_size)
}
