# Just some interesting notes learnt during development
- The basic HTTP GET request doesn't contain any data in the TCP payload. All the data is in the header. 
- Rust programs built with --release allows for integers to overflow (ffff + 1 = 0000) but debug versions don't. 
- Networks are actually rarely configured to use the maximum possible segment size, such as 65535 bytes for an ip datagram. Instead, smaller values have many advantages, such as packet loss on unreliable networks being a bigger factor with larger packets/datagrams. 
- Rust unit tests are integrated into the files
- Rust's usize varies in size depending on the target architecture. Seems risky, although some functions require it. 
- Rust's tests are not guaranteed to run in any particular order. They usually follow alphabetical order though. One reason for this is that the tests are automatically run in parallel. Therefore the tester can't expect to set up a global data structure in one test and know it exists in another test. 
- Some parts of the TCP header possibly need be included in every IPv4 fragment.  