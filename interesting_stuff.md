# Just some interesting notes learnt during development
The basic HTTP GET request doesn't contain any data in the TCP payload. All the data is in the header. 
Rust programs built with --release allows for integers to overflow (ffff + 1 = 0000) but debug versions don't. 