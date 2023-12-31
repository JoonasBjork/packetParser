# Packet parsing project in Rust

## Motivation for project
I started working on this project after looking at Jon Gjengset's video series on implementing TCP in Rust [here](https://youtu.be/bzja9fQWzdA?si=iBGWw4V2QRtcBty3). Only the **run.sh** file is taken from [his project](https://github.com/jonhoo/rust-tcp/blob/master/run.sh) as it is used to set up the virtual network device correctly. The rest of the project is written by me. 

One of the goals of the project was to rely on existing documentation and tools including ChatGPT. However, no code has or will been copied from anywhere. 

## Software needed for running
Basic Rust tools such as Cargo and Rustc can be found [here](https://doc.rust-lang.org/cargo/getting-started/installation.html). 

For creating http requests, curl is used. For creating raw TCP requests, hping3 is used. 

The development was done on WSL. 

## Running instructions
The user first needs to create a virtual network device/interface for receiving and transmitting packets in user space. The following command can be used to create the "tun0" network interface. 
```shell
sudo ip tuntap add tun0 mode tun
```

After creating the interface, the program can be run with the **run.sh script**. Packets can be sent to the program with either **tcp_ping.sh** or **icmp_ping.sh**.

## Goals
### Currently
- [ ] Full implementation of IP data structures
  - [ ] Parsing
    - [x] Unit tests
    - [ ] Support for combining fragments into single datagrams
    - [ ] support for options
  - [x] Support for creating IP datagrams
    - [x] Unit tests
    - [x] Support for creating fragmented datagrams
  - [ ] Support for IPv6
- [ ] Full implementation of TCP data structures
  - [ ] Parsing
    - [x] Unit tests
    - [ ] Support for options
  - [ ] Creation
    - [x] Unit tests
    - [ ] Helper methods for creating TCP packets
- [ ] Full implementation of TCP
  - [ ] Full support for different states and moving between states
    - [ ] 3-way handshake
    - [ ] Closing connections


### Maybe in the future
- [ ] Full implementation of Ethernet parsing
  - Requires changing from TUN interface to TAP interface
- [ ] Move the IP, TCP, Ethernet parsing into their own libraries
- [ ] Automate testing on GitHub
- [ ] DNS resolution