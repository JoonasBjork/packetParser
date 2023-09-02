# Personal notes on rfc 793 to learn.
https://www.ietf.org/rfc/rfc793.txt

## Introduction
### Operation: 
- Basic Data Transfer: continuous stream of packets, assure that the packets are sent
- Reliability: Recover from broken/duplicate/inordered data
- Flow control: Receiver governs the maount of data sent by sender
- Connections: Required for communication
- Precendence and security

## Philosophy
- packet: data of one transaction
- hosts: computers connected to the network, src and dst of packets

### Model of operation
- Processes transfer data by passing buffers of data as arguments. TCP packages the data into segments, calls on the "internet module" to transmit the segments to their destination TCP. The receiving TCP places the data into the receiving user's buffer. TCPs include control information. 
- Packet switches may perform further packaging, fragmentation etc. 

### Interfaces
- TCP/user interface provides for calls made by the user to the TCP to OPEN or CLOSE a connection, to SEND or RECEIVE data, or to obtain STATUS about a connection. 

### Reliable communication
- Streams of data are sent reliably via SEQ and ACK. 

### Connection establishment and clearing
- ip addr + port create a unique socket throughout all networks. This socket pair defines the connection. 
- Connection are "full duplex" -> carry data in both directions
- Any port is fine

- TCB (Transmission Control Block), store connection. 
- When connection is OPEN'd, a small local connection name is stored in TCB
  - Passive OPEN: process wants to accept incoming connection requests rather than attempting to initiate a connection. 
  - If any foreign socket requests a connection, it can be accepted
  - Good with well-known sockets
  - Waits for Active OPENs
  - Two cases for matching sockets
    - The waiting socket has fully specified the foreign socket (only accept connection request from there)
    - The waiting socket hasn't specified a foreign socket (Accept anything)
    - Also partially restricted matches exist
- A connection is made with the three-way handhake, 

### Functional Specification
