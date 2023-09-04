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

## Functional Specification

### Terminology
- A single connection requires remembering many variables -> stored in TCB (Transmission control block)
  - Local and remote sock nums, security and precedence of the connection, ptrs to the user's send an receive buffers, ptrs to retransmit queue and to the current segment, variables related to send and receive sequence numbers. 
- A connection's states are LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, LAST-ACK, TIME-WAIT and (fictional) CLOSED. 
- The TCP connection progresses from one state to another in response to events
  - The events are the user calls, OPEN, SEND, RECEIVE, CLOSE, ABORT, and STATUS; the incoming segments, particularly those containing the SYN, ACK, RST and FIN flags; and timeouts.

- All bytes have a sequence number, each byte can be acknowledged. 
  - Acknowledgement of sequence number X indicates that all octets up to (but not including) X have been received
