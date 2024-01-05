# Personal notes on rfc 793 to learn.
https://www.ietf.org/rfc/rfc793.txt

## 1. Introduction
### 1.5 Operation: 
- Basic Data Transfer: continuous stream of packets, assure that the packets are sent
- Reliability: Recover from broken/duplicate/inordered data
- Flow control: Receiver governs the maount of data sent by sender
- Connections: Required for communication
- Precendence and security

## 2. Philosophy
- packet: data of one transaction
- hosts: computers connected to the network, src and dst of packets

### 2.2 Model of operation
- Processes transfer data by passing buffers of data as arguments. TCP packages the data into segments, calls on the "internet module" to transmit the segments to their destination TCP. The receiving TCP places the data into the receiving user's buffer. TCPs include control information. 
- Packet switches may perform further packaging, fragmentation etc. 

### 2.4 Interfaces
- TCP/user interface provides for calls made by the user to the TCP to OPEN or CLOSE a connection, to SEND or RECEIVE data, or to obtain STATUS about a connection. 

### 2.6 Reliable communication
- Streams of data are sent reliably via SEQ and ACK. 

### 2.7 Connection establishment and clearing
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

## 3. Functional Specification

### 3.2 Terminology
- A single connection requires remembering many variables -> stored in TCB (Transmission control block)
  - Local and remote sock nums, security and precedence of the connection, ptrs to the user's send an receive buffers, ptrs to retransmit queue and to the current segment, variables related to send and receive sequence numbers. 
- A connection's states are LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, LAST-ACK, TIME-WAIT and (fictional) CLOSED. 
- The TCP connection progresses from one state to another in response to events
  - The events are the user calls, OPEN, SEND, RECEIVE, CLOSE, ABORT, and STATUS; the incoming segments, particularly those containing the SYN, ACK, RST and FIN flags; and timeouts.

- All bytes have a sequence number, each byte can be acknowledged. 
  - Acknowledgement of sequence number X indicates that all octets up to (but not including) X have been received

### 3.3 Sequence numbers
- Typical sequence nubmer comparisons
  - Determine that an acknowledgement refers to sequence number sent but not yet acknowledged
  - Determine that all sequence numbers in a segment have been acknowledged
  - Determine incoming segment contains sequence numbers which are expected

- Rules:
  - When TCP sends data, the following comparisons are needed to process the achnowledgements
    - SND.UNA is the oldest unacked seqnum
    - SND.NXT is the next seqnum to be sent
    - SEG.ACK is the ack from the receiving TCP (Next seqnum expected by the receiving TCP)
    - SEG.SEQ is the first seq of a segment
    - SEG.LEN is the number of octets in the segment (Counting SYN and FIN)
    - SEG.SEQ+SEG.LEN-1 is the last seqnum of a segment

  - A new acknowledgement (acceptable ack) is one for which the inequality hgolds
    - SND.UNA < SEG.ACK =< SND.NXT

  - A segment on the retransmission queue is fully acknowledged if the sum of its sequence number and length is less or equal than the ack value in the incoming segment

  - Wehn data is received, following comparisons are needed
    - RCV.NXT is the next seqnum expected on incoming segments and is the left/lower edge of the receive window
    - RCV.NXT+RCV.WND-1 is the last seqnum expected on an incoming segment, and is the right/upper edge of the receive window
    - SEG.SEQ is the first seqnum occupied by the incoming segment
    - SEG.SEQ+SEG.LEN-1 is the last seqnum occupied by the incoming segment

  - A segment is judged to occupy a portion of valid receive sequence space if
    - RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND (beginning segment in window)
    or
    - RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND (end segment in window)
    - More details on Page 25 for when receive window is zero
  - Extra:
    - The numbering scheme is utilized to protect control information by implicitly including control flags in the sequence space.
    - For sequence number purposes, the SYN is considered to occur before the first actual data octet of the segment in which it occurs, while the FIN is considered to occur after the last actual data octet in a segment in which it occurs.

- Initial Sequence Number Selection
  - The protocol places no restriction on a particular connection being used over and over again -> problem: same connection closing and opening rapidly causing confusion
    - Use segnums that aren't present in earlier incarnations. Initial segnums are chosen with a 32 bit clock that increments every 4ms. 
  
- Three way handshake
  1) A --> B  SYN my sequence number is X
  2) A <-- B  ACK your sequence number is X
  3) A <-- B  SYN my sequence number is Y
  4) A --> B  ACK your sequence number is Y

- Knowing When to Keep Quiet
  - After restarting, wait for MSL (2min) before assigning seqnums. 
- The TCP Quiet Time Concept

### 3.4 Establishing a connection
- three-way handshake also works if both parties initiate the connection at the same time by sending SYNs. Proper use of RST can disambiguate these cases. 
- Cases
  - Simple
    1.  CLOSED                                               LISTEN
    2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED
    3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED
    4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED
    5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
  - 