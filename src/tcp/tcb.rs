enum State {
    LISTEN,
    SYNSENT,
    SYNRECEIVED,
    ESTABLISHED,
    FINWAIT1,
    FINWAIT2,
    CLOSEWAIT,
    CLOSING,
    LASTACK,
    TIMEWAIT,
    CLOSED,
}

struct TCB {
    /// The state of the TCB
    state: State,

    // Send sequence variables
    /// send unacknowledged
    snd_una: u32,
    /// Send next
    snd_nxt: u32,
    /// Send window
    snd_wnd: u32,
    /// Send urgent pointer
    snd_up: u32,
    /// Segment sequence number used for last window update
    snd_wl1: u32,
    /// Segment acknowledgment number used for last window update
    snd_wl2: u32,
    /// Initial send sequence number
    snd_iss: u32,

    // Receive sequence variables
    /// Eeceive next
    rcv_nxt: u32,
    /// Receive window
    rcv_wnd: u32,
    /// Receive urgent pointer
    rcv_up: u32,
    /// Initial receive sequence number
    rcv_irs: u32,

    // Segment sequence variables
    /// segment sequence number
    seg_seq: u32,
    /// segment acknowledgment number
    seg_ack: u32,
    /// segment length
    seg_len: u32,
    /// segment window
    seg_wnd: u32,
    /// segment urgent pointer
    seg_up: u32,
    /// segment precedence value
    seg_prc: u32,
}
