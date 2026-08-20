# Task 2: TCP Three-Way Handshake — Manual Breakdown

## Objective
Manually dissect a TCP handshake from the FormBook pcap (Task 1) to
understand each field's purpose, not just recognize the SYN/SYN-ACK/ACK
pattern.

## Connection Analyzed
Client `172.16.8.49:54456` → Server `172.64.155.76:80`

## The Three Packets

| # | Direction | Flags | Seq | Purpose |
|---|---|---|---|---|
| 11027 | Client → Server | SYN | 0 | Client proposes starting sequence number |
| 11030 | Server → Client | SYN, ACK | 0 | Server acknowledges + proposes its own sequence |
| 11031 | Client → Server | ACK | 1 | Client confirms — connection now open |

## Key Fields Decoded

- **Sequence Number (relative 0):** Not the device's lifetime counter —
  just the starting reference point for *this* connection's byte stream.
- **Flags (0x002 = SYN):** Flags are bits within a single byte, not
  separate fields — explains why packets like [FIN, PSH, ACK] show
  multiple flags set at once.
- **Window Size (65535):** How many bytes a host can receive before
  requiring an ACK. Each side negotiates its own; the connection
  proceeds at the smaller of the two to avoid overwhelming either device.
- **MSS (1460):** Max payload per packet = 1500 (Ethernet frame) minus
  ~40 bytes of IP+TCP headers.

## Post-Handshake Behavior (Investigative Note)
Immediately after the handshake, the client sent `POST /ujvq/` (a
FormBook C2 checkin). The server replied `301 Moved Permanently`, then
initiated FIN — the client responded with RST instead of a clean
FIN/ACK close. This abrupt termination pattern (not a stealth technique,
but a functional one) is consistent with malware cycling rapidly through
multiple C2 endpoints rather than maintaining a persistent connection
like a browser session would.

## Skills Reinforced
Wireshark packet-field inspection, TCP handshake mechanics, connection
lifecycle analysis (open → data → close via RST vs FIN).
