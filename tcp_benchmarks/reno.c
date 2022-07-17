// TCP Reno
// Assumptions
// 1. tcp packet with everything being 4 bytes long.
// 2. retransmit being a PHV field. a packet is either retramsmit timeout packet
// (p.retramsmit == 1) or regular TCP packet.
// 3. segment size being a PHV field.
struct Packet {
  int src_port;
  int dst_port;
  int seq_num;
  int ack_num;
  int flags;
  int window;
  int checksum;
  int urgent;
  int options;
  // PHVs in our model:
  int retransmit;
  int seg_size;
};

int cwnd;
int rwnd;
int ss_thresh = 1;

int last_ack = 0;
int dup_ack_cnt = 0;

int in_fast_rec = 0; // in fast recovery

#define FAST_RETRANSMIT \
    if (cwnd / 2 < p.seg_size * 2) { \
      ss_thresh = p.seg_size * 2;    \
    } else {                \
      ss_thresh = cwnd / 2; \
    }               

void func(struct Packet p) {
  if (p.retransmit) {
    FAST_RETRANSMIT
    cwnd = p.seg_size; // still do slow start
  } else {
    if (p.ack_num == last_ack) {
      // dup ack
      dup_ack_cnt = dup_ack_cnt + 1;
    } else {
      dup_ack_cnt = 0;
      if (in_fast_rec) {
        cwnd = ss_thresh;
        in_fast_rec = 0;
      }
      if (cwnd < ss_thresh) { // slow start
        cwnd = cwnd + p.seg_size;
      } else { // congestion avoidance
        cwnd = cwnd + (p.seg_size * p.seg_size) / cwnd;
      }
    }
    if (dup_ack_cnt >= 3 && !in_fast_rec) {
      FAST_RETRANSMIT
        cwnd = ss_thresh + 3 * p.seg_size;
    }
  }
}

