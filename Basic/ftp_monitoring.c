// https://github.com/packet-transactions/domino-examples/blob/master/generalize/ftp_monitoring.c
#define ARRAY_SIZE 10

struct Packet {
  int drop;
  int src;
  int dst;
  int srcport;
  int dstport;
  int ftp_port;
  int array_index;
};

int ftp_data_chan[ARRAY_SIZE] = {0};

void func(struct Packet p) {
  p.array_index = p.src * 10 + p.dst * 10 + p.ftp_port; // row indexed 3D array
  if (p.dstport == 21) {
    ftp_data_chan[p.array_index] = 1;
  } else {
    if (p.srcport == 20) {
      p.drop = (ftp_data_chan[p.array_index] == 0);
    }
  }
}
