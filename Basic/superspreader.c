// https://github.com/packet-transactions/domino-examples/blob/master/generalize/superspreader.c 
#define THRESHOLD 10
#define ARRAY_SIZE 10

struct Packet {
  int srcip;
  int flag; // TCP SYN (1) or TCP FYN (2)
};

int spreader[ARRAY_SIZE] = {0};
int superspreader[ARRAY_SIZE] = {0};

void func(struct Packet p) {
  // TODO: Compiler bug
  p.srcip = p.srcip;

  if (p.flag == 1) {
    spreader[p.srcip] = spreader[p.srcip] + 1;
    if (spreader[p.srcip] == THRESHOLD) {
      superspreader[p.srcip] = 1;
    }
  } else if (p.flag == 2) {
    spreader[p.srcip] = spreader[p.srcip] - 1;
  }
}
