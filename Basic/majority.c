struct Packet {
  int srcip;
};

// zero-initialize
int elem; 
int cnt;

void func(struct Packet p) {
  if (cnt == 0) {
    elem = p.srcip;
    cnt = 1;
  } else {
    if (p.srcip == elem) {
      cnt = cnt + 1;
    } else {
      cnt = cnt - 1;
    }
  }
}

