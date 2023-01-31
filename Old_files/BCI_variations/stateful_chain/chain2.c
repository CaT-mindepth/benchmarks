struct Packet {
   int p1;
};

int c1;
int c2;

void func(struct Packet p) {
  c1 = p.p1;
  c2 = c2 + c1;
}
