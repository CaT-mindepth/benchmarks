struct Packet {
   int p1;
};

int c1;
int c2;
int c3;

void func(struct Packet p) {
  c1 = p.p1;
  c2 = c2 + c1;
  c3 = c3 + c2;
}
