struct Packet {
   int p1;
   int p2;
   int p3;
   int p4;
   int p5;
   int p6;
   int p7;
};

int c1;
int c2;

void func(struct Packet p) {
  p.p2 = p.p1 + 1;
  p.p3 = p.p2 + 1;
  p.p4 = p.p3 + 1;
  p.p5 = p.p4 + 1;
  p.p6 = p.p5 + 1;
  p.p7 = p.p6 + 1;
  c1 = p.p6;
  c2 = c2 + c1;
}
