struct Packet {
   int p1;
   int p2;
};

int c1;
int c2;
int c3;
int c4;
int c5;
int c6;
int c7;
int c8;

void func(struct Packet p) {
  c1 = p.p1 + p.p2;
  c2 = c2 + c1;
  c3 = c3 + c2;
  c4 = c4 + c3;
  c5 = c5 + c4;
  c6 = c6 + c5;
  c7 = c7 + c6;
  c8 = c8 + c7;
}
