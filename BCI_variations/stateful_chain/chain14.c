struct Packet {
   int p1;
};

int c1;
int c2;
int c3;
int c4;
int c5;
int c6;
int c7;
int c8;
int c9;
int c10;
int c11;
int c12;
int c13;
int c14;

void func(struct Packet p) {
  c1 = p.p1;
  c2 = c2 + c1;
  c3 = c3 + c2;
  c4 = c4 + c3;
  c5 = c5 + c4;
  c6 = c6 + c5;
  c7 = c7 + c6;
  c8 = c8 + c7;
  c9 = c9 + c8;
  c10 = c10 + c9;
  c11 = c11 + c10;
  c12 = c12 + c11;
  c13 = c13 + c12;
  c14 = c14 + c13;
}
