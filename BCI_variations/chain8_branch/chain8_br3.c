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

void func(struct Packet p) {
  if (c1 == p.p1) {
    if (c2 == p.p1) {
      c2 = c2 + c1;
    } else {
      c2 = p.p1;
    }
  } else {
    if (c2 == p.p1) {
     if (c3 == p.p1) {
	 c3 = c3 + c2;
     } else {
         c3 = p.p1;
     }
    } else {
      if (c3 == p.p1) {
        c3 = c3 + c2;
      } else {
        c3 = p.p1;
      }
  }
    c4 = c4 + c3;
    c5 = c5 + c4;
    c6 = c6 + c5;
    c7 = c7 + c6;
    c8 = c8 + c7;

}
