struct Packet {
  int payload1;
  int payload2;
};

// zero-initialize
int elem1; 
int cnt1;

int elem2;
int cnt2;

#define MAJ(I) \
 if (cnt##I == 0) { \
   elem##I = p.payload##I; \
   cnt##I = 1; \
 } else { \
   if (p.payload##I == elem##I) { \
     cnt##I = cnt##I + 1; \
   } else { \
     cnt##I = cnt##I - 1; \
   } \
 }


void func(struct Packet p) {
  MAJ(1)
  MAJ(2)
}

