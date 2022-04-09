int state_0 = 0;
struct Packet{
    int pkt_0;
};
void func(struct Packet p) {
  if (state_0==0) {
    state_0=1;
    p.pkt_0=1;
  }
}
