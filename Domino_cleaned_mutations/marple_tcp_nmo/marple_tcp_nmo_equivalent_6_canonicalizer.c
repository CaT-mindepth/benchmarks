struct Packet{
    int pkt_0;
};
int state_1 = 0;
int state_0 = 0;
void func(struct Packet p) {
  if (!(!(!(!(!(!(!(p.pkt_0<state_0)))))))) {
    if (!(!(!(!(!(p.pkt_0<state_0)))))) {
      if (!(!(!(p.pkt_0<state_0)))) {
        if (!(p.pkt_0<state_0)) {
          state_0=p.pkt_0;
        }
      }
    }
  } else {
    if (!(!(!(!(!(!(p.pkt_0<state_0))))))) {
      if (!(!(!(!(p.pkt_0<state_0))))) {
        if (!(!(p.pkt_0<state_0))) {
          if (p.pkt_0<state_0) {
            state_1=state_1+1;
          }
        }
      }
    }
  }
}
