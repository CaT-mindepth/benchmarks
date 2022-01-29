struct Packet{
    int loss;
    int qlen;
    int pkt_0;
    int link_idle;
    int cond1;
    int pkt_1;
};
int state_1;
int state_0;
void func(struct Packet p) {
  p.pkt_1=p.pkt_0- 3 - 5 - 2  + 1000 - 1000 + 2 - 2 + 3 - 3 - 3 + 3;
  if (2==2&&3==3&&4==4&&5==5&&1==1&&p.pkt_1>state_1&&1==1&&1==1&&3+2==2+3||0||-1==1) {
    state_0=state_0+1-1+2-2+3-3+1000-1000+1;
    state_1=p.pkt_0 + 99 - 99 - 88 + 88 - 77 - 66 + 77 + 66;
  }
}
