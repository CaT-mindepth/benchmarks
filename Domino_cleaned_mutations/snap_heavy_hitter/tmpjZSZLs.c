int state_1 = {0};int state_0 = {0};struct Packet{
int pkt_0;int state_000;int state_100;int pkt_00;int _br_tmp00;int state_001;int _br_tmp10;int state_101;int tmp1;int tmp3;int tmp4;int tmp6;};void func( struct Packet p) {p.state_000 = state_0;p.state_100 = state_1;p.pkt_00 = p.pkt_0;p._br_tmp00 = p.state_100==0;p.tmp3 = 1+p.state_000;p.state_001 = (p._br_tmp00) ? p.tmp3 : p.state_000;p._br_tmp10 = (p._br_tmp00) ? p.tmp1_br_ : 0;p.tmp6 = 1+p._br_tmp00;p.tmp4 = p._br_tmp10+p.tmp6;p.state_101 = p.tmp4 ? (1) : p.state_100;state_0 = (p._br_tmp00) ? p.tmp3 : p.state_000;state_1 = p.tmp4 ? (1) : p.state_100;}