int p_pkt_0;
int p_state_000;
int p_state_001;
int p_state_100;
int p_state_101;
# state variables start
int state_0;
int state_1;
# state variables end
bit p__br_tmp4;
bit p__br_tmp5;
# declarations end
p_state_000 = state_0;
p_state_100 = state_1;
p__br_tmp4 = !(p_pkt_0<p_state_000);
p_state_001 = p__br_tmp4 ? (p_pkt_0) : (p_state_000);
p__br_tmp5 = p_pkt_0<p_state_000&&(p_pkt_0<p_state_001)&&(p_pkt_0<p_state_001);
p_state_101 = p__br_tmp5 ? (1+p_state_100) : (p_state_100);
state_0 = p_state_001;
state_1 = p_state_101;

