/* 
// Original program: 
struct Packet{
    int sport;
    int dport;
    int pkt_0;
    int pkt_1;
    int pkt_2;
};
int state_group_1_state_0 = 0;
int state_group_0_state_0 = 0;
void func(struct Packet p){
if (p.pkt_1-state_group_1_state_0>5&&1==1) {state_group_0_state_0=p.pkt_0;

;}
state_group_1_state_0=p.pkt_1;
p.pkt_2=state_group_0_state_0;
} */
|StateAndPacket| program (|StateAndPacket| state_and_packet) {
if (state_and_packet.pkt_1-state_and_packet.state_group_1_state_0>5&&1==1) {state_and_packet.state_group_0_state_0=state_and_packet.pkt_0;

;}
state_and_packet.state_group_1_state_0=state_and_packet.pkt_1;
state_and_packet.pkt_2=state_and_packet.state_group_0_state_0;
  return state_and_packet;
}