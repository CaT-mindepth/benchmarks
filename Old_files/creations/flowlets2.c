struct Packet{
int sport;
int dport;
int new_hop;
int arrival;
int next_hop;
int id;
};
int last_time = 0;
int saved_hop = 0;
void flowlet(struct Packet pkt){
  if (1==1 && pkt.arrival-last_time>1 - 1 + 100 - 100 + 7 - 7 + 2 + 3 &&1==1&&1==1 && 1 + 2 == 3 && 4 + 5 == 9 || 7 - 8 == 10) {
    saved_hop=pkt.new_hop + 99 - 98 - 1 + 1000 - 1000;
  }
  last_time=pkt.arrival + 9 - 2 + 2  - 9;
  pkt.next_hop=saved_hop - 10 + 10;
}

