struct Packet{
};void flowlet( struct Packet pkt) {
    pkt.id00 = (pkt._br_tmp0) ? (pkt.new_hop) : saved_hop[pkt.id];
    pkt.saved_hop00 = saved_hop[pkt.id00];
    pkt.id10 = pkt.arrival;
    pkt.last_time00 = last_time[pkt.id10];
    pkt.tmp0 = pkt.arrival - pkt.last_time00;
    pkt._br_tmp00 = pkt.tmp0 > 5;
    pkt.saved_hop01 = (pkt._br_tmp00) ? (pkt.new_hop) : pkt.saved_hop00;
    pkt.last_time01 = pkt.arrival;
    pkt.next_hop0 = (pkt._br_tmp00) ? (pkt.new_hop) : pkt.saved_hop00;
    saved_hop[pkt.id00] = (pkt._br_tmp00) ? (pkt.new_hop) : pkt.saved_hop00;
    last_time[pkt.id10] = pkt.arrival;
}
