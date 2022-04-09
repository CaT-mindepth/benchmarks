#include <core.p4>
#include <v1model.p4>
header packets_t {
bit<32> pkt_0;
bit<32> pkt_1;
bit<32> pkt_2;
bit<32> pkt_3;
bit<32> pkt_4;
bit<32> pkt_5;
bit<32> pkt_6;
bit<32> pkt_7;
bit<32> pkt_8;
bit<32> pkt_9;
bit<32> pkt_10;
bit<32> pkt_11;
}
struct headers {
    packets_t  pkts;
}

struct metadata {
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.pkts);
        transition accept;
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_0 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_1 = 1;
        hdr.pkts.pkt_2 = mc_index;
        hdr.pkts.pkt_3 = 1;
        hdr.pkts.pkt_4 = mcast_rpf_group ^ hdr.pkts.pkt_5;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_1 = 2;
        hdr.pkts.pkt_2 = mc_index;
        hdr.pkts.pkt_3 = 1;
        hdr.pkts.pkt_4 = mcast_rpf_group | hdr.pkts.pkt_6;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_7          : exact;
            hdr.pkts.pkt_8 : exact;
        }
        size = 1024;
    }
    action set_bd_flood_mc_index(bit<32> mc_index) {
        hdr.pkts.pkt_9 = mc_index;
    }
    table bd_flood {
        actions = {
            
            set_bd_flood_mc_index;
        }
        key = {
            hdr.pkts.pkt_10     : exact;
            hdr.pkts.pkt_11 : exact;
        }
        size = 1024;
    }

    apply {
        ipv6_multicast_route_star_g.apply();
        bd_flood.apply();
    }
}

control egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {  }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply { }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
ingress(),
egress(),
MyComputeChecksum(),
MyDeparser()
) main;
