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
bit<32> pkt_12;
bit<32> pkt_13;
bit<32> pkt_14;
bit<32> pkt_15;
bit<32> pkt_16;
bit<32> pkt_17;
bit<32> pkt_18;
bit<32> pkt_19;
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
    
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_0 = ifindex;
    }
    table ipv6_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_1                    : exact;
            hdr.pkts.pkt_2                        : exact;
            hdr.pkts.pkt_3 : exact;
        }
        size = 1024;
    }
    action set_ingress_dst_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_4 = range_id;
    }
    table ingress_l4_dst_port {
        actions = {
            
            set_ingress_dst_port_range_id;
        }
        key = {
            hdr.pkts.pkt_5 : range;
        }
        size = 512;
    }
    action multicast_bridge_star_g_hit_ipv6(bit<32> mc_index) {
        hdr.pkts.pkt_6 = mc_index;
        hdr.pkts.pkt_7 = 1;
    }
    table ipv6_multicast_bridge_star_g {
        actions = {
            multicast_bridge_star_g_hit_ipv6;
        }
        key = {
            hdr.pkts.pkt_8      : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }
    action multicast_route_s_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_10 = mc_index;
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_12 = 1;
        hdr.pkts.pkt_13 = mcast_rpf_group ^ hdr.pkts.pkt_14;
    }
    table ipv6_multicast_route {
        actions = {
            multicast_route_s_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_1          : exact;
            hdr.pkts.pkt_15 : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }
    action set_src_nat_rewrite_index(bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_16 = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            
            set_src_nat_rewrite_index;
        }
        key = {
            hdr.pkts.pkt_1          : exact;
            hdr.pkts.pkt_17 : exact;
            hdr.pkts.pkt_18 : exact;
            hdr.pkts.pkt_19 : exact;
        }
        size = 1024;
    }

    apply {
        ipv6_src_vtep.apply();
        ingress_l4_dst_port.apply();
        ipv6_multicast_bridge_star_g.apply();
        ipv6_multicast_route.apply();
        nat_src.apply();
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
