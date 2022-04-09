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
bit<32> pkt_20;
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
    
    action set_ingress_tc(bit<32> tc) {
        hdr.pkts.pkt_0 = 5;
    }
    action set_ingress_color(bit<32> color) {
        hdr.pkts.pkt_1 = 5;
    }
    action set_ingress_tc_and_color(bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_0 = 5;
        hdr.pkts.pkt_1 = 5;
    }
    table ingress_qos_map_pcp {
        actions = {
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            hdr.pkts.pkt_2 : exact;
            hdr.pkts.pkt_3           : exact;
        }
        size = 64;
    }
    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_4 = 1;
        hdr.pkts.pkt_5 = 5;
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = hdr.pkts.pkt_8;
        hdr.pkts.pkt_9 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_4 = 2;
        hdr.pkts.pkt_5 = 5;
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_9 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_5 = 5;
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_9 = 127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_12 : exact;
            hdr.pkts.pkt_13     : exact;
            hdr.pkts.pkt_14                           : exact;
        }
        size = 512;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_16 = 5;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_18;
    }
    table ipv6_urpf {
        actions = {
            ipv6_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_19          : exact;
            hdr.pkts.pkt_20 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_qos_map_pcp.apply();
        outer_ipv6_multicast_star_g.apply();
        ipv6_urpf.apply();
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
