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
bit<32> pkt_21;
bit<32> pkt_22;
bit<32> pkt_23;
bit<32> pkt_24;
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
    
    action set_valid_outer_ipv4_packet() {
        hdr.pkts.pkt_0 = 1;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_2;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_4;
    }
    action set_malformed_outer_ipv4_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_6 = drop_reason;
    }
    table validate_outer_ipv4_packet {
        actions = {
            set_valid_outer_ipv4_packet;
            set_malformed_outer_ipv4_packet;
        }
        key = {
            hdr.pkts.pkt_4       : exact;
            hdr.pkts.pkt_7           : exact;
            hdr.pkts.pkt_8 : exact;
        }
        size = 512;
    }
    action set_stp_state(bit<32> stp_state) {
        hdr.pkts.pkt_9 = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            hdr.pkts.pkt_10 : exact;
            hdr.pkts.pkt_11   : exact;
        }
        size = 1024;
    }
    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_12 = 1;
        hdr.pkts.pkt_13 = mc_index;
        hdr.pkts.pkt_14 = 1;
        hdr.pkts.pkt_15 = mcast_rpf_group ^ hdr.pkts.pkt_16;
        hdr.pkts.pkt_17 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_12 = 2;
        hdr.pkts.pkt_13 = mc_index;
        hdr.pkts.pkt_14 = 1;
        hdr.pkts.pkt_15 = mcast_rpf_group | hdr.pkts.pkt_18;
        hdr.pkts.pkt_17 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_13 = mc_index;
        hdr.pkts.pkt_19 = 1;
        hdr.pkts.pkt_17 = 127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_20 : exact;
            hdr.pkts.pkt_21     : exact;
            hdr.pkts.pkt_22                           : exact;
        }
        size = 512;
    }
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_23 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_24 : range;
        }
        size = 512;
    }

    apply {
        validate_outer_ipv4_packet.apply();
        spanning_tree.apply();
        outer_ipv6_multicast_star_g.apply();
        ingress_l4_src_port.apply();
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
