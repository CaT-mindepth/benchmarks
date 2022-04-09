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
bit<32> pkt_25;
bit<32> pkt_26;
bit<32> pkt_27;
bit<32> pkt_28;
bit<32> pkt_29;
bit<32> pkt_30;
bit<32> pkt_31;
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
    
    action set_valid_mpls_label1() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
    }
    action set_valid_mpls_label2() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_4;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_5;
    }
    action set_valid_mpls_label3() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_6;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_7;
    }
    table validate_mpls_packet {
        actions = {
            set_valid_mpls_label1;
            set_valid_mpls_label2;
            set_valid_mpls_label3;
        }
        key = {
            hdr.pkts.pkt_1    : exact;
            hdr.pkts.pkt_8      : exact;
            hdr.pkts.pkt_4    : exact;
            hdr.pkts.pkt_9      : exact;
            hdr.pkts.pkt_6    : exact;
            hdr.pkts.pkt_10      : exact;
        }
        size = 512;
    }
    action set_ingress_tc(bit<32> tc) {
        hdr.pkts.pkt_11 = tc;
    }
    action set_ingress_color(bit<32> color) {
        hdr.pkts.pkt_12 = color;
    }
    action set_ingress_tc_and_color(bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_11 = tc;
        hdr.pkts.pkt_12 = color;
    }
    table ingress_qos_map_pcp {
        actions = {
            
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            hdr.pkts.pkt_13 : exact;
            hdr.pkts.pkt_14           : exact;
        }
        size = 64;
    }
    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_15 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_16 = tunnel_vni;
        hdr.pkts.pkt_15 = 1;
    }
    table ipv6_dest_vtep {
        actions = {
            
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_17                    : exact;
            hdr.pkts.pkt_18                        : exact;
            hdr.pkts.pkt_19 : exact;
        }
        size = 1024;
    }
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_20 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_21 = 1;
        hdr.pkts.pkt_22 = mc_index;
        hdr.pkts.pkt_23 = 1;
        hdr.pkts.pkt_24 = mcast_rpf_group ^ hdr.pkts.pkt_25;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_21 = 2;
        hdr.pkts.pkt_22 = mc_index;
        hdr.pkts.pkt_23 = 1;
        hdr.pkts.pkt_24 = mcast_rpf_group | hdr.pkts.pkt_26;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_17          : exact;
            hdr.pkts.pkt_27 : exact;
        }
        size = 1024;
    }
    action set_src_nat_rewrite_index(bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_28 = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            
            set_src_nat_rewrite_index;
        }
        key = {
            hdr.pkts.pkt_17          : exact;
            hdr.pkts.pkt_29 : exact;
            hdr.pkts.pkt_30 : exact;
            hdr.pkts.pkt_31 : exact;
        }
        size = 1024;
    }

    apply {
        validate_mpls_packet.apply();
        ingress_qos_map_pcp.apply();
        ipv6_dest_vtep.apply();
        ipv6_multicast_route_star_g.apply();
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
