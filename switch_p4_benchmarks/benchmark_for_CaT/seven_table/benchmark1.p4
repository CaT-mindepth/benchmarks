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
bit<32> pkt_32;
bit<32> pkt_33;
bit<32> pkt_34;
bit<32> pkt_35;
bit<32> pkt_36;
bit<32> pkt_37;
bit<32> pkt_38;
bit<32> pkt_39;
bit<32> pkt_40;
bit<32> pkt_41;
bit<32> pkt_42;
bit<32> pkt_43;
bit<32> pkt_44;
bit<32> pkt_45;
bit<32> pkt_46;
bit<32> pkt_47;
bit<32> pkt_48;
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
    action set_valid_mpls_label1() {
        hdr.pkts.pkt_9 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action set_valid_mpls_label2() {
        hdr.pkts.pkt_9 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_14;
    }
    action set_valid_mpls_label3() {
        hdr.pkts.pkt_9 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_16;
    }
    table validate_mpls_packet {
        actions = {
            set_valid_mpls_label1;
            set_valid_mpls_label2;
            set_valid_mpls_label3;
        }
        key = {
            hdr.pkts.pkt_10    : exact;
            hdr.pkts.pkt_17      : exact;
            hdr.pkts.pkt_13    : exact;
            hdr.pkts.pkt_18      : exact;
            hdr.pkts.pkt_15    : exact;
            hdr.pkts.pkt_19      : exact;
        }
        size = 512;
    }
    action int_set_src() {
        hdr.pkts.pkt_20 = 1;
    }
    action int_set_no_src() {
        hdr.pkts.pkt_20 = 0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.pkts.pkt_21 : exact;
            hdr.pkts.pkt_22 : exact;
            hdr.pkts.pkt_23        : exact;
            hdr.pkts.pkt_24        : exact;
        }
        size = 256;
    }

    action outer_multicast_route_s_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_25 = mc_index;
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = mcast_rpf_group ^ hdr.pkts.pkt_28;
        hdr.pkts.pkt_29 = 127;
    }
    action outer_multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_25 = mc_index;
        hdr.pkts.pkt_30 = 1;
        hdr.pkts.pkt_29 = 127;
    }
    table outer_ipv4_multicast {
        actions = {
            
            
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_31 : exact;
            hdr.pkts.pkt_32     : exact;
            hdr.pkts.pkt_33                           : exact;
            hdr.pkts.pkt_34                           : exact;
        }
        size = 1024;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_36 = urpf_bd_group;
        hdr.pkts.pkt_37 = hdr.pkts.pkt_38;
    }
    action urpf_miss() {
        hdr.pkts.pkt_39 = 1;
    }
    table ipv6_urpf_lpm {
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        key = {
            hdr.pkts.pkt_40          : exact;
            hdr.pkts.pkt_41 : exact;
        }
        size = 512;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_42 = mc_index;
        hdr.pkts.pkt_43 = 1;
    }
    table ipv4_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_44      : exact;
            hdr.pkts.pkt_22 : exact;
            hdr.pkts.pkt_21 : exact;
        }
        size = 1024;
    }
    action set_icos(bit<32> icos) {
        hdr.pkts.pkt_45 = icos;
    }
    action set_queue(bit<32> qid) {
        hdr.pkts.pkt_46 = qid;
    }
    action set_icos_and_queue(bit<32> icos, bit<32> qid) {
        hdr.pkts.pkt_45 = icos;
        hdr.pkts.pkt_46 = qid;
    }
    table traffic_class {
        actions = {
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        key = {
            hdr.pkts.pkt_47 : exact;
            hdr.pkts.pkt_48      : exact;
        }
        size = 512;
    }

    apply {
        validate_outer_ipv4_packet.apply();
        validate_mpls_packet.apply();
        int_source.apply();
        outer_ipv4_multicast.apply();
        ipv6_urpf_lpm.apply();
        ipv4_multicast_bridge.apply();
        traffic_class.apply();
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
