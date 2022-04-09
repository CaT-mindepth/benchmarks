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
    
    action malformed_outer_ethernet_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_0 = 1;
        hdr.pkts.pkt_1 = drop_reason;
    }
    action set_valid_outer_unicast_packet_untagged() {
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_4;
    }
    action set_valid_outer_unicast_packet_single_tagged() {
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
    }
    action set_valid_outer_unicast_packet_double_tagged() {
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_8;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_9;
    }
    action set_valid_outer_unicast_packet_qinq_tagged() {
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_11;
    }
    action set_valid_outer_multicast_packet_untagged() {
        hdr.pkts.pkt_2 = 2;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_12;
    }
    action set_valid_outer_multicast_packet_single_tagged() {
        hdr.pkts.pkt_2 = 2;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_14;
    }
    action set_valid_outer_multicast_packet_double_tagged() {
        hdr.pkts.pkt_2 = 2;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_16;
    }
    action set_valid_outer_multicast_packet_qinq_tagged() {
        hdr.pkts.pkt_2 = 2;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_17;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_18;
    }
    action set_valid_outer_broadcast_packet_untagged() {
        hdr.pkts.pkt_2 = 4;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_19;
    }
    action set_valid_outer_broadcast_packet_single_tagged() {
        hdr.pkts.pkt_2 = 4;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_20;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_21;
    }
    action set_valid_outer_broadcast_packet_double_tagged() {
        hdr.pkts.pkt_2 = 4;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_22;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_23;
    }
    action set_valid_outer_broadcast_packet_qinq_tagged() {
        hdr.pkts.pkt_2 = 4;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_25;
    }
    table validate_outer_ethernet {
        actions = {
            malformed_outer_ethernet_packet;
            set_valid_outer_unicast_packet_untagged;
            set_valid_outer_unicast_packet_single_tagged;
            set_valid_outer_unicast_packet_double_tagged;
            set_valid_outer_unicast_packet_qinq_tagged;
            set_valid_outer_multicast_packet_untagged;
            set_valid_outer_multicast_packet_single_tagged;
            set_valid_outer_multicast_packet_double_tagged;
            set_valid_outer_multicast_packet_qinq_tagged;
            set_valid_outer_broadcast_packet_untagged;
            set_valid_outer_broadcast_packet_single_tagged;
            set_valid_outer_broadcast_packet_double_tagged;
            set_valid_outer_broadcast_packet_qinq_tagged;
        }
        key = {
            hdr.pkts.pkt_26      : exact;
            hdr.pkts.pkt_27      : exact;
        }
        size = 512;
    }
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_28 : exact;
        }
        size = 1024;
    }
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_29 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_30 : range;
        }
        size = 512;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_31 = 1;
        hdr.pkts.pkt_32 = nexthop_index;
        hdr.pkts.pkt_33 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_31 = 1;
        hdr.pkts.pkt_32 = ecmp_index;
        hdr.pkts.pkt_33 = 1;
    }
    table ipv6_fib_lpm {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_34          : exact;
            hdr.pkts.pkt_35 : exact;
        }
        size = 512;
    }
    action multicast_route_s_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_36 = mc_index;
        hdr.pkts.pkt_37 = 1;
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_39 = mcast_rpf_group ^ hdr.pkts.pkt_40;
    }
    table ipv4_multicast_route {
        actions = {
            multicast_route_s_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_34          : exact;
            hdr.pkts.pkt_41 : exact;
            hdr.pkts.pkt_42 : exact;
        }
        size = 1024;
    }

    apply {
        validate_outer_ethernet.apply();
        fabric_ingress_src_lkp.apply();
        ingress_l4_src_port.apply();
        ipv6_fib_lpm.apply();
        ipv4_multicast_route.apply();
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
