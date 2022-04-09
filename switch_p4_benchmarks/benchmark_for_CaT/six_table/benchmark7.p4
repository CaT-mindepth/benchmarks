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
    
        action set_ifindex(bit<32> ifindex, bit<32> port_type) {
               hdr.pkts.pkt_0 = ifindex;
               hdr.pkts.pkt_1 = port_type;
        }
        table ingress_port_mapping {
              actions = {
                  set_ifindex;
              }
              key = {
                  hdr.pkts.pkt_2 : exact;
              }
              size = 288;
        }
    action int_set_src() {
        hdr.pkts.pkt_3 = 1;
    }
    action int_set_no_src() {
        hdr.pkts.pkt_3 = 0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.pkts.pkt_4 : exact;
            hdr.pkts.pkt_5 : exact;
            hdr.pkts.pkt_6        : exact;
            hdr.pkts.pkt_7        : exact;
        }
        size = 256;
    }

    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = mc_index;
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = mcast_rpf_group ^ hdr.pkts.pkt_12;
        hdr.pkts.pkt_13 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_8 = 2;
        hdr.pkts.pkt_9 = mc_index;
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = mcast_rpf_group | hdr.pkts.pkt_14;
        hdr.pkts.pkt_13 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_9 = mc_index;
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_13 = 127;
    }
    table outer_ipv4_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_16 : exact;
            hdr.pkts.pkt_17     : exact;
            hdr.pkts.pkt_18                           : exact;
        }
        size = 512;
    }
    action set_storm_control_meter(bit<32> meter_idx) {
        hdr.pkts.pkt_19 = (bit<32>)meter_idx;
    }
    table storm_control {
        actions = {
            
            set_storm_control_meter;
        }
        key = {
            hdr.pkts.pkt_2 : exact;
            hdr.pkts.pkt_20 : exact;
        }
        size = 512;
    }
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_21 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_22 : range;
        }
        size = 512;
    }
    action set_dst_nat_nexthop_index(bit<32> nexthop_index, bit<32> nexthop_type, bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_23 = nexthop_index;
        hdr.pkts.pkt_24 = nexthop_type;
        hdr.pkts.pkt_25 = nat_rewrite_index;
        hdr.pkts.pkt_26 = 1;
    }
    table nat_dst {
        actions = {
            
            set_dst_nat_nexthop_index;
        }
        key = {
            hdr.pkts.pkt_27          : exact;
            hdr.pkts.pkt_4 : exact;
            hdr.pkts.pkt_28 : exact;
            hdr.pkts.pkt_29 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_mapping.apply();
        int_source.apply();
        outer_ipv4_multicast_star_g.apply();
        storm_control.apply();
        ingress_l4_src_port.apply();
        nat_dst.apply();
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
