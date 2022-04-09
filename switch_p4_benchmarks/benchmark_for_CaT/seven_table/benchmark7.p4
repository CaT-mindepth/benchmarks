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
    
        action set_ingress_port_properties(bit<32> if_label, bit<32> qos_group, bit<32> tc_qos_group, bit<32> tc, bit<32> color, bit<32> trust_dscp, bit<32> trust_pcp) {
               hdr.pkts.pkt_0 = if_label;
               hdr.pkts.pkt_1 = qos_group;
               hdr.pkts.pkt_2 = tc_qos_group;
               hdr.pkts.pkt_3 = tc;
               hdr.pkts.pkt_4 = color;
               hdr.pkts.pkt_5 = trust_dscp;
               hdr.pkts.pkt_6 = trust_pcp;
        }
        table ingress_port_properties {
              actions = {
                  set_ingress_port_properties;
              }
              key = {
                  hdr.pkts.pkt_7 : exact;
              }
              size = 288;
        }
    action set_valid_outer_ipv4_packet() {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action set_malformed_outer_ipv4_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = drop_reason;
    }
    table validate_outer_ipv4_packet {
        actions = {
            set_valid_outer_ipv4_packet;
            set_malformed_outer_ipv4_packet;
        }
        key = {
            hdr.pkts.pkt_12       : exact;
            hdr.pkts.pkt_15           : exact;
            hdr.pkts.pkt_16 : exact;
        }
        size = 512;
    }
    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_17 = 1;
        hdr.pkts.pkt_18 = mc_index;
        hdr.pkts.pkt_19 = 1;
        hdr.pkts.pkt_20 = mcast_rpf_group ^ hdr.pkts.pkt_21;
        hdr.pkts.pkt_22 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_17 = 2;
        hdr.pkts.pkt_18 = mc_index;
        hdr.pkts.pkt_19 = 1;
        hdr.pkts.pkt_20 = mcast_rpf_group | hdr.pkts.pkt_23;
        hdr.pkts.pkt_22 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_18 = mc_index;
        hdr.pkts.pkt_24 = 1;
        hdr.pkts.pkt_22 = 127;
    }
    table outer_ipv4_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_25 : exact;
            hdr.pkts.pkt_26     : exact;
            hdr.pkts.pkt_27                           : exact;
        }
        size = 512;
    }
    action set_ingress_dst_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_28 = range_id;
    }
    table ingress_l4_dst_port {
        actions = {
            
            set_ingress_dst_port_range_id;
        }
        key = {
            hdr.pkts.pkt_29 : range;
        }
        size = 512;
    }
    action dmac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_30 = ifindex;
        hdr.pkts.pkt_31 = hdr.pkts.pkt_31 ^ ifindex;
    }
    action dmac_multicast_hit(bit<32> mc_index) {
        hdr.pkts.pkt_18 = mc_index;
        hdr.pkts.pkt_22 = 127;
    }
    action dmac_miss() {
        hdr.pkts.pkt_30 = 65535;
        hdr.pkts.pkt_22 = 127;
    }
    action dmac_redirect_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_32 = 1;
        hdr.pkts.pkt_33 = nexthop_index;
        hdr.pkts.pkt_34 = 0;
    }
    action dmac_redirect_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_32 = 1;
        hdr.pkts.pkt_33 = ecmp_index;
        hdr.pkts.pkt_34 = 1;
    }
    table dmac {
        support_timeout = true;
        actions = {
            
            dmac_hit;
            dmac_multicast_hit;
            dmac_miss;
            dmac_redirect_nexthop;
            dmac_redirect_ecmp;
        }
        key = {
            hdr.pkts.pkt_35   : exact;
            hdr.pkts.pkt_36 : exact;
        }
        size = 1024;
    }
    action smac_miss() {
        hdr.pkts.pkt_37 = 1;
    }
    action smac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_38 = hdr.pkts.pkt_39 ^ ifindex;
    }
    table smac {
        actions = {
            
            smac_miss;
            smac_hit;
        }
        key = {
            hdr.pkts.pkt_35   : exact;
            hdr.pkts.pkt_40 : exact;
        }
        size = 1024;
    }
    action set_src_nat_rewrite_index(bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_41 = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            
            set_src_nat_rewrite_index;
        }
        key = {
            hdr.pkts.pkt_42          : exact;
            hdr.pkts.pkt_43 : exact;
            hdr.pkts.pkt_44 : exact;
            hdr.pkts.pkt_45 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_properties.apply();
        validate_outer_ipv4_packet.apply();
        outer_ipv4_multicast_star_g.apply();
        ingress_l4_dst_port.apply();
        dmac.apply();
        smac.apply();
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
