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
bit<32> pkt_49;
bit<32> pkt_50;
bit<32> pkt_51;
bit<32> pkt_52;
bit<32> pkt_53;
bit<32> pkt_54;
bit<32> pkt_55;
bit<32> pkt_56;
bit<32> pkt_57;
bit<32> pkt_58;
bit<32> pkt_59;
bit<32> pkt_60;
bit<32> pkt_61;
bit<32> pkt_62;
bit<32> pkt_63;
bit<32> pkt_64;
bit<32> pkt_65;
bit<32> pkt_66;
bit<32> pkt_67;
bit<32> pkt_68;
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
    action set_ingress_tc(bit<32> tc) {
        hdr.pkts.pkt_9 = tc;
    }
    action set_ingress_color(bit<32> color) {
        hdr.pkts.pkt_10 = color;
    }
    action set_ingress_tc_and_color(bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    table ingress_qos_map_pcp {
        actions = {
            
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            hdr.pkts.pkt_11 : exact;
            hdr.pkts.pkt_12           : exact;
        }
        size = 64;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_13 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_14                    : exact;
            hdr.pkts.pkt_15                        : exact;
            hdr.pkts.pkt_16 : exact;
        }
        size = 1024;
    }
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_17 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_18 : range;
        }
        size = 512;
    }
    action dmac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_19 = ifindex;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_20 ^ ifindex;
    }
    action dmac_multicast_hit(bit<32> mc_index) {
        hdr.pkts.pkt_21 = mc_index;
        hdr.pkts.pkt_22 = 127;
    }
    action dmac_miss() {
        hdr.pkts.pkt_19 = 65535;
        hdr.pkts.pkt_22 = 127;
    }
    action dmac_redirect_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_23 = 1;
        hdr.pkts.pkt_24 = nexthop_index;
        hdr.pkts.pkt_25 = 0;
    }
    action dmac_redirect_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_23 = 1;
        hdr.pkts.pkt_24 = ecmp_index;
        hdr.pkts.pkt_25 = 1;
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
            hdr.pkts.pkt_26   : exact;
            hdr.pkts.pkt_27 : exact;
        }
        size = 1024;
    }
    action urpf_bd_miss() {
        hdr.pkts.pkt_28 = 1;
    }
    table urpf_bd {
        actions = {
            
            urpf_bd_miss;
        }
        key = {
            hdr.pkts.pkt_29 : exact;
            hdr.pkts.pkt_26      : exact;
        }
        size = 1024;
    }
    action multicast_route_s_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_30 = mc_index;
        hdr.pkts.pkt_31 = 1;
        hdr.pkts.pkt_32 = 1;
        hdr.pkts.pkt_33 = mcast_rpf_group ^ hdr.pkts.pkt_34;
    }
    table ipv4_multicast_route {
        actions = {
            multicast_route_s_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_35 : exact;
            hdr.pkts.pkt_36 : exact;
        }
        size = 1024;
    }
    action multicast_bridge_star_g_hit_ipv6(bit<32> mc_index) {
        hdr.pkts.pkt_37 = mc_index;
        hdr.pkts.pkt_38 = 1;
    }
    table ipv6_multicast_bridge_star_g {
        actions = {
            multicast_bridge_star_g_hit_ipv6;
        }
        key = {
            hdr.pkts.pkt_26      : exact;
            hdr.pkts.pkt_39 : exact;
        }
        size = 1024;
    }
    action set_l2_redirect_action() {
        hdr.pkts.pkt_40 = hdr.pkts.pkt_41;
        hdr.pkts.pkt_42 = hdr.pkts.pkt_43;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_21 = 0;
        hdr.pkts.pkt_22 = 0;
    }
    action set_fib_redirect_action() {
        hdr.pkts.pkt_40 = hdr.pkts.pkt_44;
        hdr.pkts.pkt_42 = hdr.pkts.pkt_45;
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_21 = 0;
        hdr.pkts.pkt_47 = 217;
        hdr.pkts.pkt_22 = 0;
    }
    action set_cpu_redirect_action() {
        hdr.pkts.pkt_46 = 0;
        hdr.pkts.pkt_21 = 0;
        hdr.pkts.pkt_48 = 64;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_22 = 0;
    }
    action set_acl_redirect_action() {
        hdr.pkts.pkt_40 = hdr.pkts.pkt_49;
        hdr.pkts.pkt_42 = hdr.pkts.pkt_50;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_21 = 0;
        hdr.pkts.pkt_22 = 0;
    }
    action set_racl_redirect_action() {
        hdr.pkts.pkt_40 = hdr.pkts.pkt_51;
        hdr.pkts.pkt_42 = hdr.pkts.pkt_52;
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_21 = 0;
        hdr.pkts.pkt_22 = 0;
    }
    action set_nat_redirect_action() {
        hdr.pkts.pkt_40 = hdr.pkts.pkt_53;
        hdr.pkts.pkt_42 = hdr.pkts.pkt_54;
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_21 = 0;
        hdr.pkts.pkt_22 = 0;
    }
    action set_multicast_route_action() {
        hdr.pkts.pkt_22 = 127;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_55;
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_56 = 65535;
    }
    action set_multicast_bridge_action() {
        hdr.pkts.pkt_22 = 127;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_57;
    }
    action set_multicast_flood() {
        hdr.pkts.pkt_22 = 127;
        hdr.pkts.pkt_19 = 65535;
    }
    action set_multicast_drop() {
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_6 = 44;
    }
    table fwd_result {
        actions = {
            
            set_l2_redirect_action;
            set_fib_redirect_action;
            set_cpu_redirect_action;
            set_acl_redirect_action;
            set_racl_redirect_action;
            set_nat_redirect_action;
            set_multicast_route_action;
            set_multicast_bridge_action;
            set_multicast_flood;
            set_multicast_drop;
        }
        key = {
            hdr.pkts.pkt_23                 : exact;
            hdr.pkts.pkt_58               : exact;
            hdr.pkts.pkt_59              : exact;
            hdr.pkts.pkt_60                    : exact;
            hdr.pkts.pkt_61                     : exact;
            hdr.pkts.pkt_62                    : exact;
            hdr.pkts.pkt_63                : exact;
            hdr.pkts.pkt_0                 : exact;
            hdr.pkts.pkt_64 : exact;
            hdr.pkts.pkt_65 : exact;
            hdr.pkts.pkt_32      : exact;
            hdr.pkts.pkt_38     : exact;
            hdr.pkts.pkt_33      : exact;
            hdr.pkts.pkt_31           : exact;
        }
        size = 512;
    }
    action set_ecmp_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> nhop_index, bit<32> tunnel) {
        hdr.pkts.pkt_19 = ifindex;
        hdr.pkts.pkt_40 = nhop_index;
        hdr.pkts.pkt_56 = hdr.pkts.pkt_26 ^ bd;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_20 ^ ifindex;
        hdr.pkts.pkt_66 = hdr.pkts.pkt_67 ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index, bit<32> nhop_index) {
        hdr.pkts.pkt_21 = uuc_mc_index;
        hdr.pkts.pkt_40 = nhop_index;
        hdr.pkts.pkt_19 = 0;
        hdr.pkts.pkt_56 = hdr.pkts.pkt_26 ^ bd;
        hdr.pkts.pkt_22 = 127;
    }
    table ecmp_group {
        actions = {
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_40 : exact;
            hdr.pkts.pkt_68      : exact;
        }
        size = 1024;
    }

    apply {
        validate_outer_ipv4_packet.apply();
        ingress_qos_map_pcp.apply();
        ipv4_src_vtep.apply();
        ingress_l4_src_port.apply();
        dmac.apply();
        urpf_bd.apply();
        ipv4_multicast_route.apply();
        ipv6_multicast_bridge_star_g.apply();
        fwd_result.apply();
        ecmp_group.apply();
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
