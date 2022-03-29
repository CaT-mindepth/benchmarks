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
bit<32> pkt_69;
bit<32> pkt_70;
bit<32> pkt_71;
bit<32> pkt_72;
bit<32> pkt_73;
bit<32> pkt_74;
bit<32> pkt_75;
bit<32> pkt_76;
bit<32> pkt_77;
bit<32> pkt_78;
bit<32> pkt_79;
bit<32> pkt_80;
bit<32> pkt_81;
bit<32> pkt_82;
bit<32> pkt_83;
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
    action malformed_outer_ethernet_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = drop_reason;
    }
    action set_valid_outer_unicast_packet_untagged() {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action set_valid_outer_unicast_packet_single_tagged() {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
    }
    action set_valid_outer_unicast_packet_double_tagged() {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_16;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_17;
    }
    action set_valid_outer_unicast_packet_qinq_tagged() {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_19;
    }
    action set_valid_outer_multicast_packet_untagged() {
        hdr.pkts.pkt_10 = 2;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_20;
    }
    action set_valid_outer_multicast_packet_single_tagged() {
        hdr.pkts.pkt_10 = 2;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_21;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_22;
    }
    action set_valid_outer_multicast_packet_double_tagged() {
        hdr.pkts.pkt_10 = 2;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_24;
    }
    action set_valid_outer_multicast_packet_qinq_tagged() {
        hdr.pkts.pkt_10 = 2;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_25;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_26;
    }
    action set_valid_outer_broadcast_packet_untagged() {
        hdr.pkts.pkt_10 = 4;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_27;
    }
    action set_valid_outer_broadcast_packet_single_tagged() {
        hdr.pkts.pkt_10 = 4;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_29;
    }
    action set_valid_outer_broadcast_packet_double_tagged() {
        hdr.pkts.pkt_10 = 4;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_30;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_31;
    }
    action set_valid_outer_broadcast_packet_qinq_tagged() {
        hdr.pkts.pkt_10 = 4;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_32;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_33;
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
            hdr.pkts.pkt_34      : exact;
            hdr.pkts.pkt_35      : exact;
        }
        size = 512;
    }
    action set_valid_outer_ipv4_packet() {
        hdr.pkts.pkt_36 = 1;
        hdr.pkts.pkt_37 = hdr.pkts.pkt_38;
        hdr.pkts.pkt_39 = hdr.pkts.pkt_40;
    }
    action set_malformed_outer_ipv4_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = drop_reason;
    }
    table validate_outer_ipv4_packet {
        actions = {
            set_valid_outer_ipv4_packet;
            set_malformed_outer_ipv4_packet;
        }
        key = {
            hdr.pkts.pkt_40       : exact;
            hdr.pkts.pkt_41           : exact;
            hdr.pkts.pkt_42 : exact;
        }
        size = 512;
    }
    action set_ingress_tc(bit<32> tc) {
        hdr.pkts.pkt_3 = tc;
    }
    action set_ingress_color(bit<32> color) {
        hdr.pkts.pkt_4 = color;
    }
    action set_ingress_tc_and_color(bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    table ingress_qos_map_pcp {
        actions = {
            
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_14           : exact;
        }
        size = 64;
    }
    action outer_rmac_hit() {
        hdr.pkts.pkt_43 = 1;
    }
    table outer_rmac {
        actions = {
            
            outer_rmac_hit;
        }
        key = {
            hdr.pkts.pkt_44 : exact;
            hdr.pkts.pkt_35       : exact;
        }
        size = 1024;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_45 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_46                    : exact;
            hdr.pkts.pkt_47                        : exact;
            hdr.pkts.pkt_48 : exact;
        }
        size = 1024;
    }
    action acl_deny(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_49 = 1;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_51 = acl_meter_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_53 = nat_mode;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_permit(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_51 = acl_meter_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_53 = nat_mode;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_redirect_nexthop(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_55 = 1;
        hdr.pkts.pkt_56 = nexthop_index;
        hdr.pkts.pkt_57 = 0;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_51 = acl_meter_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_53 = nat_mode;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_redirect_ecmp(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_55 = 1;
        hdr.pkts.pkt_56 = ecmp_index;
        hdr.pkts.pkt_57 = 1;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_51 = acl_meter_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_53 = nat_mode;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_mirror(bit<32> session_id, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_58 = (bit<32>)session_id;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_51 = acl_meter_index;
        hdr.pkts.pkt_53 = nat_mode;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    table ip_acl {
        actions = {
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
            acl_mirror;
        }
        key = {
            hdr.pkts.pkt_0                 : exact;
            hdr.pkts.pkt_59                 : exact;
            hdr.pkts.pkt_60             : exact;
            hdr.pkts.pkt_61             : exact;
            hdr.pkts.pkt_62              : exact;
            hdr.pkts.pkt_63 : exact;
            hdr.pkts.pkt_64 : exact;
            hdr.pkts.pkt_65                              : exact;
            hdr.pkts.pkt_66                : exact;
        }
        size = 512;
    }
    action racl_deny(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_67 = 1;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action racl_permit(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action racl_redirect_nexthop(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_68 = 1;
        hdr.pkts.pkt_69 = nexthop_index;
        hdr.pkts.pkt_70 = 0;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action racl_redirect_ecmp(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_68 = 1;
        hdr.pkts.pkt_69 = ecmp_index;
        hdr.pkts.pkt_70 = 1;
        hdr.pkts.pkt_50 = acl_stats_index;
        hdr.pkts.pkt_52 = acl_copy_reason;
        hdr.pkts.pkt_54 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    table ipv4_racl {
        actions = {
            
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        key = {
            hdr.pkts.pkt_59                 : exact;
            hdr.pkts.pkt_60             : exact;
            hdr.pkts.pkt_61             : exact;
            hdr.pkts.pkt_62              : exact;
            hdr.pkts.pkt_63 : exact;
            hdr.pkts.pkt_64 : exact;
        }
        size = 512;
    }
    action multicast_bridge_star_g_hit_ipv6(bit<32> mc_index) {
        hdr.pkts.pkt_71 = mc_index;
        hdr.pkts.pkt_72 = 1;
    }
    table ipv6_multicast_bridge_star_g {
        actions = {
            multicast_bridge_star_g_hit_ipv6;
        }
        key = {
            hdr.pkts.pkt_73      : exact;
            hdr.pkts.pkt_74 : exact;
        }
        size = 1024;
    }
    action set_ecmp_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> nhop_index, bit<32> tunnel) {
        hdr.pkts.pkt_75 = ifindex;
        hdr.pkts.pkt_76 = nhop_index;
        hdr.pkts.pkt_77 = hdr.pkts.pkt_73 ^ bd;
        hdr.pkts.pkt_78 = hdr.pkts.pkt_78 ^ ifindex;
        hdr.pkts.pkt_79 = hdr.pkts.pkt_80 ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index, bit<32> nhop_index) {
        hdr.pkts.pkt_81 = uuc_mc_index;
        hdr.pkts.pkt_76 = nhop_index;
        hdr.pkts.pkt_75 = 0;
        hdr.pkts.pkt_77 = hdr.pkts.pkt_73 ^ bd;
        hdr.pkts.pkt_82 = 127;
    }
    table ecmp_group {
        actions = {
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_76 : exact;
            hdr.pkts.pkt_83      : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_properties.apply();
        validate_outer_ethernet.apply();
        validate_outer_ipv4_packet.apply();
        ingress_qos_map_pcp.apply();
        outer_rmac.apply();
        ipv4_src_vtep.apply();
        ip_acl.apply();
        ipv4_racl.apply();
        ipv6_multicast_bridge_star_g.apply();
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
