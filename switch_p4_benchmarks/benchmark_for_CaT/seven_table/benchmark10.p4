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
    
    action int_set_src() {
        hdr.pkts.pkt_0 = 1;
    }
    action int_set_no_src() {
        hdr.pkts.pkt_0 = 0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_2 : exact;
            hdr.pkts.pkt_3        : exact;
            hdr.pkts.pkt_4        : exact;
        }
        size = 256;
    }

    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_6 = mc_index;
        hdr.pkts.pkt_7 = 1;
        hdr.pkts.pkt_8 = mcast_rpf_group ^ hdr.pkts.pkt_9;
        hdr.pkts.pkt_10 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_5 = 2;
        hdr.pkts.pkt_6 = mc_index;
        hdr.pkts.pkt_7 = 1;
        hdr.pkts.pkt_8 = mcast_rpf_group | hdr.pkts.pkt_11;
        hdr.pkts.pkt_10 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_6 = mc_index;
        hdr.pkts.pkt_12 = 1;
        hdr.pkts.pkt_10 = 127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_13 : exact;
            hdr.pkts.pkt_14     : exact;
            hdr.pkts.pkt_15                           : exact;
        }
        size = 512;
    }
    action set_ingress_dst_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_16 = range_id;
    }
    table ingress_l4_dst_port {
        actions = {
            
            set_ingress_dst_port_range_id;
        }
        key = {
            hdr.pkts.pkt_17 : range;
        }
        size = 512;
    }
    action acl_deny_mac(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_meter_index;
        hdr.pkts.pkt_21 = acl_copy_reason;
        hdr.pkts.pkt_22 = nat_mode;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action acl_permit_mac(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_meter_index;
        hdr.pkts.pkt_21 = acl_copy_reason;
        hdr.pkts.pkt_22 = nat_mode;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action acl_redirect_nexthop_mac(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = nexthop_index;
        hdr.pkts.pkt_28 = 0;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_meter_index;
        hdr.pkts.pkt_21 = acl_copy_reason;
        hdr.pkts.pkt_22 = nat_mode;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action acl_redirect_ecmp_mac(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = ecmp_index;
        hdr.pkts.pkt_28 = 1;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_meter_index;
        hdr.pkts.pkt_21 = acl_copy_reason;
        hdr.pkts.pkt_22 = nat_mode;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action acl_mirror_mac(bit<32> session_id, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_29 = (bit<32>)session_id;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_meter_index;
        hdr.pkts.pkt_22 = nat_mode;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    table mac_acl {
        actions = {
            acl_deny_mac;
            acl_permit_mac;
            acl_redirect_nexthop_mac;
            acl_redirect_ecmp_mac;
            acl_mirror_mac;
        }
        key = {
            hdr.pkts.pkt_30   : exact;
            hdr.pkts.pkt_31   : exact;
            hdr.pkts.pkt_32  : exact;
            hdr.pkts.pkt_33  : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 512;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_36 = urpf_bd_group;
        hdr.pkts.pkt_37 = hdr.pkts.pkt_38;
    }
    table ipv6_urpf {
        actions = {
            
            ipv6_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_39          : exact;
            hdr.pkts.pkt_40 : exact;
        }
        size = 1024;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_41 = 1;
        hdr.pkts.pkt_42 = nexthop_index;
        hdr.pkts.pkt_43 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_41 = 1;
        hdr.pkts.pkt_42 = ecmp_index;
        hdr.pkts.pkt_43 = 1;
    }
    table ipv6_fib_lpm {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_39          : exact;
            hdr.pkts.pkt_44 : exact;
        }
        size = 512;
    }
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_45 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_47 = mc_index;
        hdr.pkts.pkt_48 = 1;
        hdr.pkts.pkt_8 = mcast_rpf_group ^ hdr.pkts.pkt_49;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_46 = 2;
        hdr.pkts.pkt_47 = mc_index;
        hdr.pkts.pkt_48 = 1;
        hdr.pkts.pkt_8 = mcast_rpf_group | hdr.pkts.pkt_50;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_39          : exact;
            hdr.pkts.pkt_44 : exact;
        }
        size = 1024;
    }

    apply {
        int_source.apply();
        outer_ipv6_multicast_star_g.apply();
        ingress_l4_dst_port.apply();
        mac_acl.apply();
        ipv6_urpf.apply();
        ipv6_fib_lpm.apply();
        ipv6_multicast_route_star_g.apply();
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
