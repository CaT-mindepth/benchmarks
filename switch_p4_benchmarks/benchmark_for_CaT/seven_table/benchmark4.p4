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
    
    action int_sink_gpe(bit<32> mirror_id) {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1 << 2;
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = mirror_id;
    }
    action int_no_sink() {
        hdr.pkts.pkt_2 = 0;
    }
    table int_terminate {
        actions = {
            int_sink_gpe;
            int_no_sink;
        }
        key = {
            hdr.pkts.pkt_4    : exact;
            hdr.pkts.pkt_5            : exact;
        }
        size = 256;
    }

    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = mc_index;
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = mcast_rpf_group ^ hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_6 = 2;
        hdr.pkts.pkt_7 = mc_index;
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = mcast_rpf_group | hdr.pkts.pkt_12;
        hdr.pkts.pkt_11 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_7 = mc_index;
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_11 = 127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_14 : exact;
            hdr.pkts.pkt_15     : exact;
            hdr.pkts.pkt_16                           : exact;
        }
        size = 512;
    }
    action set_storm_control_meter(bit<32> meter_idx) {
        hdr.pkts.pkt_17 = (bit<32>)meter_idx;
    }
    table storm_control {
        actions = {
            
            set_storm_control_meter;
        }
        key = {
            hdr.pkts.pkt_18 : exact;
            hdr.pkts.pkt_19 : exact;
        }
        size = 512;
    }
    action racl_deny(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_20 = 1;
        hdr.pkts.pkt_21 = acl_stats_index;
        hdr.pkts.pkt_22 = acl_copy_reason;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action racl_permit(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_21 = acl_stats_index;
        hdr.pkts.pkt_22 = acl_copy_reason;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action racl_redirect_nexthop(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = nexthop_index;
        hdr.pkts.pkt_28 = 0;
        hdr.pkts.pkt_21 = acl_stats_index;
        hdr.pkts.pkt_22 = acl_copy_reason;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    action racl_redirect_ecmp(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = ecmp_index;
        hdr.pkts.pkt_28 = 1;
        hdr.pkts.pkt_21 = acl_stats_index;
        hdr.pkts.pkt_22 = acl_copy_reason;
        hdr.pkts.pkt_23 = ingress_cos;
        hdr.pkts.pkt_24 = tc;
        hdr.pkts.pkt_25 = color;
    }
    table ipv6_racl {
        actions = {
            
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        key = {
            hdr.pkts.pkt_29                 : exact;
            hdr.pkts.pkt_30             : exact;
            hdr.pkts.pkt_31             : exact;
            hdr.pkts.pkt_32              : exact;
            hdr.pkts.pkt_33 : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 512;
    }
    action multicast_route_star_g_miss_0() {
        hdr.pkts.pkt_35 = 1;
    }
    action multicast_route_sm_star_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_36 = 1;
        hdr.pkts.pkt_37 = mc_index;
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_9 = mcast_rpf_group ^ hdr.pkts.pkt_39;
    }
    action multicast_route_bidir_star_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_36 = 2;
        hdr.pkts.pkt_37 = mc_index;
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_9 = mcast_rpf_group | hdr.pkts.pkt_40;
    }
    table ipv4_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_0;
            multicast_route_sm_star_g_hit_0;
            multicast_route_bidir_star_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_41          : exact;
            hdr.pkts.pkt_4 : exact;
        }
        size = 1024;
    }
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_35 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_36 = 1;
        hdr.pkts.pkt_37 = mc_index;
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_9 = mcast_rpf_group ^ hdr.pkts.pkt_42;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_36 = 2;
        hdr.pkts.pkt_37 = mc_index;
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_9 = mcast_rpf_group | hdr.pkts.pkt_43;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_41          : exact;
            hdr.pkts.pkt_31 : exact;
        }
        size = 1024;
    }
    action set_fabric_lag_port(bit<32> port) {
        hdr.pkts.pkt_44 = port;
    }
    action set_fabric_multicast(bit<32> fabric_mgid) {
        hdr.pkts.pkt_45 = hdr.pkts.pkt_46;
    }
    table fabric_lag {
        actions = {
            
            set_fabric_lag_port;
            set_fabric_multicast;
        }
        key = {
            hdr.pkts.pkt_11 : exact;
            hdr.pkts.pkt_47       : exact;
        }
    }

    apply {
        int_terminate.apply();
        outer_ipv6_multicast_star_g.apply();
        storm_control.apply();
        ipv6_racl.apply();
        ipv4_multicast_route_star_g.apply();
        ipv6_multicast_route_star_g.apply();
        fabric_lag.apply();
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
