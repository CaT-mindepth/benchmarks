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
    action sflow_ing_pkt_to_cpu(bit<32> sflow_i2e_mirror_id) {
        hdr.pkts.pkt_8 = (bit<32>)sflow_i2e_mirror_id;
    }
    table sflow_ing_take_sample {
        actions = {
            
            sflow_ing_pkt_to_cpu;
        }
        key = {
            hdr.pkts.pkt_9 : exact;
            hdr.pkts.pkt_10   : exact;
        }
        size = 16;
    }
    action sflow_ing_session_enable_0(bit<32> rate_thr, bit<32> session_id) {
        hdr.pkts.pkt_9 = rate_thr + hdr.pkts.pkt_9;
        hdr.pkts.pkt_10 = session_id;
    }
    table sflow_ingress {
        actions = {
            sflow_ing_session_enable_0;
        }
        key = {
            hdr.pkts.pkt_12 : exact;
            hdr.pkts.pkt_13 : exact;
            hdr.pkts.pkt_14 : exact;
        }
        size = 512;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_12 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_15                    : exact;
            hdr.pkts.pkt_16                        : exact;
            hdr.pkts.pkt_17 : exact;
        }
        size = 1024;
    }
    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = mc_index;
        hdr.pkts.pkt_20 = 1;
        hdr.pkts.pkt_21 = mcast_rpf_group ^ hdr.pkts.pkt_22;
        hdr.pkts.pkt_23 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_18 = 2;
        hdr.pkts.pkt_19 = mc_index;
        hdr.pkts.pkt_20 = 1;
        hdr.pkts.pkt_21 = mcast_rpf_group | hdr.pkts.pkt_24;
        hdr.pkts.pkt_23 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_19 = mc_index;
        hdr.pkts.pkt_25 = 1;
        hdr.pkts.pkt_23 = 127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_26 : exact;
            hdr.pkts.pkt_27     : exact;
            hdr.pkts.pkt_28                           : exact;
        }
        size = 512;
    }
    action racl_deny_ipv4(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_29 = 1;
        hdr.pkts.pkt_30 = acl_stats_index;
        hdr.pkts.pkt_31 = acl_copy_reason;
        hdr.pkts.pkt_32 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action racl_permit_ipv4(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_30 = acl_stats_index;
        hdr.pkts.pkt_31 = acl_copy_reason;
        hdr.pkts.pkt_32 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action racl_redirect_nexthop_ipv4(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_33 = 1;
        hdr.pkts.pkt_34 = nexthop_index;
        hdr.pkts.pkt_35 = 0;
        hdr.pkts.pkt_30 = acl_stats_index;
        hdr.pkts.pkt_31 = acl_copy_reason;
        hdr.pkts.pkt_32 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action racl_redirect_ecmp_ipv4(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_33 = 1;
        hdr.pkts.pkt_34 = ecmp_index;
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_30 = acl_stats_index;
        hdr.pkts.pkt_31 = acl_copy_reason;
        hdr.pkts.pkt_32 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    table ipv4_racl {
        actions = {
            
            racl_deny_ipv4;
            racl_permit_ipv4;
            racl_redirect_nexthop_ipv4;
            racl_redirect_ecmp_ipv4;
        }
        key = {
            hdr.pkts.pkt_36                 : exact;
            hdr.pkts.pkt_13             : exact;
            hdr.pkts.pkt_14             : exact;
            hdr.pkts.pkt_37              : exact;
            hdr.pkts.pkt_38 : exact;
            hdr.pkts.pkt_39 : exact;
        }
        size = 512;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_40 = 1;
        hdr.pkts.pkt_41 = nexthop_index;
        hdr.pkts.pkt_42 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_40 = 1;
        hdr.pkts.pkt_41 = ecmp_index;
        hdr.pkts.pkt_42 = 1;
    }
    table ipv6_fib_lpm {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_15          : exact;
            hdr.pkts.pkt_43 : exact;
        }
        size = 512;
    }

    apply {
        ingress_port_properties.apply();
        sflow_ing_take_sample.apply();
        sflow_ingress.apply();
        ipv4_src_vtep.apply();
        outer_ipv6_multicast_star_g.apply();
        ipv4_racl.apply();
        ipv6_fib_lpm.apply();
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
