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
    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_13 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_14 = tunnel_vni;
        hdr.pkts.pkt_13 = 1;
    }
    table ipv4_dest_vtep {
        actions = {
            
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_15                    : exact;
            hdr.pkts.pkt_16                        : exact;
            hdr.pkts.pkt_17 : exact;
        }
        size = 1024;
    }
    action racl_deny_ipv4(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_18 = 1;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_copy_reason;
        hdr.pkts.pkt_21 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    action racl_permit_ipv4(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_copy_reason;
        hdr.pkts.pkt_21 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    action racl_redirect_nexthop_ipv4(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_22 = 1;
        hdr.pkts.pkt_23 = nexthop_index;
        hdr.pkts.pkt_24 = 0;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_copy_reason;
        hdr.pkts.pkt_21 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    action racl_redirect_ecmp_ipv4(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_22 = 1;
        hdr.pkts.pkt_23 = ecmp_index;
        hdr.pkts.pkt_24 = 1;
        hdr.pkts.pkt_19 = acl_stats_index;
        hdr.pkts.pkt_20 = acl_copy_reason;
        hdr.pkts.pkt_21 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    table ipv4_racl {
        actions = {
            
            racl_deny_ipv4;
            racl_permit_ipv4;
            racl_redirect_nexthop_ipv4;
            racl_redirect_ecmp_ipv4;
        }
        key = {
            hdr.pkts.pkt_25                 : exact;
            hdr.pkts.pkt_26             : exact;
            hdr.pkts.pkt_27             : exact;
            hdr.pkts.pkt_28              : exact;
            hdr.pkts.pkt_29 : exact;
            hdr.pkts.pkt_30 : exact;
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
            hdr.pkts.pkt_15          : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 512;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_35 = mc_index;
        hdr.pkts.pkt_36 = 1;
    }
    table ipv6_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_37      : exact;
            hdr.pkts.pkt_38 : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 1024;
    }

    apply {
        validate_outer_ipv4_packet.apply();
        ingress_qos_map_pcp.apply();
        ipv4_dest_vtep.apply();
        ipv4_racl.apply();
        ipv6_fib_lpm.apply();
        ipv6_multicast_bridge.apply();
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
