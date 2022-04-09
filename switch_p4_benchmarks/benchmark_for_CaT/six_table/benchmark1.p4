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
    
    action set_stp_state(bit<32> stp_state) {
        hdr.pkts.pkt_0 = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_2   : exact;
        }
        size = 1024;
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
    table ingress_qos_map_dscp {
        actions = {
            
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            hdr.pkts.pkt_5 : exact;
            hdr.pkts.pkt_6          : exact;
        }
        size = 64;
    }
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_7 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_8 : range;
        }
        size = 512;
    }
    action acl_deny_mac(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_9 = 1;
        hdr.pkts.pkt_10 = acl_stats_index;
        hdr.pkts.pkt_11 = acl_meter_index;
        hdr.pkts.pkt_12 = acl_copy_reason;
        hdr.pkts.pkt_13 = nat_mode;
        hdr.pkts.pkt_14 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_permit_mac(bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_10 = acl_stats_index;
        hdr.pkts.pkt_11 = acl_meter_index;
        hdr.pkts.pkt_12 = acl_copy_reason;
        hdr.pkts.pkt_13 = nat_mode;
        hdr.pkts.pkt_14 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_redirect_nexthop_mac(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_16 = nexthop_index;
        hdr.pkts.pkt_17 = 0;
        hdr.pkts.pkt_10 = acl_stats_index;
        hdr.pkts.pkt_11 = acl_meter_index;
        hdr.pkts.pkt_12 = acl_copy_reason;
        hdr.pkts.pkt_13 = nat_mode;
        hdr.pkts.pkt_14 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_redirect_ecmp_mac(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> acl_copy_reason, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_16 = ecmp_index;
        hdr.pkts.pkt_17 = 1;
        hdr.pkts.pkt_10 = acl_stats_index;
        hdr.pkts.pkt_11 = acl_meter_index;
        hdr.pkts.pkt_12 = acl_copy_reason;
        hdr.pkts.pkt_13 = nat_mode;
        hdr.pkts.pkt_14 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
    }
    action acl_mirror_mac(bit<32> session_id, bit<32> acl_stats_index, bit<32> acl_meter_index, bit<32> nat_mode, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_18 = (bit<32>)session_id;
        hdr.pkts.pkt_10 = acl_stats_index;
        hdr.pkts.pkt_11 = acl_meter_index;
        hdr.pkts.pkt_13 = nat_mode;
        hdr.pkts.pkt_14 = ingress_cos;
        hdr.pkts.pkt_3 = tc;
        hdr.pkts.pkt_4 = color;
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
            hdr.pkts.pkt_19   : exact;
            hdr.pkts.pkt_20   : exact;
            hdr.pkts.pkt_21  : exact;
            hdr.pkts.pkt_22  : exact;
            hdr.pkts.pkt_23 : exact;
        }
        size = 512;
    }
    action ipv4_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_24 = 1;
        hdr.pkts.pkt_25 = urpf_bd_group;
        hdr.pkts.pkt_26 = hdr.pkts.pkt_27;
    }
    table ipv4_urpf {
        actions = {
            
            ipv4_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_28          : exact;
            hdr.pkts.pkt_29 : exact;
        }
        size = 1024;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_30 = mc_index;
        hdr.pkts.pkt_31 = 1;
    }
    table ipv6_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_32      : exact;
            hdr.pkts.pkt_33 : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 1024;
    }

    apply {
        spanning_tree.apply();
        ingress_qos_map_dscp.apply();
        ingress_l4_src_port.apply();
        mac_acl.apply();
        ipv4_urpf.apply();
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
