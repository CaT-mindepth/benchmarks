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
    action set_stp_state(bit<32> stp_state) {
        hdr.pkts.pkt_8 = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            hdr.pkts.pkt_9 : exact;
            hdr.pkts.pkt_10   : exact;
        }
        size = 1024;
    }
    action int_sink_gpe(bit<32> mirror_id) {
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12 << 2;
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = mirror_id;
    }
    action int_no_sink() {
        hdr.pkts.pkt_13 = 0;
    }
    table int_terminate {
        actions = {
            int_sink_gpe;
            int_no_sink;
        }
        key = {
            hdr.pkts.pkt_15    : exact;
            hdr.pkts.pkt_16            : exact;
        }
        size = 256;
    }

    action int_sink_update_vxlan_gpe_v4() {
        hdr.pkts.pkt_17 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_19 - hdr.pkts.pkt_20;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_21 - hdr.pkts.pkt_22;
    }
    table int_sink_update_outer {
        actions = {
            int_sink_update_vxlan_gpe_v4;
            
        }
        key = {
            hdr.pkts.pkt_13        : exact;
        }
        size = 2;
    }

    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_23 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_24 = tunnel_vni;
        hdr.pkts.pkt_23 = 1;
    }
    table ipv4_dest_vtep {
        actions = {
            
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_25                    : exact;
            hdr.pkts.pkt_26                        : exact;
            hdr.pkts.pkt_27 : exact;
        }
        size = 1024;
    }
    @name(".fib_hit_nexthop") action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_28 = 1;
        hdr.pkts.pkt_29 = nexthop_index;
        hdr.pkts.pkt_30 = 0;
    }
    @name(".fib_hit_ecmp") action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_28 = 1;
        hdr.pkts.pkt_29 = ecmp_index;
        hdr.pkts.pkt_30 = 1;
    }
    @name(".ipv6_fib") table ipv6_fib {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_25          : exact;
            hdr.pkts.pkt_31 : exact;
        }
        size = 1024;
    }
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_32 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_33 = 1;
        hdr.pkts.pkt_34 = mc_index;
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_36 = mcast_rpf_group ^ hdr.pkts.pkt_37;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_33 = 2;
        hdr.pkts.pkt_34 = mc_index;
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_36 = mcast_rpf_group | hdr.pkts.pkt_38;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_25          : exact;
            hdr.pkts.pkt_31 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_properties.apply();
        spanning_tree.apply();
        int_terminate.apply();
        int_sink_update_outer.apply();
        ipv4_dest_vtep.apply();
        ipv6_fib.apply();
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
