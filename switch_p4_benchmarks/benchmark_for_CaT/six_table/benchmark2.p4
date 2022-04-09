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
    action tunnel_lookup_miss() {
    }
    action terminate_tunnel_inner_non_ip(bit<32> bd, bit<32> bd_label, bit<32> stats_idx) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_12 = bd;
        hdr.pkts.pkt_13 = bd_label;
        hdr.pkts.pkt_14 = stats_idx;
        hdr.pkts.pkt_15 = 0;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17;
    }
    action terminate_tunnel_inner_ethernet_ipv4(bit<32> bd, bit<32> vrf, bit<32> rmac_group, bit<32> bd_label, bit<32> ipv4_unicast_enabled, bit<32> ipv4_urpf_mode, bit<32> igmp_snooping_enabled, bit<32> stats_idx, bit<32> ipv4_multicast_enabled, bit<32> mrpf_group) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_12 = bd;
        hdr.pkts.pkt_18 = vrf;
        hdr.pkts.pkt_19 = ipv4_unicast_enabled;
        hdr.pkts.pkt_20 = ipv4_urpf_mode;
        hdr.pkts.pkt_21 = rmac_group;
        hdr.pkts.pkt_13 = bd_label;
        hdr.pkts.pkt_14 = stats_idx;
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_22;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_25 = igmp_snooping_enabled;
        hdr.pkts.pkt_26 = ipv4_multicast_enabled;
        hdr.pkts.pkt_27 = mrpf_group;
    }
    action terminate_tunnel_inner_ipv4(bit<32> vrf, bit<32> rmac_group, bit<32> ipv4_urpf_mode, bit<32> ipv4_unicast_enabled, bit<32> ipv4_multicast_enabled, bit<32> mrpf_group) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_18 = vrf;
        hdr.pkts.pkt_19 = ipv4_unicast_enabled;
        hdr.pkts.pkt_20 = ipv4_urpf_mode;
        hdr.pkts.pkt_21 = rmac_group;
        hdr.pkts.pkt_28 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_30 = hdr.pkts.pkt_31;
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_32;
        hdr.pkts.pkt_27 = mrpf_group;
        hdr.pkts.pkt_26 = ipv4_multicast_enabled;
    }
    action terminate_tunnel_inner_ethernet_ipv6(bit<32> bd, bit<32> vrf, bit<32> rmac_group, bit<32> bd_label, bit<32> ipv6_unicast_enabled, bit<32> ipv6_urpf_mode, bit<32> mld_snooping_enabled, bit<32> stats_idx, bit<32> ipv6_multicast_enabled, bit<32> mrpf_group) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_12 = bd;
        hdr.pkts.pkt_18 = vrf;
        hdr.pkts.pkt_33 = ipv6_unicast_enabled;
        hdr.pkts.pkt_34 = ipv6_urpf_mode;
        hdr.pkts.pkt_21 = rmac_group;
        hdr.pkts.pkt_13 = bd_label;
        hdr.pkts.pkt_14 = stats_idx;
        hdr.pkts.pkt_15 = 2;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_35;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_36;
        hdr.pkts.pkt_27 = mrpf_group;
        hdr.pkts.pkt_37 = ipv6_multicast_enabled;
        hdr.pkts.pkt_38 = mld_snooping_enabled;
    }
    action terminate_tunnel_inner_ipv6(bit<32> vrf, bit<32> rmac_group, bit<32> ipv6_unicast_enabled, bit<32> ipv6_urpf_mode, bit<32> ipv6_multicast_enabled, bit<32> mrpf_group) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_18 = vrf;
        hdr.pkts.pkt_33 = ipv6_unicast_enabled;
        hdr.pkts.pkt_34 = ipv6_urpf_mode;
        hdr.pkts.pkt_21 = rmac_group;
        hdr.pkts.pkt_28 = hdr.pkts.pkt_39;
        hdr.pkts.pkt_30 = hdr.pkts.pkt_40;
        hdr.pkts.pkt_15 = 2;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_41;
        hdr.pkts.pkt_27 = mrpf_group;
        hdr.pkts.pkt_37 = ipv6_multicast_enabled;
    }
    table tunnel {
        actions = {
            
            tunnel_lookup_miss;
            terminate_tunnel_inner_non_ip;
            terminate_tunnel_inner_ethernet_ipv4;
            terminate_tunnel_inner_ipv4;
            terminate_tunnel_inner_ethernet_ipv6;
            terminate_tunnel_inner_ipv6;
        }
        key = {
            hdr.pkts.pkt_42         : exact;
            hdr.pkts.pkt_43 : exact;
        }
        size = 1024;
    }
    action dmac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_44 = ifindex;
        hdr.pkts.pkt_45 = hdr.pkts.pkt_45 ^ ifindex;
    }
    action dmac_multicast_hit(bit<32> mc_index) {
        hdr.pkts.pkt_46 = mc_index;
        hdr.pkts.pkt_47 = 127;
    }
    action dmac_miss() {
        hdr.pkts.pkt_44 = 65535;
        hdr.pkts.pkt_47 = 127;
    }
    action dmac_redirect_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_48 = 1;
        hdr.pkts.pkt_49 = nexthop_index;
        hdr.pkts.pkt_50 = 0;
    }
    action dmac_redirect_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_48 = 1;
        hdr.pkts.pkt_49 = ecmp_index;
        hdr.pkts.pkt_50 = 1;
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
            hdr.pkts.pkt_12   : exact;
            hdr.pkts.pkt_30 : exact;
        }
        size = 1024;
    }
    action multicast_bridge_star_g_hit_ipv4(bit<32> mc_index) {
        hdr.pkts.pkt_51 = mc_index;
        hdr.pkts.pkt_52 = 1;
    }
    table ipv4_multicast_bridge_star_g {
        actions = {
            
            multicast_bridge_star_g_hit_ipv4;
        }
        key = {
            hdr.pkts.pkt_12      : exact;
            hdr.pkts.pkt_53 : exact;
        }
        size = 1024;
    }
    action set_src_nat_rewrite_index(bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_54 = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            
            set_src_nat_rewrite_index;
        }
        key = {
            hdr.pkts.pkt_18          : exact;
            hdr.pkts.pkt_55 : exact;
            hdr.pkts.pkt_56 : exact;
            hdr.pkts.pkt_57 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_properties.apply();
        sflow_ing_take_sample.apply();
        tunnel.apply();
        dmac.apply();
        ipv4_multicast_bridge_star_g.apply();
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
