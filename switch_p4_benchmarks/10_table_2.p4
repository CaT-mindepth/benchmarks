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
bit<32> pkt_84;
bit<32> pkt_85;
bit<32> pkt_86;
bit<32> pkt_87;
bit<32> pkt_88;
bit<32> pkt_89;
bit<32> pkt_90;
bit<32> pkt_91;
bit<32> pkt_92;
bit<32> pkt_93;
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
    
    action set_valid_outer_ipv6_packet() {
        hdr.pkts.pkt_0 = 2;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_2;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_4;
    }
    action set_malformed_outer_ipv6_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_6 = drop_reason;
    }
    table validate_outer_ipv6_packet {
        actions = {
            set_valid_outer_ipv6_packet;
            set_malformed_outer_ipv6_packet;
        }
        key = {
            hdr.pkts.pkt_4         : exact;
            hdr.pkts.pkt_7        : exact;
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
    action non_ip_lkp() {
        hdr.pkts.pkt_13 = hdr.pkts.pkt_14;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_16;
    }
    action ipv4_lkp() {
        hdr.pkts.pkt_13 = hdr.pkts.pkt_17;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_20;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_22;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_27 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_29 = hdr.pkts.pkt_30;
    }
    action ipv6_lkp() {
        hdr.pkts.pkt_13 = hdr.pkts.pkt_31;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_32;
        hdr.pkts.pkt_33 = hdr.pkts.pkt_34;
        hdr.pkts.pkt_35 = hdr.pkts.pkt_36;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_37;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_38;
        hdr.pkts.pkt_27 = hdr.pkts.pkt_39;
        hdr.pkts.pkt_29 = hdr.pkts.pkt_40;
    }
    table tunnel_lookup_miss_0 {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.pkts.pkt_41 : exact;
            hdr.pkts.pkt_42 : exact;
        }
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_43 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_44                    : exact;
            hdr.pkts.pkt_20                        : exact;
            hdr.pkts.pkt_45 : exact;
        }
        size = 1024;
    }
    action terminate_eompls(bit<32> bd, bit<32> tunnel_type) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_45 = tunnel_type;
        hdr.pkts.pkt_47 = bd;
        hdr.pkts.pkt_48 = hdr.pkts.pkt_49;
    }
    action terminate_vpls(bit<32> bd, bit<32> tunnel_type) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_45 = tunnel_type;
        hdr.pkts.pkt_47 = bd;
        hdr.pkts.pkt_48 = hdr.pkts.pkt_50;
    }
    action terminate_ipv4_over_mpls(bit<32> vrf, bit<32> tunnel_type) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_45 = tunnel_type;
        hdr.pkts.pkt_44 = vrf;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_51;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_52;
        hdr.pkts.pkt_0 = 1;
        hdr.pkts.pkt_48 = hdr.pkts.pkt_53;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_54;
    }
    action terminate_ipv6_over_mpls(bit<32> vrf, bit<32> tunnel_type) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_45 = tunnel_type;
        hdr.pkts.pkt_44 = vrf;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_55;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_56;
        hdr.pkts.pkt_0 = 2;
        hdr.pkts.pkt_48 = hdr.pkts.pkt_57;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_58;
    }
    action terminate_pw(bit<32> ifindex) {
        hdr.pkts.pkt_59 = ifindex;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_60;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_61;
    }
    action forward_mpls(bit<32> nexthop_index) {
        hdr.pkts.pkt_62 = nexthop_index;
        hdr.pkts.pkt_63 = 0;
        hdr.pkts.pkt_64 = 1;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_65;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_66;
    }
    table mpls_0 {
        actions = {
            terminate_eompls;
            terminate_vpls;
            terminate_ipv4_over_mpls;
            terminate_ipv6_over_mpls;
            terminate_pw;
            forward_mpls;
        }
        key = {
            hdr.pkts.pkt_67 : exact;
        }
        size = 1024;
    }
    action racl_deny(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_68 = 1;
        hdr.pkts.pkt_69 = acl_stats_index;
        hdr.pkts.pkt_70 = acl_copy_reason;
        hdr.pkts.pkt_71 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    action racl_permit(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_69 = acl_stats_index;
        hdr.pkts.pkt_70 = acl_copy_reason;
        hdr.pkts.pkt_71 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    action racl_redirect_nexthop(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_72 = 1;
        hdr.pkts.pkt_73 = nexthop_index;
        hdr.pkts.pkt_74 = 0;
        hdr.pkts.pkt_69 = acl_stats_index;
        hdr.pkts.pkt_70 = acl_copy_reason;
        hdr.pkts.pkt_71 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    action racl_redirect_ecmp(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_72 = 1;
        hdr.pkts.pkt_73 = ecmp_index;
        hdr.pkts.pkt_74 = 1;
        hdr.pkts.pkt_69 = acl_stats_index;
        hdr.pkts.pkt_70 = acl_copy_reason;
        hdr.pkts.pkt_71 = ingress_cos;
        hdr.pkts.pkt_9 = tc;
        hdr.pkts.pkt_10 = color;
    }
    table ipv6_racl {
        actions = {
            
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        key = {
            hdr.pkts.pkt_75                 : exact;
            hdr.pkts.pkt_33             : exact;
            hdr.pkts.pkt_35             : exact;
            hdr.pkts.pkt_23              : exact;
            hdr.pkts.pkt_76 : exact;
            hdr.pkts.pkt_77 : exact;
        }
        size = 512;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_78 = 1;
        hdr.pkts.pkt_79 = urpf_bd_group;
        hdr.pkts.pkt_80 = hdr.pkts.pkt_81;
    }
    action urpf_miss() {
        hdr.pkts.pkt_82 = 1;
    }
    table ipv6_urpf_lpm {
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        key = {
            hdr.pkts.pkt_44          : exact;
            hdr.pkts.pkt_33 : lpm;
        }
        size = 512;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_64 = 1;
        hdr.pkts.pkt_62 = nexthop_index;
        hdr.pkts.pkt_63 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_64 = 1;
        hdr.pkts.pkt_62 = ecmp_index;
        hdr.pkts.pkt_63 = 1;
    }
    table ipv6_fib_lpm {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_44          : exact;
            hdr.pkts.pkt_35 : lpm;
        }
        size = 512;
    }
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_83 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_84 = 1;
        hdr.pkts.pkt_85 = mc_index;
        hdr.pkts.pkt_86 = 1;
        hdr.pkts.pkt_87 = mcast_rpf_group ^ hdr.pkts.pkt_88;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_84 = 2;
        hdr.pkts.pkt_85 = mc_index;
        hdr.pkts.pkt_86 = 1;
        hdr.pkts.pkt_87 = mcast_rpf_group | hdr.pkts.pkt_89;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_44          : exact;
            hdr.pkts.pkt_35 : exact;
        }
        size = 1024;
    }
    action set_lag_port(bit<32> port) {
        hdr.pkts.pkt_90 = port;
    }
    action set_lag_remote_port(bit<32> device, bit<32> port) {
        hdr.pkts.pkt_91 = device;
        hdr.pkts.pkt_92 = port;
    }
    table lag_group {
        actions = {
            set_lag_port;
            set_lag_remote_port;
        }
        key = {
            hdr.pkts.pkt_59 : exact;
            hdr.pkts.pkt_93            : exact;
        }
        size = 1024;
    }

    apply {
        validate_outer_ipv6_packet.apply();
        ingress_qos_map_pcp.apply();
        tunnel_lookup_miss_0.apply();
        ipv4_src_vtep.apply();
        mpls_0.apply();
        ipv6_racl.apply();
        ipv6_urpf_lpm.apply();
        ipv6_fib_lpm.apply();
        ipv6_multicast_route_star_g.apply();
        lag_group.apply();
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
