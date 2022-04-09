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
    
    action outer_multicast_route_s_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_0 = mc_index;
        hdr.pkts.pkt_1 = 1;
        hdr.pkts.pkt_2 = mcast_rpf_group ^ hdr.pkts.pkt_3;
        hdr.pkts.pkt_4 = 127;
    }
    action outer_multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_0 = mc_index;
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_4 = 127;
    }
    table outer_ipv6_multicast {
        actions = {
            
            
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_6 : exact;
            hdr.pkts.pkt_7     : exact;
            hdr.pkts.pkt_8                           : exact;
            hdr.pkts.pkt_9                           : exact;
        }
        size = 1024;
    }
    action outer_multicast_route_sm_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_0 = mc_index;
        hdr.pkts.pkt_1 = 1;
        hdr.pkts.pkt_2 = mcast_rpf_group ^ hdr.pkts.pkt_11;
        hdr.pkts.pkt_4 = 127;
    }
    action outer_multicast_route_bidir_star_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_10 = 2;
        hdr.pkts.pkt_0 = mc_index;
        hdr.pkts.pkt_1 = 1;
        hdr.pkts.pkt_2 = mcast_rpf_group | hdr.pkts.pkt_12;
        hdr.pkts.pkt_4 = 127;
    }
    action outer_multicast_bridge_star_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_0 = mc_index;
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_4 = 127;
    }
    table outer_ipv6_multicast_star_g {
        actions = {
            
            outer_multicast_route_sm_star_g_hit;
            outer_multicast_route_bidir_star_g_hit;
            outer_multicast_bridge_star_g_hit;
        }
        key = {
            hdr.pkts.pkt_6 : exact;
            hdr.pkts.pkt_7     : exact;
            hdr.pkts.pkt_9                           : exact;
        }
        size = 512;
    }
    action ipv4_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = urpf_bd_group;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_16;
    }
    action urpf_miss() {
        hdr.pkts.pkt_17 = 1;
    }
    table ipv4_urpf_lpm {
        actions = {
            ipv4_urpf_hit;
            urpf_miss;
        }
        key = {
            hdr.pkts.pkt_18          : exact;
            hdr.pkts.pkt_19 : exact;
        }
        size = 512;
    }
    @name(".fib_hit_nexthop") action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_20 = 1;
        hdr.pkts.pkt_21 = nexthop_index;
        hdr.pkts.pkt_22 = 0;
    }
    @name(".fib_hit_ecmp") action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_20 = 1;
        hdr.pkts.pkt_21 = ecmp_index;
        hdr.pkts.pkt_22 = 1;
    }
    @name(".ipv6_fib") table ipv6_fib {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_18          : exact;
            hdr.pkts.pkt_23 : exact;
        }
        size = 1024;
    }

    apply {
        outer_ipv6_multicast.apply();
        outer_ipv6_multicast_star_g.apply();
        ipv4_urpf_lpm.apply();
        ipv6_fib.apply();
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
