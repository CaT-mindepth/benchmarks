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
    
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_0 = 1;
        hdr.pkts.pkt_1 = urpf_bd_group;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
    }
    action urpf_miss() {
        hdr.pkts.pkt_4 = 1;
    }
    table ipv6_urpf_lpm {
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        key = {
            hdr.pkts.pkt_5          : exact;
            hdr.pkts.pkt_6 : exact;
        }
        size = 512;
    }
    action multicast_route_s_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_7 = mc_index;
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = 1;
        hdr.pkts.pkt_10 = mcast_rpf_group ^ hdr.pkts.pkt_11;
    }
    table ipv4_multicast_route {
        actions = {
            multicast_route_s_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_5          : exact;
            hdr.pkts.pkt_12 : exact;
            hdr.pkts.pkt_13 : exact;
        }
        size = 1024;
    }
    action set_ecmp_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> nhop_index, bit<32> tunnel) {
        hdr.pkts.pkt_14 = ifindex;
        hdr.pkts.pkt_15 = nhop_index;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17 ^ bd;
        hdr.pkts.pkt_18 = hdr.pkts.pkt_18 ^ ifindex;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_20 ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index, bit<32> nhop_index) {
        hdr.pkts.pkt_21 = uuc_mc_index;
        hdr.pkts.pkt_15 = nhop_index;
        hdr.pkts.pkt_14 = 0;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17 ^ bd;
        hdr.pkts.pkt_22 = 127;
    }
    table ecmp_group {
        actions = {
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_15 : exact;
            hdr.pkts.pkt_23      : exact;
        }
        size = 1024;
    }

    apply {
        ipv6_urpf_lpm.apply();
        ipv4_multicast_route.apply();
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
