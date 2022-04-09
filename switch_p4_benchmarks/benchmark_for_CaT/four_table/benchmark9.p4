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
    
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_0 : exact;
        }
        size = 1024;
    }
    action outer_multicast_route_s_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_1 = mc_index;
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = mcast_rpf_group ^ hdr.pkts.pkt_4;
        hdr.pkts.pkt_5 = 127;
    }
    action outer_multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_1 = mc_index;
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_5 = 127;
    }
    table outer_ipv6_multicast {
        actions = {
            
            
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_7 : exact;
            hdr.pkts.pkt_8     : exact;
            hdr.pkts.pkt_9                           : exact;
            hdr.pkts.pkt_10                           : exact;
        }
        size = 1024;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_12 = nexthop_index;
        hdr.pkts.pkt_13 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_11 = 1;
        hdr.pkts.pkt_12 = ecmp_index;
        hdr.pkts.pkt_13 = 1;
    }
    table ipv4_fib_lpm {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_15 : exact;
        }
        size = 512;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_16 = mc_index;
        hdr.pkts.pkt_17 = 1;
    }
    table ipv6_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_18      : exact;
            hdr.pkts.pkt_19 : exact;
            hdr.pkts.pkt_20 : exact;
        }
        size = 1024;
    }

    apply {
        fabric_ingress_src_lkp.apply();
        outer_ipv6_multicast.apply();
        ipv4_fib_lpm.apply();
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
