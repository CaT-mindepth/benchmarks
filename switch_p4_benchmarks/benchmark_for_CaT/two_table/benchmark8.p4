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
    
    action non_ip_lkp() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
    }
    action ipv4_lkp() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_4;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_9;
        hdr.pkts.pkt_10 = hdr.pkts.pkt_11;
        hdr.pkts.pkt_12 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17;
    }
    action ipv6_lkp() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_19;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_21;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_10 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_12 = hdr.pkts.pkt_25;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_27;
    }
    table tunnel_lookup_miss_0 {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.pkts.pkt_28 : exact;
            hdr.pkts.pkt_29 : exact;
        }
    }
    action outer_multicast_route_s_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_30 = mc_index;
        hdr.pkts.pkt_31 = 1;
        hdr.pkts.pkt_32 = mcast_rpf_group ^ hdr.pkts.pkt_33;
        hdr.pkts.pkt_34 = 127;
    }
    action outer_multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_30 = mc_index;
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_34 = 127;
    }
    table outer_ipv4_multicast {
        actions = {
            
            
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_36 : exact;
            hdr.pkts.pkt_37     : exact;
            hdr.pkts.pkt_7                           : exact;
            hdr.pkts.pkt_9                           : exact;
        }
        size = 1024;
    }

    apply {
        tunnel_lookup_miss_0.apply();
        outer_ipv4_multicast.apply();
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
