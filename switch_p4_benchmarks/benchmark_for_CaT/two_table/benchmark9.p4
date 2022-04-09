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
    
    action set_ecmp_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> nhop_index, bit<32> tunnel) {
        hdr.pkts.pkt_0 = ifindex;
        hdr.pkts.pkt_1 = nhop_index;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3 ^ bd;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_4 ^ ifindex;
        hdr.pkts.pkt_5 = hdr.pkts.pkt_6 ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index, bit<32> nhop_index) {
        hdr.pkts.pkt_7 = uuc_mc_index;
        hdr.pkts.pkt_1 = nhop_index;
        hdr.pkts.pkt_0 = 0;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3 ^ bd;
        hdr.pkts.pkt_8 = 127;
    }
    table ecmp_group {
        actions = {
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_9      : exact;
        }
        size = 1024;
    }
    action set_fabric_lag_port(bit<32> port) {
        hdr.pkts.pkt_10 = port;
    }
    action set_fabric_multicast(bit<32> fabric_mgid) {
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    table fabric_lag {
        actions = {
            
            set_fabric_lag_port;
            set_fabric_multicast;
        }
        key = {
            hdr.pkts.pkt_8 : exact;
            hdr.pkts.pkt_13       : exact;
        }
    }

    apply {
        ecmp_group.apply();
        fabric_lag.apply();
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
