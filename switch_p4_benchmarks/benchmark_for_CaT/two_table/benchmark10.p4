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
    
    action multicast_bridge_star_g_hit_ipv6(bit<32> mc_index) {
        hdr.pkts.pkt_0 = mc_index;
        hdr.pkts.pkt_1 = 1;
    }
    table ipv6_multicast_bridge_star_g {
        actions = {
            multicast_bridge_star_g_hit_ipv6;
        }
        key = {
            hdr.pkts.pkt_2      : exact;
            hdr.pkts.pkt_3 : exact;
        }
        size = 1024;
    }
    action set_icos(bit<32> icos) {
        hdr.pkts.pkt_4 = icos;
    }
    action set_queue(bit<32> qid) {
        hdr.pkts.pkt_5 = qid;
    }
    action set_icos_and_queue(bit<32> icos, bit<32> qid) {
        hdr.pkts.pkt_4 = icos;
        hdr.pkts.pkt_5 = qid;
    }
    table traffic_class {
        actions = {
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        key = {
            hdr.pkts.pkt_6 : exact;
            hdr.pkts.pkt_7      : exact;
        }
        size = 512;
    }

    apply {
        ipv6_multicast_bridge_star_g.apply();
        traffic_class.apply();
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
