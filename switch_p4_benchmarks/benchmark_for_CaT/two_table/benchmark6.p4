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
    
    action set_ingress_tc(bit<32> tc) {
        hdr.pkts.pkt_0 = tc;
    }
    action set_ingress_color(bit<32> color) {
        hdr.pkts.pkt_1 = color;
    }
    action set_ingress_tc_and_color(bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_0 = tc;
        hdr.pkts.pkt_1 = color;
    }
    table ingress_qos_map_dscp {
        actions = {
            
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }
        key = {
            hdr.pkts.pkt_2 : exact;
            hdr.pkts.pkt_3          : exact;
        }
        size = 64;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_4 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_5                    : exact;
            hdr.pkts.pkt_6                        : exact;
            hdr.pkts.pkt_7 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_qos_map_dscp.apply();
        ipv4_src_vtep.apply();
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
