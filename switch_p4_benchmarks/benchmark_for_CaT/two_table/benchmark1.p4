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
    action set_valid_outer_ipv4_packet() {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action set_malformed_outer_ipv4_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = drop_reason;
    }
    table validate_outer_ipv4_packet {
        actions = {
            set_valid_outer_ipv4_packet;
            set_malformed_outer_ipv4_packet;
        }
        key = {
            hdr.pkts.pkt_12       : exact;
            hdr.pkts.pkt_15           : exact;
            hdr.pkts.pkt_16 : exact;
        }
        size = 512;
    }

    apply {
        ingress_port_properties.apply();
        validate_outer_ipv4_packet.apply();
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
