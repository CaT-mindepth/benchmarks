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
    
    action sflow_ing_pkt_to_cpu(bit<32> sflow_i2e_mirror_id) {
        hdr.pkts.pkt_0 = (bit<32>)sflow_i2e_mirror_id;
    }
    table sflow_ing_take_sample {
        actions = {
            
            sflow_ing_pkt_to_cpu;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_2   : exact;
        }
        size = 16;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_3 = 1;
        hdr.pkts.pkt_4 = urpf_bd_group;
        hdr.pkts.pkt_5 = hdr.pkts.pkt_6;
    }
    table ipv6_urpf {
        actions = {
            
            ipv6_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_7          : exact;
            hdr.pkts.pkt_8 : exact;
        }
        size = 1024;
    }

    apply {
        sflow_ing_take_sample.apply();
        ipv6_urpf.apply();
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
