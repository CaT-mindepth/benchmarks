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
    
    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_0 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_1 = tunnel_vni;
        hdr.pkts.pkt_0 = 1;
    }
    table ipv4_dest_vtep {
        actions = {
            
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_2                    : exact;
            hdr.pkts.pkt_3                        : exact;
            hdr.pkts.pkt_4 : exact;
        }
        size = 1024;
    }
    action ipv4_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_5 = 1;
        hdr.pkts.pkt_6 = urpf_bd_group;
        hdr.pkts.pkt_7 = hdr.pkts.pkt_8;
    }
    table ipv4_urpf {
        actions = {
            
            ipv4_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_2          : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }

    apply {
        ipv4_dest_vtep.apply();
        ipv4_urpf.apply();
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
