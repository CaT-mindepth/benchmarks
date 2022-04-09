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
    
    action int_sink_update_vxlan_gpe_v4() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_2 - hdr.pkts.pkt_3;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_4 - hdr.pkts.pkt_5;
    }
    table int_sink_update_outer {
        actions = {
            int_sink_update_vxlan_gpe_v4;
            
        }
        key = {
            hdr.pkts.pkt_6        : exact;
        }
        size = 2;
    }

    action sflow_ing_pkt_to_cpu(bit<32> sflow_i2e_mirror_id) {
        hdr.pkts.pkt_7 = (bit<32>)sflow_i2e_mirror_id;
    }
    table sflow_ing_take_sample {
        actions = {
            
            sflow_ing_pkt_to_cpu;
        }
        key = {
            hdr.pkts.pkt_8 : exact;
            hdr.pkts.pkt_9   : exact;
        }
        size = 16;
    }
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_10 : exact;
        }
        size = 1024;
    }

    apply {
        int_sink_update_outer.apply();
        sflow_ing_take_sample.apply();
        fabric_ingress_src_lkp.apply();
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
