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
    action int_sink_update_vxlan_gpe_v4() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_6 - hdr.pkts.pkt_7;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 - hdr.pkts.pkt_9;
    }
    table int_sink_update_outer {
        actions = {
            int_sink_update_vxlan_gpe_v4;
            
        }
        key = {
            hdr.pkts.pkt_10        : exact;
        }
        size = 2;
    }

    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_11 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_12 = tunnel_vni;
        hdr.pkts.pkt_11 = 1;
    }
    table ipv4_dest_vtep {
        actions = {
            
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_13                    : exact;
            hdr.pkts.pkt_14                        : exact;
            hdr.pkts.pkt_15 : exact;
        }
        size = 1024;
    }
    action set_icos(bit<32> icos) {
        hdr.pkts.pkt_16 = icos;
    }
    action set_queue(bit<32> qid) {
        hdr.pkts.pkt_17 = qid;
    }
    action set_icos_and_queue(bit<32> icos, bit<32> qid) {
        hdr.pkts.pkt_16 = icos;
        hdr.pkts.pkt_17 = qid;
    }
    table traffic_class {
        actions = {
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        key = {
            hdr.pkts.pkt_18 : exact;
            hdr.pkts.pkt_0      : exact;
        }
        size = 512;
    }

    apply {
        ingress_qos_map_dscp.apply();
        int_sink_update_outer.apply();
        ipv4_dest_vtep.apply();
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
