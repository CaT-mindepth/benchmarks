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
    
        action set_ifindex(bit<32> ifindex, bit<32> port_type) {
               hdr.pkts.pkt_0 = ifindex;
               hdr.pkts.pkt_1 = port_type;
        }
        table ingress_port_mapping {
              actions = {
                  set_ifindex;
              }
              key = {
                  hdr.pkts.pkt_2 : exact;
              }
              size = 288;
        }
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_3 : exact;
        }
        size = 1024;
    }
    action non_ip_over_fabric() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_9;
    }
    action ipv4_over_fabric() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_11;
        hdr.pkts.pkt_12 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17;
        hdr.pkts.pkt_18 = hdr.pkts.pkt_19;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_21;
    }
    action ipv6_over_fabric() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_22;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_25;
        hdr.pkts.pkt_26 = hdr.pkts.pkt_27;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_18 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_30;
    }
    table native_packet_over_fabric {
        actions = {
            non_ip_over_fabric;
            ipv4_over_fabric;
            ipv6_over_fabric;
        }
        key = {
            hdr.pkts.pkt_31 : exact;
            hdr.pkts.pkt_32 : exact;
        }
        size = 1024;
    }
    action set_tunnel_termination_flag() {
        hdr.pkts.pkt_33 = 1;
    }
    action set_tunnel_vni_and_termination_flag(bit<32> tunnel_vni) {
        hdr.pkts.pkt_34 = tunnel_vni;
        hdr.pkts.pkt_33 = 1;
    }
    table ipv6_dest_vtep {
        actions = {
            
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        key = {
            hdr.pkts.pkt_35                    : exact;
            hdr.pkts.pkt_27                        : exact;
            hdr.pkts.pkt_36 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_mapping.apply();
        fabric_ingress_src_lkp.apply();
        native_packet_over_fabric.apply();
        ipv6_dest_vtep.apply();
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
