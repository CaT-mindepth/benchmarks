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
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_5 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_6 : range;
        }
        size = 512;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_7 = mc_index;
        hdr.pkts.pkt_8 = 1;
    }
    table ipv4_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_9      : exact;
            hdr.pkts.pkt_10 : exact;
            hdr.pkts.pkt_11 : exact;
        }
        size = 1024;
    }
    action multicast_route_s_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_12 = mc_index;
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = 1;
        hdr.pkts.pkt_15 = mcast_rpf_group ^ hdr.pkts.pkt_16;
    }
    table ipv4_multicast_route {
        actions = {
            multicast_route_s_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_2          : exact;
            hdr.pkts.pkt_10 : exact;
            hdr.pkts.pkt_11 : exact;
        }
        size = 1024;
    }

    apply {
        ipv4_dest_vtep.apply();
        ingress_l4_src_port.apply();
        ipv4_multicast_bridge.apply();
        ipv4_multicast_route.apply();
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
