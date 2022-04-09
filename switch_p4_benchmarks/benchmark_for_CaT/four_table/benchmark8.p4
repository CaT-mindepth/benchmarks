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

    action multicast_route_s_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_11 = mc_index;
        hdr.pkts.pkt_12 = 1;
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = mcast_rpf_group ^ hdr.pkts.pkt_15;
    }
    table ipv4_multicast_route {
        actions = {
            multicast_route_s_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_16          : exact;
            hdr.pkts.pkt_17 : exact;
            hdr.pkts.pkt_18 : exact;
        }
        size = 1024;
    }
    action set_src_nat_rewrite_index(bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_19 = nat_rewrite_index;
    }
    table nat_src {
        actions = {
            
            set_src_nat_rewrite_index;
        }
        key = {
            hdr.pkts.pkt_16          : exact;
            hdr.pkts.pkt_17 : exact;
            hdr.pkts.pkt_20 : exact;
            hdr.pkts.pkt_21 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_qos_map_dscp.apply();
        int_sink_update_outer.apply();
        ipv4_multicast_route.apply();
        nat_src.apply();
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
