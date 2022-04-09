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
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_0 = ifindex;
    }
    table ipv6_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_3                    : exact;
            hdr.pkts.pkt_4                        : exact;
            hdr.pkts.pkt_5 : exact;
        }
        size = 1024;
    }
    action set_unicast() {
        hdr.pkts.pkt_6 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_6 = 2;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_6 = 2;
        hdr.pkts.pkt_7 = 1;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_6 = 4;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_8 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_9 = 1;
        hdr.pkts.pkt_10 = drop_reason;
    }
    table validate_packet {
        actions = {
            
            set_unicast;
            set_unicast_and_ipv6_src_is_link_local;
            set_multicast;
            set_multicast_and_ipv6_src_is_link_local;
            set_broadcast;
            set_malformed_packet;
        }
        key = {
            hdr.pkts.pkt_11            : exact;
            hdr.pkts.pkt_12            : exact;
            hdr.pkts.pkt_13           : exact;
            hdr.pkts.pkt_14            : exact;
            hdr.pkts.pkt_15        : exact;
            hdr.pkts.pkt_16  : exact;
            hdr.pkts.pkt_17 : exact;
        }
        size = 512;
    }
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_18 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_19 : range;
        }
        size = 512;
    }
    action multicast_route_star_g_miss_1() {
        hdr.pkts.pkt_20 = 1;
    }
    action multicast_route_sm_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_21 = 1;
        hdr.pkts.pkt_22 = mc_index;
        hdr.pkts.pkt_23 = 1;
        hdr.pkts.pkt_24 = mcast_rpf_group ^ hdr.pkts.pkt_25;
    }
    action multicast_route_bidir_star_g_hit_1(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_21 = 2;
        hdr.pkts.pkt_22 = mc_index;
        hdr.pkts.pkt_23 = 1;
        hdr.pkts.pkt_24 = mcast_rpf_group | hdr.pkts.pkt_26;
    }
    table ipv6_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_1;
            multicast_route_sm_star_g_hit_1;
            multicast_route_bidir_star_g_hit_1;
        }
        key = {
            hdr.pkts.pkt_3          : exact;
            hdr.pkts.pkt_27 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_mapping.apply();
        ipv6_src_vtep.apply();
        validate_packet.apply();
        ingress_l4_src_port.apply();
        ipv6_multicast_route_star_g.apply();
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
