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

    action set_unicast() {
        hdr.pkts.pkt_7 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_7 = 1;
        hdr.pkts.pkt_8 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_7 = 2;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_9 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_7 = 2;
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_9 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_7 = 4;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_9 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = drop_reason;
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
            hdr.pkts.pkt_12            : exact;
            hdr.pkts.pkt_13            : exact;
            hdr.pkts.pkt_14           : exact;
            hdr.pkts.pkt_15            : exact;
            hdr.pkts.pkt_16        : exact;
            hdr.pkts.pkt_17  : exact;
            hdr.pkts.pkt_18 : exact;
        }
        size = 512;
    }
    action smac_miss() {
        hdr.pkts.pkt_19 = 1;
    }
    action smac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_20 = hdr.pkts.pkt_21 ^ ifindex;
    }
    table smac {
        actions = {
            
            smac_miss;
            smac_hit;
        }
        key = {
            hdr.pkts.pkt_22   : exact;
            hdr.pkts.pkt_12 : exact;
        }
        size = 1024;
    }
    action multicast_route_star_g_miss_0() {
        hdr.pkts.pkt_23 = 1;
    }
    action multicast_route_sm_star_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_24 = 1;
        hdr.pkts.pkt_25 = mc_index;
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = mcast_rpf_group ^ hdr.pkts.pkt_28;
    }
    action multicast_route_bidir_star_g_hit_0(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_24 = 2;
        hdr.pkts.pkt_25 = mc_index;
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = mcast_rpf_group | hdr.pkts.pkt_29;
    }
    table ipv4_multicast_route_star_g {
        actions = {
            multicast_route_star_g_miss_0;
            multicast_route_sm_star_g_hit_0;
            multicast_route_bidir_star_g_hit_0;
        }
        key = {
            hdr.pkts.pkt_30          : exact;
            hdr.pkts.pkt_31 : exact;
        }
        size = 1024;
    }

    apply {
        int_sink_update_outer.apply();
        validate_packet.apply();
        smac.apply();
        ipv4_multicast_route_star_g.apply();
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
