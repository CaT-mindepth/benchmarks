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
bit<32> pkt_37;
bit<32> pkt_38;
bit<32> pkt_39;
bit<32> pkt_40;
bit<32> pkt_41;
bit<32> pkt_42;
bit<32> pkt_43;
bit<32> pkt_44;
bit<32> pkt_45;
bit<32> pkt_46;
bit<32> pkt_47;
bit<32> pkt_48;
bit<32> pkt_49;
bit<32> pkt_50;
bit<32> pkt_51;
bit<32> pkt_52;
bit<32> pkt_53;
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
    
    action int_sink_gpe(bit<32> mirror_id) {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1 << 2;
        hdr.pkts.pkt_2 = 1;
        hdr.pkts.pkt_3 = mirror_id;
    }
    action int_no_sink() {
        hdr.pkts.pkt_2 = 0;
    }
    table int_terminate {
        actions = {
            int_sink_gpe;
            int_no_sink;
        }
        key = {
            hdr.pkts.pkt_4    : exact;
            hdr.pkts.pkt_5            : exact;
        }
        size = 256;
    }

    action non_ip_over_fabric() {
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_9;
        hdr.pkts.pkt_10 = hdr.pkts.pkt_11;
    }
    action ipv4_over_fabric() {
        hdr.pkts.pkt_6 = hdr.pkts.pkt_12;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_16;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_20;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_22;
    }
    action ipv6_over_fabric() {
        hdr.pkts.pkt_6 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_8 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_27 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_30;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_31;
    }
    table native_packet_over_fabric {
        actions = {
            non_ip_over_fabric;
            ipv4_over_fabric;
            ipv6_over_fabric;
        }
        key = {
            hdr.pkts.pkt_32 : exact;
            hdr.pkts.pkt_33 : exact;
        }
        size = 1024;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_34 = ifindex;
    }
    table ipv6_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_35                    : exact;
            hdr.pkts.pkt_26                        : exact;
            hdr.pkts.pkt_36 : exact;
        }
        size = 1024;
    }
    action set_unicast() {
        hdr.pkts.pkt_37 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_37 = 1;
        hdr.pkts.pkt_38 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_37 = 2;
        hdr.pkts.pkt_39 = hdr.pkts.pkt_39 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_37 = 2;
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_39 = hdr.pkts.pkt_39 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_37 = 4;
        hdr.pkts.pkt_39 = hdr.pkts.pkt_39 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_40 = 1;
        hdr.pkts.pkt_41 = drop_reason;
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
            hdr.pkts.pkt_6            : exact;
            hdr.pkts.pkt_8            : exact;
            hdr.pkts.pkt_42           : exact;
            hdr.pkts.pkt_43            : exact;
            hdr.pkts.pkt_44        : exact;
            hdr.pkts.pkt_45  : exact;
            hdr.pkts.pkt_46 : exact;
        }
        size = 512;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_47 = mc_index;
        hdr.pkts.pkt_48 = 1;
    }
    table ipv4_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_49      : exact;
            hdr.pkts.pkt_14 : exact;
            hdr.pkts.pkt_4 : exact;
        }
        size = 1024;
    }
    action set_dst_nat_nexthop_index(bit<32> nexthop_index, bit<32> nexthop_type, bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_50 = nexthop_index;
        hdr.pkts.pkt_51 = nexthop_type;
        hdr.pkts.pkt_52 = nat_rewrite_index;
        hdr.pkts.pkt_53 = 1;
    }
    table nat_dst {
        actions = {
            
            set_dst_nat_nexthop_index;
        }
        key = {
            hdr.pkts.pkt_35          : exact;
            hdr.pkts.pkt_4 : exact;
            hdr.pkts.pkt_17 : exact;
            hdr.pkts.pkt_21 : exact;
        }
        size = 1024;
    }

    apply {
        int_terminate.apply();
        native_packet_over_fabric.apply();
        ipv6_src_vtep.apply();
        validate_packet.apply();
        ipv4_multicast_bridge.apply();
        nat_dst.apply();
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
