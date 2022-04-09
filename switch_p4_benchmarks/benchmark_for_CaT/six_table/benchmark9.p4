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
    
    action set_stp_state(bit<32> stp_state) {
        hdr.pkts.pkt_0 = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_2   : exact;
        }
        size = 1024;
    }
    action outer_rmac_hit() {
        hdr.pkts.pkt_3 = 1;
    }
    table outer_rmac {
        actions = {
            
            outer_rmac_hit;
        }
        key = {
            hdr.pkts.pkt_4 : exact;
            hdr.pkts.pkt_5       : exact;
        }
        size = 1024;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_1 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_6                    : exact;
            hdr.pkts.pkt_7                        : exact;
            hdr.pkts.pkt_8 : exact;
        }
        size = 1024;
    }
    action set_unicast() {
        hdr.pkts.pkt_9 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_9 = 1;
        hdr.pkts.pkt_10 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_9 = 2;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_11 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_9 = 2;
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_11 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_9 = 4;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_11 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_12 = 1;
        hdr.pkts.pkt_13 = drop_reason;
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
            hdr.pkts.pkt_14            : exact;
            hdr.pkts.pkt_15            : exact;
            hdr.pkts.pkt_16           : exact;
            hdr.pkts.pkt_17            : exact;
            hdr.pkts.pkt_18        : exact;
            hdr.pkts.pkt_19  : exact;
            hdr.pkts.pkt_20 : exact;
        }
        size = 512;
    }
    action multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_21 = mc_index;
        hdr.pkts.pkt_22 = 1;
    }
    table ipv4_multicast_bridge {
        actions = {
            
            multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_23      : exact;
            hdr.pkts.pkt_24 : exact;
            hdr.pkts.pkt_25 : exact;
        }
        size = 1024;
    }
    action set_fabric_lag_port(bit<32> port) {
        hdr.pkts.pkt_26 = port;
    }
    action set_fabric_multicast(bit<32> fabric_mgid) {
        hdr.pkts.pkt_27 = hdr.pkts.pkt_28;
    }
    table fabric_lag {
        actions = {
            
            set_fabric_lag_port;
            set_fabric_multicast;
        }
        key = {
            hdr.pkts.pkt_29 : exact;
            hdr.pkts.pkt_30       : exact;
        }
    }

    apply {
        spanning_tree.apply();
        outer_rmac.apply();
        ipv4_src_vtep.apply();
        validate_packet.apply();
        ipv4_multicast_bridge.apply();
        fabric_lag.apply();
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
