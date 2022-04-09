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
    
    action ipsg_miss() {
        hdr.pkts.pkt_0 = 1;
    }
    table ipsg_permit_special {
        actions = {
            ipsg_miss;
        }
        key = {
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_2 : exact;
            hdr.pkts.pkt_3 : exact;
        }
        size = 512;
    }
    action outer_rmac_hit() {
        hdr.pkts.pkt_4 = 1;
    }
    table outer_rmac {
        actions = {
            
            outer_rmac_hit;
        }
        key = {
            hdr.pkts.pkt_5 : exact;
            hdr.pkts.pkt_6       : exact;
        }
        size = 1024;
    }
    action non_ip_lkp() {
        hdr.pkts.pkt_7 = hdr.pkts.pkt_8;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_10;
    }
    action ipv4_lkp() {
        hdr.pkts.pkt_7 = hdr.pkts.pkt_11;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_12;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_14;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_16;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_20;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_21;
    }
    action ipv6_lkp() {
        hdr.pkts.pkt_7 = hdr.pkts.pkt_22;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_25;
        hdr.pkts.pkt_26 = hdr.pkts.pkt_27;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_30;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_31;
    }
    table tunnel_lookup_miss_0 {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.pkts.pkt_32 : exact;
            hdr.pkts.pkt_33 : exact;
        }
    }
    action set_unicast() {
        hdr.pkts.pkt_34 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_34 = 1;
        hdr.pkts.pkt_35 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_34 = 2;
        hdr.pkts.pkt_36 = hdr.pkts.pkt_36 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_34 = 2;
        hdr.pkts.pkt_35 = 1;
        hdr.pkts.pkt_36 = hdr.pkts.pkt_36 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_34 = 4;
        hdr.pkts.pkt_36 = hdr.pkts.pkt_36 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_37 = 1;
        hdr.pkts.pkt_38 = drop_reason;
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
            hdr.pkts.pkt_7            : exact;
            hdr.pkts.pkt_9            : exact;
            hdr.pkts.pkt_39           : exact;
            hdr.pkts.pkt_17            : exact;
            hdr.pkts.pkt_40        : exact;
            hdr.pkts.pkt_41  : exact;
            hdr.pkts.pkt_42 : exact;
        }
        size = 512;
    }
    action multicast_bridge_star_g_hit_ipv4(bit<32> mc_index) {
        hdr.pkts.pkt_43 = mc_index;
        hdr.pkts.pkt_44 = 1;
    }
    table ipv4_multicast_bridge_star_g {
        actions = {
            
            multicast_bridge_star_g_hit_ipv4;
        }
        key = {
            hdr.pkts.pkt_45      : exact;
            hdr.pkts.pkt_3 : exact;
        }
        size = 1024;
    }

    apply {
        ipsg_permit_special.apply();
        outer_rmac.apply();
        tunnel_lookup_miss_0.apply();
        validate_packet.apply();
        ipv4_multicast_bridge_star_g.apply();
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
