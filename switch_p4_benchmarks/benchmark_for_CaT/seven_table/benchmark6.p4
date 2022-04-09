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
bit<32> pkt_54;
bit<32> pkt_55;
bit<32> pkt_56;
bit<32> pkt_57;
bit<32> pkt_58;
bit<32> pkt_59;
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
    
    action terminate_cpu_packet() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
    }
    action switch_fabric_unicast_packet() {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action terminate_fabric_unicast_packet() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17;
        hdr.pkts.pkt_18 = hdr.pkts.pkt_19;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_21;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_24;
    }
    action switch_fabric_multicast_packet() {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_25;
    }
    action terminate_fabric_multicast_packet() {
        hdr.pkts.pkt_14 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_27;
        hdr.pkts.pkt_18 = 0;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_30;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_31;
    }
    table fabric_ingress_dst_lkp {
        actions = {
            
            terminate_cpu_packet;
            switch_fabric_unicast_packet;
            terminate_fabric_unicast_packet;
            switch_fabric_multicast_packet;
            terminate_fabric_multicast_packet;
        }
        key = {
            hdr.pkts.pkt_10 : exact;
        }
    }
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_32 : exact;
        }
        size = 1024;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_33 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_34                    : exact;
            hdr.pkts.pkt_35                        : exact;
            hdr.pkts.pkt_16 : exact;
        }
        size = 1024;
    }
    action set_storm_control_meter(bit<32> meter_idx) {
        hdr.pkts.pkt_36 = (bit<32>)meter_idx;
    }
    table storm_control {
        actions = {
            
            set_storm_control_meter;
        }
        key = {
            hdr.pkts.pkt_37 : exact;
            hdr.pkts.pkt_38 : exact;
        }
        size = 512;
    }
    action set_unicast() {
        hdr.pkts.pkt_38 = 1;
    }
    action set_unicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_38 = 1;
        hdr.pkts.pkt_39 = 1;
    }
    action set_multicast() {
        hdr.pkts.pkt_38 = 2;
        hdr.pkts.pkt_40 = hdr.pkts.pkt_40 + 1;
    }
    action set_multicast_and_ipv6_src_is_link_local() {
        hdr.pkts.pkt_38 = 2;
        hdr.pkts.pkt_39 = 1;
        hdr.pkts.pkt_40 = hdr.pkts.pkt_40 + 1;
    }
    action set_broadcast() {
        hdr.pkts.pkt_38 = 4;
        hdr.pkts.pkt_40 = hdr.pkts.pkt_40 + 2;
    }
    action set_malformed_packet(bit<32> drop_reason) {
        hdr.pkts.pkt_41 = 1;
        hdr.pkts.pkt_42 = drop_reason;
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
            hdr.pkts.pkt_43            : exact;
            hdr.pkts.pkt_44            : exact;
            hdr.pkts.pkt_45           : exact;
            hdr.pkts.pkt_46            : exact;
            hdr.pkts.pkt_47        : exact;
            hdr.pkts.pkt_48  : exact;
            hdr.pkts.pkt_49 : exact;
        }
        size = 512;
    }
    action set_ecmp_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> nhop_index, bit<32> tunnel) {
        hdr.pkts.pkt_50 = ifindex;
        hdr.pkts.pkt_18 = nhop_index;
        hdr.pkts.pkt_51 = hdr.pkts.pkt_52 ^ bd;
        hdr.pkts.pkt_53 = hdr.pkts.pkt_53 ^ ifindex;
        hdr.pkts.pkt_54 = hdr.pkts.pkt_14 ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index, bit<32> nhop_index) {
        hdr.pkts.pkt_4 = uuc_mc_index;
        hdr.pkts.pkt_18 = nhop_index;
        hdr.pkts.pkt_50 = 0;
        hdr.pkts.pkt_51 = hdr.pkts.pkt_52 ^ bd;
        hdr.pkts.pkt_9 = 127;
    }
    table ecmp_group {
        actions = {
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_18 : exact;
            hdr.pkts.pkt_55      : exact;
        }
        size = 1024;
    }
    action set_icos(bit<32> icos) {
        hdr.pkts.pkt_56 = icos;
    }
    action set_queue(bit<32> qid) {
        hdr.pkts.pkt_57 = qid;
    }
    action set_icos_and_queue(bit<32> icos, bit<32> qid) {
        hdr.pkts.pkt_56 = icos;
        hdr.pkts.pkt_57 = qid;
    }
    table traffic_class {
        actions = {
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        key = {
            hdr.pkts.pkt_58 : exact;
            hdr.pkts.pkt_59      : exact;
        }
        size = 512;
    }

    apply {
        fabric_ingress_dst_lkp.apply();
        fabric_ingress_src_lkp.apply();
        ipv4_src_vtep.apply();
        storm_control.apply();
        validate_packet.apply();
        ecmp_group.apply();
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
