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
bit<32> pkt_60;
bit<32> pkt_61;
bit<32> pkt_62;
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
    
    action set_valid_mpls_label1() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
    }
    action set_valid_mpls_label2() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_4;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_5;
    }
    action set_valid_mpls_label3() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_6;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_7;
    }
    table validate_mpls_packet {
        actions = {
            set_valid_mpls_label1;
            set_valid_mpls_label2;
            set_valid_mpls_label3;
        }
        key = {
            hdr.pkts.pkt_1    : exact;
            hdr.pkts.pkt_8      : exact;
            hdr.pkts.pkt_4    : exact;
            hdr.pkts.pkt_9      : exact;
            hdr.pkts.pkt_6    : exact;
            hdr.pkts.pkt_10      : exact;
        }
        size = 512;
    }
    action int_sink_update_vxlan_gpe_v4() {
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_13 - hdr.pkts.pkt_14;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_15 - hdr.pkts.pkt_16;
    }
    table int_sink_update_outer {
        actions = {
            int_sink_update_vxlan_gpe_v4;
            
        }
        key = {
            hdr.pkts.pkt_17        : exact;
        }
        size = 2;
    }

    action terminate_cpu_packet() {
        hdr.pkts.pkt_18 = hdr.pkts.pkt_19;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_21;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_25;
    }
    action switch_fabric_unicast_packet() {
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_27 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_29 = hdr.pkts.pkt_30;
    }
    action terminate_fabric_unicast_packet() {
        hdr.pkts.pkt_18 = hdr.pkts.pkt_31;
        hdr.pkts.pkt_32 = hdr.pkts.pkt_33;
        hdr.pkts.pkt_34 = hdr.pkts.pkt_35;
        hdr.pkts.pkt_36 = hdr.pkts.pkt_37;
        hdr.pkts.pkt_38 = hdr.pkts.pkt_39;
        hdr.pkts.pkt_40 = hdr.pkts.pkt_41;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_42;
    }
    action switch_fabric_multicast_packet() {
        hdr.pkts.pkt_26 = 1;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_43;
    }
    action terminate_fabric_multicast_packet() {
        hdr.pkts.pkt_32 = hdr.pkts.pkt_44;
        hdr.pkts.pkt_34 = hdr.pkts.pkt_45;
        hdr.pkts.pkt_36 = 0;
        hdr.pkts.pkt_38 = hdr.pkts.pkt_46;
        hdr.pkts.pkt_40 = hdr.pkts.pkt_47;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_48;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_49;
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
            hdr.pkts.pkt_28 : exact;
        }
    }
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_50 : exact;
        }
        size = 1024;
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_51 = ifindex;
    }
    table ipv4_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_52                    : exact;
            hdr.pkts.pkt_53                        : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 1024;
    }
    action set_twice_nat_nexthop_index(bit<32> nexthop_index, bit<32> nexthop_type, bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_54 = nexthop_index;
        hdr.pkts.pkt_55 = nexthop_type;
        hdr.pkts.pkt_56 = nat_rewrite_index;
        hdr.pkts.pkt_57 = 1;
    }
    table nat_twice {
        actions = {
            
            set_twice_nat_nexthop_index;
        }
        key = {
            hdr.pkts.pkt_52          : exact;
            hdr.pkts.pkt_58 : exact;
            hdr.pkts.pkt_59 : exact;
            hdr.pkts.pkt_60 : exact;
            hdr.pkts.pkt_61 : exact;
            hdr.pkts.pkt_62 : exact;
        }
        size = 1024;
    }

    apply {
        validate_mpls_packet.apply();
        int_sink_update_outer.apply();
        fabric_ingress_dst_lkp.apply();
        fabric_ingress_src_lkp.apply();
        ipv4_src_vtep.apply();
        nat_twice.apply();
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
