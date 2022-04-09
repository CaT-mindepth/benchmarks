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
    action set_stp_state(bit<32> stp_state) {
        hdr.pkts.pkt_11 = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            hdr.pkts.pkt_12 : exact;
            hdr.pkts.pkt_13   : exact;
        }
        size = 1024;
    }
    action ipsg_miss() {
        hdr.pkts.pkt_14 = 1;
    }
    table ipsg_permit_special {
        actions = {
            ipsg_miss;
        }
        key = {
            hdr.pkts.pkt_15 : exact;
            hdr.pkts.pkt_16 : exact;
            hdr.pkts.pkt_17 : exact;
        }
        size = 512;
    }
    action int_set_src() {
        hdr.pkts.pkt_18 = 1;
    }
    action int_set_no_src() {
        hdr.pkts.pkt_18 = 0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.pkts.pkt_17 : exact;
            hdr.pkts.pkt_19 : exact;
            hdr.pkts.pkt_20        : exact;
            hdr.pkts.pkt_21        : exact;
        }
        size = 256;
    }

    action set_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> tunnel) {
        hdr.pkts.pkt_22 = ifindex;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_24 ^ bd;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_25 ^ ifindex;
        hdr.pkts.pkt_26 = hdr.pkts.pkt_27 ^ tunnel;
    }
    action set_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index) {
        hdr.pkts.pkt_28 = uuc_mc_index;
        hdr.pkts.pkt_22 = 0;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_24 ^ bd;
        hdr.pkts.pkt_29 = 127;
    }
    table nexthop {
        actions = {
            
            set_nexthop_details;
            set_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_30 : exact;
        }
        size = 1024;
    }

    apply {
        validate_mpls_packet.apply();
        spanning_tree.apply();
        ipsg_permit_special.apply();
        int_source.apply();
        nexthop.apply();
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
