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

    action set_storm_control_meter(bit<32> meter_idx) {
        hdr.pkts.pkt_6 = (bit<32>)meter_idx;
    }
    table storm_control {
        actions = {
            
            set_storm_control_meter;
        }
        key = {
            hdr.pkts.pkt_7 : exact;
            hdr.pkts.pkt_8 : exact;
        }
        size = 512;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_9 = 1;
        hdr.pkts.pkt_10 = urpf_bd_group;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action urpf_miss() {
        hdr.pkts.pkt_13 = 1;
    }
    table ipv6_urpf_lpm {
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_15 : exact;
        }
        size = 512;
    }
    action set_dst_nat_nexthop_index(bit<32> nexthop_index, bit<32> nexthop_type, bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_16 = nexthop_index;
        hdr.pkts.pkt_17 = nexthop_type;
        hdr.pkts.pkt_18 = nat_rewrite_index;
        hdr.pkts.pkt_19 = 1;
    }
    table nat_dst {
        actions = {
            
            set_dst_nat_nexthop_index;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_4 : exact;
            hdr.pkts.pkt_20 : exact;
            hdr.pkts.pkt_21 : exact;
        }
        size = 1024;
    }
    action set_ecmp_nexthop_details(bit<32> ifindex, bit<32> bd, bit<32> nhop_index, bit<32> tunnel) {
        hdr.pkts.pkt_22 = ifindex;
        hdr.pkts.pkt_23 = nhop_index;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_25 ^ bd;
        hdr.pkts.pkt_26 = hdr.pkts.pkt_26 ^ ifindex;
        hdr.pkts.pkt_27 = hdr.pkts.pkt_28 ^ tunnel;
    }
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<32> bd, bit<32> uuc_mc_index, bit<32> nhop_index) {
        hdr.pkts.pkt_29 = uuc_mc_index;
        hdr.pkts.pkt_23 = nhop_index;
        hdr.pkts.pkt_22 = 0;
        hdr.pkts.pkt_24 = hdr.pkts.pkt_25 ^ bd;
        hdr.pkts.pkt_30 = 127;
    }
    table ecmp_group {
        actions = {
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        key = {
            hdr.pkts.pkt_23 : exact;
            hdr.pkts.pkt_31      : exact;
        }
        size = 1024;
    }

    apply {
        int_terminate.apply();
        storm_control.apply();
        ipv6_urpf_lpm.apply();
        nat_dst.apply();
        ecmp_group.apply();
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
