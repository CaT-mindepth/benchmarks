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
    
    action set_ingress_src_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_0 = range_id;
    }
    table ingress_l4_src_port {
        actions = {
            
            set_ingress_src_port_range_id;
        }
        key = {
            hdr.pkts.pkt_1 : range;
        }
        size = 512;
    }
    action smac_miss() {
        hdr.pkts.pkt_2 = 1;
    }
    action smac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_3 = hdr.pkts.pkt_4 ^ ifindex;
    }
    table smac {
        actions = {
            
            smac_miss;
            smac_hit;
        }
        key = {
            hdr.pkts.pkt_5   : exact;
            hdr.pkts.pkt_6 : exact;
        }
        size = 1024;
    }
    action racl_deny(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_7 = 1;
        hdr.pkts.pkt_8 = acl_stats_index;
        hdr.pkts.pkt_9 = acl_copy_reason;
        hdr.pkts.pkt_10 = ingress_cos;
        hdr.pkts.pkt_11 = tc;
        hdr.pkts.pkt_12 = color;
    }
    action racl_permit(bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_8 = acl_stats_index;
        hdr.pkts.pkt_9 = acl_copy_reason;
        hdr.pkts.pkt_10 = ingress_cos;
        hdr.pkts.pkt_11 = tc;
        hdr.pkts.pkt_12 = color;
    }
    action racl_redirect_nexthop(bit<32> nexthop_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = nexthop_index;
        hdr.pkts.pkt_15 = 0;
        hdr.pkts.pkt_8 = acl_stats_index;
        hdr.pkts.pkt_9 = acl_copy_reason;
        hdr.pkts.pkt_10 = ingress_cos;
        hdr.pkts.pkt_11 = tc;
        hdr.pkts.pkt_12 = color;
    }
    action racl_redirect_ecmp(bit<32> ecmp_index, bit<32> acl_stats_index, bit<32> acl_copy_reason, bit<32> ingress_cos, bit<32> tc, bit<32> color) {
        hdr.pkts.pkt_13 = 1;
        hdr.pkts.pkt_14 = ecmp_index;
        hdr.pkts.pkt_15 = 1;
        hdr.pkts.pkt_8 = acl_stats_index;
        hdr.pkts.pkt_9 = acl_copy_reason;
        hdr.pkts.pkt_10 = ingress_cos;
        hdr.pkts.pkt_11 = tc;
        hdr.pkts.pkt_12 = color;
    }
    table ipv6_racl {
        actions = {
            
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        key = {
            hdr.pkts.pkt_16                 : exact;
            hdr.pkts.pkt_17             : exact;
            hdr.pkts.pkt_18             : exact;
            hdr.pkts.pkt_19              : exact;
            hdr.pkts.pkt_0 : exact;
            hdr.pkts.pkt_20 : exact;
        }
        size = 512;
    }

    apply {
        ingress_l4_src_port.apply();
        smac.apply();
        ipv6_racl.apply();
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
