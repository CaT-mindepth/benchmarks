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
    action set_ingress_ifindex_properties() {
    }
    table fabric_ingress_src_lkp {
        actions = {
            
            set_ingress_ifindex_properties;
        }
        key = {
            hdr.pkts.pkt_4 : exact;
        }
        size = 1024;
    }
    action smac_miss() {
        hdr.pkts.pkt_5 = 1;
    }
    action smac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7 ^ ifindex;
    }
    table smac {
        actions = {
            
            smac_miss;
            smac_hit;
        }
        key = {
            hdr.pkts.pkt_8   : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }
    action ipv4_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = urpf_bd_group;
        hdr.pkts.pkt_12 = hdr.pkts.pkt_13;
    }
    table ipv4_urpf {
        actions = {
            
            ipv4_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_15 : exact;
        }
        size = 1024;
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
            hdr.pkts.pkt_3 : exact;
            hdr.pkts.pkt_1 : exact;
            hdr.pkts.pkt_2 : exact;
        }
        size = 1024;
    }

    apply {
        ipsg_permit_special.apply();
        fabric_ingress_src_lkp.apply();
        smac.apply();
        ipv4_urpf.apply();
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
