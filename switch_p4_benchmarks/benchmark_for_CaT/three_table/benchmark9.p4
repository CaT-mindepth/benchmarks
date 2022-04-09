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
    
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_0 = 1;
        hdr.pkts.pkt_1 = urpf_bd_group;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
    }
    table ipv6_urpf {
        actions = {
            
            ipv6_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_4          : exact;
            hdr.pkts.pkt_5 : exact;
        }
        size = 1024;
    }
    @name(".fib_hit_nexthop") action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = nexthop_index;
        hdr.pkts.pkt_8 = 0;
    }
    @name(".fib_hit_ecmp") action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_6 = 1;
        hdr.pkts.pkt_7 = ecmp_index;
        hdr.pkts.pkt_8 = 1;
    }
    @name(".ipv6_fib") table ipv6_fib {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_4          : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }
    action set_twice_nat_nexthop_index(bit<32> nexthop_index, bit<32> nexthop_type, bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_10 = nexthop_index;
        hdr.pkts.pkt_11 = nexthop_type;
        hdr.pkts.pkt_12 = nat_rewrite_index;
        hdr.pkts.pkt_13 = 1;
    }
    table nat_twice {
        actions = {
            
            set_twice_nat_nexthop_index;
        }
        key = {
            hdr.pkts.pkt_4          : exact;
            hdr.pkts.pkt_14 : exact;
            hdr.pkts.pkt_15 : exact;
            hdr.pkts.pkt_16 : exact;
            hdr.pkts.pkt_17 : exact;
            hdr.pkts.pkt_18 : exact;
        }
        size = 1024;
    }

    apply {
        ipv6_urpf.apply();
        ipv6_fib.apply();
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
