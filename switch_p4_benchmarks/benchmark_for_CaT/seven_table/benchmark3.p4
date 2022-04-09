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
    
        action set_ifindex(bit<32> ifindex, bit<32> port_type) {
               hdr.pkts.pkt_0 = ifindex;
               hdr.pkts.pkt_1 = port_type;
        }
        table ingress_port_mapping {
              actions = {
                  set_ifindex;
              }
              key = {
                  hdr.pkts.pkt_2 : exact;
              }
              size = 288;
        }
    action set_stp_state(bit<32> stp_state) {
        hdr.pkts.pkt_3 = stp_state;
    }
    table spanning_tree {
        actions = {
            set_stp_state;
        }
        key = {
            hdr.pkts.pkt_0 : exact;
            hdr.pkts.pkt_4   : exact;
        }
        size = 1024;
    }
    action sflow_ing_pkt_to_cpu(bit<32> sflow_i2e_mirror_id) {
        hdr.pkts.pkt_5 = (bit<32>)sflow_i2e_mirror_id;
    }
    table sflow_ing_take_sample {
        actions = {
            
            sflow_ing_pkt_to_cpu;
        }
        key = {
            hdr.pkts.pkt_6 : exact;
            hdr.pkts.pkt_7   : exact;
        }
        size = 16;
    }
    action set_ingress_dst_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_8 = range_id;
    }
    table ingress_l4_dst_port {
        actions = {
            
            set_ingress_dst_port_range_id;
        }
        key = {
            hdr.pkts.pkt_9 : range;
        }
        size = 512;
    }
    action ipv6_urpf_hit(bit<32> urpf_bd_group) {
        hdr.pkts.pkt_10 = 1;
        hdr.pkts.pkt_11 = urpf_bd_group;
        hdr.pkts.pkt_12 = hdr.pkts.pkt_13;
    }
    table ipv6_urpf {
        actions = {
            
            ipv6_urpf_hit;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_15 : exact;
        }
        size = 1024;
    }
    action multicast_bridge_star_g_hit_ipv4(bit<32> mc_index) {
        hdr.pkts.pkt_16 = mc_index;
        hdr.pkts.pkt_17 = 1;
    }
    table ipv4_multicast_bridge_star_g {
        actions = {
            
            multicast_bridge_star_g_hit_ipv4;
        }
        key = {
            hdr.pkts.pkt_18      : exact;
            hdr.pkts.pkt_19 : exact;
        }
        size = 1024;
    }
    action set_dst_nat_nexthop_index(bit<32> nexthop_index, bit<32> nexthop_type, bit<32> nat_rewrite_index) {
        hdr.pkts.pkt_20 = nexthop_index;
        hdr.pkts.pkt_21 = nexthop_type;
        hdr.pkts.pkt_22 = nat_rewrite_index;
        hdr.pkts.pkt_23 = 1;
    }
    table nat_dst {
        actions = {
            
            set_dst_nat_nexthop_index;
        }
        key = {
            hdr.pkts.pkt_14          : exact;
            hdr.pkts.pkt_19 : exact;
            hdr.pkts.pkt_24 : exact;
            hdr.pkts.pkt_9 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_mapping.apply();
        spanning_tree.apply();
        sflow_ing_take_sample.apply();
        ingress_l4_dst_port.apply();
        ipv6_urpf.apply();
        ipv4_multicast_bridge_star_g.apply();
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
