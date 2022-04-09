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
    action non_ip_lkp() {
        hdr.pkts.pkt_5 = hdr.pkts.pkt_6;
        hdr.pkts.pkt_7 = hdr.pkts.pkt_8;
    }
    action ipv4_lkp() {
        hdr.pkts.pkt_5 = hdr.pkts.pkt_9;
        hdr.pkts.pkt_7 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
        hdr.pkts.pkt_13 = hdr.pkts.pkt_14;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_16;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_18;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_20;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_22;
    }
    action ipv6_lkp() {
        hdr.pkts.pkt_5 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_7 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_27 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_15 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_17 = hdr.pkts.pkt_30;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_31;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_32;
    }
    table tunnel_lookup_miss_0 {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.pkts.pkt_33 : exact;
            hdr.pkts.pkt_34 : exact;
        }
    }
    action outer_multicast_route_s_g_hit(bit<32> mc_index, bit<32> mcast_rpf_group) {
        hdr.pkts.pkt_35 = mc_index;
        hdr.pkts.pkt_36 = 1;
        hdr.pkts.pkt_37 = mcast_rpf_group ^ hdr.pkts.pkt_38;
        hdr.pkts.pkt_39 = 127;
    }
    action outer_multicast_bridge_s_g_hit(bit<32> mc_index) {
        hdr.pkts.pkt_35 = mc_index;
        hdr.pkts.pkt_40 = 1;
        hdr.pkts.pkt_39 = 127;
    }
    table outer_ipv6_multicast {
        actions = {
            
            
            outer_multicast_route_s_g_hit;
            outer_multicast_bridge_s_g_hit;
        }
        key = {
            hdr.pkts.pkt_41 : exact;
            hdr.pkts.pkt_42     : exact;
            hdr.pkts.pkt_26                           : exact;
            hdr.pkts.pkt_28                           : exact;
        }
        size = 1024;
    }
    action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_43 = 1;
        hdr.pkts.pkt_44 = nexthop_index;
        hdr.pkts.pkt_45 = 0;
    }
    action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_43 = 1;
        hdr.pkts.pkt_44 = ecmp_index;
        hdr.pkts.pkt_45 = 1;
    }
    table ipv6_fib_lpm {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_46          : exact;
            hdr.pkts.pkt_27 : exact;
        }
        size = 512;
    }
    action set_icos(bit<32> icos) {
        hdr.pkts.pkt_47 = icos;
    }
    action set_queue(bit<32> qid) {
        hdr.pkts.pkt_48 = qid;
    }
    action set_icos_and_queue(bit<32> icos, bit<32> qid) {
        hdr.pkts.pkt_47 = icos;
        hdr.pkts.pkt_48 = qid;
    }
    table traffic_class {
        actions = {
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        key = {
            hdr.pkts.pkt_49 : exact;
            hdr.pkts.pkt_50      : exact;
        }
        size = 512;
    }

    apply {
        ingress_port_mapping.apply();
        spanning_tree.apply();
        tunnel_lookup_miss_0.apply();
        outer_ipv6_multicast.apply();
        ipv6_fib_lpm.apply();
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
