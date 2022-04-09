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
    action set_bd_properties(bit<32> bd, bit<32> vrf, bit<32> stp_group, bit<32> learning_enabled, bit<32> bd_label, bit<32> stats_idx, bit<32> rmac_group, bit<32> ipv4_unicast_enabled, bit<32> ipv6_unicast_enabled, bit<32> ipv4_urpf_mode, bit<32> ipv6_urpf_mode, bit<32> igmp_snooping_enabled, bit<32> mld_snooping_enabled, bit<32> ipv4_multicast_enabled, bit<32> ipv6_multicast_enabled, bit<32> mrpf_group, bit<32> ipv4_mcast_key, bit<32> ipv4_mcast_key_type, bit<32> ipv6_mcast_key, bit<32> ipv6_mcast_key_type) {
        hdr.pkts.pkt_3 = bd;
        hdr.pkts.pkt_4 = bd;
        hdr.pkts.pkt_5 = bd_label;
        hdr.pkts.pkt_6 = stp_group;
        hdr.pkts.pkt_7 = stats_idx;
        hdr.pkts.pkt_8 = learning_enabled;
        hdr.pkts.pkt_9 = vrf;
        hdr.pkts.pkt_10 = ipv4_unicast_enabled;
        hdr.pkts.pkt_11 = ipv6_unicast_enabled;
        hdr.pkts.pkt_12 = ipv4_urpf_mode;
        hdr.pkts.pkt_13 = ipv6_urpf_mode;
        hdr.pkts.pkt_14 = rmac_group;
        hdr.pkts.pkt_15 = igmp_snooping_enabled;
        hdr.pkts.pkt_16 = mld_snooping_enabled;
        hdr.pkts.pkt_17 = ipv4_multicast_enabled;
        hdr.pkts.pkt_18 = ipv6_multicast_enabled;
        hdr.pkts.pkt_19 = mrpf_group;
        hdr.pkts.pkt_20 = ipv4_mcast_key_type;
        hdr.pkts.pkt_21 = ipv4_mcast_key;
        hdr.pkts.pkt_22 = ipv6_mcast_key_type;
        hdr.pkts.pkt_23 = ipv6_mcast_key;
    }
    action port_vlan_mapping_miss() {
        hdr.pkts.pkt_24 = 1;
    }
    table port_vlan_mapping {
        actions = {
            set_bd_properties;
            port_vlan_mapping_miss;
        }
        key = {
            hdr.pkts.pkt_0 : exact;
            hdr.pkts.pkt_25         : exact;
            hdr.pkts.pkt_26         : exact;
        }
        size = 4096;
    }
    action set_ingress_dst_port_range_id(bit<32> range_id) {
        hdr.pkts.pkt_27 = range_id;
    }
    table ingress_l4_dst_port {
        actions = {
            
            set_ingress_dst_port_range_id;
        }
        key = {
            hdr.pkts.pkt_28 : range;
        }
        size = 512;
    }
    @name(".fib_hit_nexthop") action fib_hit_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_29 = 1;
        hdr.pkts.pkt_30 = nexthop_index;
        hdr.pkts.pkt_31 = 0;
    }
    @name(".fib_hit_ecmp") action fib_hit_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_29 = 1;
        hdr.pkts.pkt_30 = ecmp_index;
        hdr.pkts.pkt_31 = 1;
    }
    @name(".ipv6_fib") table ipv6_fib {
        actions = {
            
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        key = {
            hdr.pkts.pkt_9          : exact;
            hdr.pkts.pkt_32 : exact;
        }
        size = 1024;
    }

    apply {
        ingress_port_mapping.apply();
        port_vlan_mapping.apply();
        ingress_l4_dst_port.apply();
        ipv6_fib.apply();
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
