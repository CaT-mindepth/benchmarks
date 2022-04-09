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
    
    action set_bd_properties(bit<32> bd, bit<32> vrf, bit<32> stp_group, bit<32> learning_enabled, bit<32> bd_label, bit<32> stats_idx, bit<32> rmac_group, bit<32> ipv4_unicast_enabled, bit<32> ipv6_unicast_enabled, bit<32> ipv4_urpf_mode, bit<32> ipv6_urpf_mode, bit<32> igmp_snooping_enabled, bit<32> mld_snooping_enabled, bit<32> ipv4_multicast_enabled, bit<32> ipv6_multicast_enabled, bit<32> mrpf_group, bit<32> ipv4_mcast_key, bit<32> ipv4_mcast_key_type, bit<32> ipv6_mcast_key, bit<32> ipv6_mcast_key_type) {
        hdr.pkts.pkt_0 = bd;
        hdr.pkts.pkt_1 = bd;
        hdr.pkts.pkt_2 = bd_label;
        hdr.pkts.pkt_3 = stp_group;
        hdr.pkts.pkt_4 = stats_idx;
        hdr.pkts.pkt_5 = learning_enabled;
        hdr.pkts.pkt_6 = vrf;
        hdr.pkts.pkt_7 = ipv4_unicast_enabled;
        hdr.pkts.pkt_8 = ipv6_unicast_enabled;
        hdr.pkts.pkt_9 = ipv4_urpf_mode;
        hdr.pkts.pkt_10 = ipv6_urpf_mode;
        hdr.pkts.pkt_11 = rmac_group;
        hdr.pkts.pkt_12 = igmp_snooping_enabled;
        hdr.pkts.pkt_13 = mld_snooping_enabled;
        hdr.pkts.pkt_14 = ipv4_multicast_enabled;
        hdr.pkts.pkt_15 = ipv6_multicast_enabled;
        hdr.pkts.pkt_16 = mrpf_group;
        hdr.pkts.pkt_17 = ipv4_mcast_key_type;
        hdr.pkts.pkt_18 = ipv4_mcast_key;
        hdr.pkts.pkt_19 = ipv6_mcast_key_type;
        hdr.pkts.pkt_20 = ipv6_mcast_key;
    }
    action port_vlan_mapping_miss() {
        hdr.pkts.pkt_21 = 1;
    }
    table port_vlan_mapping {
        actions = {
            set_bd_properties;
            port_vlan_mapping_miss;
        }
        key = {
            hdr.pkts.pkt_22 : exact;
            hdr.pkts.pkt_23         : exact;
            hdr.pkts.pkt_24         : exact;
        }
        size = 4096;
    }
    action int_sink_gpe(bit<32> mirror_id) {
        hdr.pkts.pkt_25 = hdr.pkts.pkt_26 << 2;
        hdr.pkts.pkt_27 = 1;
        hdr.pkts.pkt_28 = mirror_id;
    }
    action int_no_sink() {
        hdr.pkts.pkt_27 = 0;
    }
    table int_terminate {
        actions = {
            int_sink_gpe;
            int_no_sink;
        }
        key = {
            hdr.pkts.pkt_29    : exact;
            hdr.pkts.pkt_30            : exact;
        }
        size = 256;
    }

    action multicast_bridge_star_g_hit_ipv4(bit<32> mc_index) {
        hdr.pkts.pkt_31 = mc_index;
        hdr.pkts.pkt_32 = 1;
    }
    table ipv4_multicast_bridge_star_g {
        actions = {
            
            multicast_bridge_star_g_hit_ipv4;
        }
        key = {
            hdr.pkts.pkt_0      : exact;
            hdr.pkts.pkt_29 : exact;
        }
        size = 1024;
    }

    apply {
        port_vlan_mapping.apply();
        int_terminate.apply();
        ipv4_multicast_bridge_star_g.apply();
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
