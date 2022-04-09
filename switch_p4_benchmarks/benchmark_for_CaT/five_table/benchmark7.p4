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
    action non_ip_lkp() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
    }
    action ipv4_lkp() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_8;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_9;
        hdr.pkts.pkt_10 = hdr.pkts.pkt_11;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_12;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_18;
    }
    action ipv6_lkp() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_19;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_20;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_22;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_25;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_27;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_28;
    }
    table adjust_lkp_fields {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.pkts.pkt_29 : exact;
            hdr.pkts.pkt_30 : exact;
        }
    }
    action non_ip_lkp() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_31;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_32;
    }
    action ipv4_lkp() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_33;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_34;
        hdr.pkts.pkt_10 = hdr.pkts.pkt_35;
        hdr.pkts.pkt_3 = hdr.pkts.pkt_36;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_37;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_38;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_39;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_40;
    }
    action ipv6_lkp() {
        hdr.pkts.pkt_4 = hdr.pkts.pkt_41;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_42;
        hdr.pkts.pkt_21 = hdr.pkts.pkt_43;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_44;
        hdr.pkts.pkt_1 = hdr.pkts.pkt_45;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_46;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_47;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_48;
    }
    table tunnel_lookup_miss_0 {
        actions = {
            non_ip_lkp;
            ipv4_lkp;
            ipv6_lkp;
        }
        key = {
            hdr.pkts.pkt_29 : exact;
            hdr.pkts.pkt_30 : exact;
        }
    }
    action src_vtep_hit(bit<32> ifindex) {
        hdr.pkts.pkt_49 = ifindex;
    }
    table ipv6_src_vtep {
        actions = {
            
            src_vtep_hit;
        }
        key = {
            hdr.pkts.pkt_50                    : exact;
            hdr.pkts.pkt_43                        : exact;
            hdr.pkts.pkt_51 : exact;
        }
        size = 1024;
    }
    action set_lag_port(bit<32> port) {
        hdr.pkts.pkt_52 = port;
    }
    action set_lag_remote_port(bit<32> device, bit<32> port) {
        hdr.pkts.pkt_53 = device;
        hdr.pkts.pkt_54 = port;
    }
    table lag_group {
        actions = {
            set_lag_port;
            set_lag_remote_port;
        }
        key = {
            hdr.pkts.pkt_55 : exact;
            hdr.pkts.pkt_56            : exact;
        }
        size = 1024;
    }

    apply {
        ipsg_permit_special.apply();
        adjust_lkp_fields.apply();
        tunnel_lookup_miss_0.apply();
        ipv6_src_vtep.apply();
        lag_group.apply();
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
