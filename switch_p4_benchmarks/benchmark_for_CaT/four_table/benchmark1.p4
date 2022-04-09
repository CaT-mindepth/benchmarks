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
    action int_set_src() {
        hdr.pkts.pkt_11 = 1;
    }
    action int_set_no_src() {
        hdr.pkts.pkt_11 = 0;
    }
    table int_source {
        actions = {
            int_set_src;
            int_set_no_src;
        }
        key = {
            hdr.pkts.pkt_12 : exact;
            hdr.pkts.pkt_13 : exact;
            hdr.pkts.pkt_14        : exact;
            hdr.pkts.pkt_15        : exact;
        }
        size = 256;
    }

    action terminate_eompls(bit<32> bd, bit<32> tunnel_type) {
        hdr.pkts.pkt_16 = 1;
        hdr.pkts.pkt_17 = tunnel_type;
        hdr.pkts.pkt_18 = bd;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_20;
    }
    action terminate_vpls(bit<32> bd, bit<32> tunnel_type) {
        hdr.pkts.pkt_16 = 1;
        hdr.pkts.pkt_17 = tunnel_type;
        hdr.pkts.pkt_18 = bd;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_21;
    }
    action terminate_ipv4_over_mpls(bit<32> vrf, bit<32> tunnel_type) {
        hdr.pkts.pkt_16 = 1;
        hdr.pkts.pkt_17 = tunnel_type;
        hdr.pkts.pkt_22 = vrf;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_24;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_27 = 1;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_29 = hdr.pkts.pkt_30;
    }
    action terminate_ipv6_over_mpls(bit<32> vrf, bit<32> tunnel_type) {
        hdr.pkts.pkt_16 = 1;
        hdr.pkts.pkt_17 = tunnel_type;
        hdr.pkts.pkt_22 = vrf;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_31;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_32;
        hdr.pkts.pkt_27 = 2;
        hdr.pkts.pkt_19 = hdr.pkts.pkt_33;
        hdr.pkts.pkt_29 = hdr.pkts.pkt_34;
    }
    action terminate_pw(bit<32> ifindex) {
        hdr.pkts.pkt_35 = ifindex;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_36;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_37;
    }
    action forward_mpls(bit<32> nexthop_index) {
        hdr.pkts.pkt_38 = nexthop_index;
        hdr.pkts.pkt_39 = 0;
        hdr.pkts.pkt_40 = 1;
        hdr.pkts.pkt_23 = hdr.pkts.pkt_41;
        hdr.pkts.pkt_25 = hdr.pkts.pkt_42;
    }
    table mpls_0 {
        actions = {
            terminate_eompls;
            terminate_vpls;
            terminate_ipv4_over_mpls;
            terminate_ipv6_over_mpls;
            terminate_pw;
            forward_mpls;
        }
        key = {
            hdr.pkts.pkt_0 : exact;
        }
        size = 1024;
    }
    action dmac_hit(bit<32> ifindex) {
        hdr.pkts.pkt_35 = ifindex;
        hdr.pkts.pkt_43 = hdr.pkts.pkt_43 ^ ifindex;
    }
    action dmac_multicast_hit(bit<32> mc_index) {
        hdr.pkts.pkt_44 = mc_index;
        hdr.pkts.pkt_45 = 127;
    }
    action dmac_miss() {
        hdr.pkts.pkt_35 = 65535;
        hdr.pkts.pkt_45 = 127;
    }
    action dmac_redirect_nexthop(bit<32> nexthop_index) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_47 = nexthop_index;
        hdr.pkts.pkt_48 = 0;
    }
    action dmac_redirect_ecmp(bit<32> ecmp_index) {
        hdr.pkts.pkt_46 = 1;
        hdr.pkts.pkt_47 = ecmp_index;
        hdr.pkts.pkt_48 = 1;
    }
    table dmac {
        support_timeout = true;
        actions = {
            
            dmac_hit;
            dmac_multicast_hit;
            dmac_miss;
            dmac_redirect_nexthop;
            dmac_redirect_ecmp;
        }
        key = {
            hdr.pkts.pkt_18   : exact;
            hdr.pkts.pkt_25 : exact;
        }
        size = 1024;
    }

    apply {
        validate_mpls_packet.apply();
        int_source.apply();
        mpls_0.apply();
        dmac.apply();
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
