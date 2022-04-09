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
    
    action terminate_cpu_packet() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_1;
        hdr.pkts.pkt_2 = hdr.pkts.pkt_3;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_5;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_7;
    }
    action switch_fabric_unicast_packet() {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_9 = hdr.pkts.pkt_10;
        hdr.pkts.pkt_11 = hdr.pkts.pkt_12;
    }
    action terminate_fabric_unicast_packet() {
        hdr.pkts.pkt_0 = hdr.pkts.pkt_13;
        hdr.pkts.pkt_14 = hdr.pkts.pkt_15;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_17;
        hdr.pkts.pkt_18 = hdr.pkts.pkt_19;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_21;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_23;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_24;
    }
    action switch_fabric_multicast_packet() {
        hdr.pkts.pkt_8 = 1;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_25;
    }
    action terminate_fabric_multicast_packet() {
        hdr.pkts.pkt_14 = hdr.pkts.pkt_26;
        hdr.pkts.pkt_16 = hdr.pkts.pkt_27;
        hdr.pkts.pkt_18 = 0;
        hdr.pkts.pkt_20 = hdr.pkts.pkt_28;
        hdr.pkts.pkt_22 = hdr.pkts.pkt_29;
        hdr.pkts.pkt_4 = hdr.pkts.pkt_30;
        hdr.pkts.pkt_6 = hdr.pkts.pkt_31;
    }
    table fabric_ingress_dst_lkp {
        actions = {
            
            terminate_cpu_packet;
            switch_fabric_unicast_packet;
            terminate_fabric_unicast_packet;
            switch_fabric_multicast_packet;
            terminate_fabric_multicast_packet;
        }
        key = {
            hdr.pkts.pkt_10 : exact;
        }
    }
    action set_storm_control_meter(bit<32> meter_idx) {
        hdr.pkts.pkt_32 = (bit<32>)meter_idx;
    }
    table storm_control {
        actions = {
            
            set_storm_control_meter;
        }
        key = {
            hdr.pkts.pkt_33 : exact;
            hdr.pkts.pkt_34 : exact;
        }
        size = 512;
    }

    apply {
        fabric_ingress_dst_lkp.apply();
        storm_control.apply();
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
