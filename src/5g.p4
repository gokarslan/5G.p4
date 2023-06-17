/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_eth;
    }

    state parse_eth {
        packet.extract(hdr.eth);
        transition select(hdr.eth.type) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_SCTP: parse_sctp;
            //TYPE_TCP: parse_tcp;
            //TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_sctp {
        packet.extract(hdr.sctp);
        transition select(hdr.sctp.srcPort){
            NGAP_PORT: parse_sctp_chunk;
            default: parse_sctp_dst;
        }
    }

    state parse_sctp_dst {
        transition select(hdr.sctp.dstPort){
            NGAP_PORT: parse_sctp_chunk;
            default: accept;
        }
    }

    state parse_sctp_chunk {
        packet.extract(hdr.sctp_chunk);
        transition select(hdr.sctp_chunk.type){
            DATA_CHUNK: parse_data_chunk;
            SACK_CHUNK: parse_sack_chunk;
            default: accept;
        }
    }

    // Assume sack is always come with a data chunk
    state parse_sack_chunk {
        packet.extract(hdr.sack);
        transition parse_data_chunk;
        //transition select(hdr.sack)
    }
    state parse_data_chunk {
        packet.extract(hdr.data);
        transition parse_ngap;
    }

    state parse_ngap {
        packet.extract(hdr.ngap);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    apply {
        if(hdr.arp.isValid()){
            hdr.arp.opcode = 2;
            bit <32> tmp_ip;
            if (standard_metadata.ingress_port == 1) {
                hdr.arp.srcMAC = 0x00aabb000001;
            } else if (standard_metadata.ingress_port == 2) {
                hdr.arp.srcMAC = 0x00aabb000002;
            }
            tmp_ip = hdr.arp.srcIP;
            hdr.arp.srcIP = hdr.arp.dstIP;
            hdr.arp.dstIP = tmp_ip;
            
            hdr.arp.dstMAC = hdr.eth.src;

            hdr.eth.dst = hdr.eth.src;
            hdr.eth.src = hdr.arp.dstMAC;
            standard_metadata.egress_spec = standard_metadata.ingress_port;
        }
        else if(hdr.ngap.isValid()){
            // Swap Ethernet and IPv4
            bit<48> tempEthernet = hdr.eth.src;
            hdr.eth.src = tempEthernet;
            hdr.eth.dst = hdr.eth.src;
        
            bit <32> tempIP = hdr.ipv4.src;
            hdr.ipv4.src = hdr.ipv4.dst;
            hdr.ipv4.dst = tempIP;
            hdr.ipv4.len = hdr.ipv4.len + 128 / 8;

            bit<16> tempPort = hdr.sctp.srcPort;
            hdr.sctp.srcPort = hdr.sctp.dstPort;
            hdr.sctp.dstPort = tempPort;

            //hdr.ngap.messageType = 5;
            //hdr.ngap.procedureCode = 6;
            //hdr.ngap.criticality = 7;

            standard_metadata.egress_spec = standard_metadata.ingress_port;
        }
        else{
            if (standard_metadata.ingress_port == 1) {
                standard_metadata.egress_spec = 2;
                hdr.eth.dst = 0x000400000001;//0x00aabb000001;
            } else if (standard_metadata.ingress_port == 2) {
                standard_metadata.egress_spec = 1;
                hdr.eth.dst = 0x000400000000;
            }
        }
        hdr.ipv4.ttl = 52;
    }
/*
    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.eth.etherType;
        hdr.cpu_metadata.sourcePort = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu_metadata.arpDst = meta.nextHop;
        hdr.eth.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.eth.etherType = hdr.cpu_metadata.origEtherType;
        meta.sourcePort = (bit<9>)hdr.cpu_metadata.sourcePort;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
        // increment counter for packets-to-cp
        ct.count(COUNTER_CP);
    }

    action route(ip4Addr_t nextHop, egressSpec_t port){
        standard_metadata.egress_spec = port;
        meta.nextHop = nextHop;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // not here...
        // hdr.eth.src = hdr.eth.dst;
        //hdr.eth.dst = dst;

    }

    action arp_lookup(macAddr_t nextHopMac){
        // set the src MAC address based on the port the packet is departing from
        hdr.eth.src = hdr.eth.dst; //0x000000000100 + (bit<48>)standard_metadata.egress_spec;
        hdr.eth.dst = nextHopMac;

        // decrement TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action local_ipv4_match(){
        meta.matchedLocalIP = 0x1;
    }

    action drop_local_match(){
    }

    action send_pwospf_hello(){
        standard_metadata.egress_spec = meta.sourcePort;

    }
    table routing_table {
        key = {
            hdr.ipv4.dst: lpm;
        }
        actions = {
            drop_local_match;
            route;
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table arp_table {
        key = {
           meta.nextHop: exact;
        }
        actions = {
            arp_lookup;
            // if there is a entry in the routing table but there is no entry in the arp table.
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 64;
        default_action = send_to_cpu();
    }

    table local_ipv4_table {
        key = {
            hdr.ipv4.dst: exact;
        }
        actions = {
            local_ipv4_match;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table fwd_l2 {
        key = {
            hdr.eth.dst: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    // TODO is initial value always 0?
    action init_matchedlocalip(){
        meta.matchedLocalIP = 0x0;
    }
    apply {

        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if (hdr.arp.isValid()) {
            // increment counter for ARP
            ct.count(COUNTER_ARP);
            if(standard_metadata.ingress_port != CPU_PORT){
                send_to_cpu();
            }else{
                fwd_l2.apply();

            }
        }
        else if (hdr.eth.isValid()) {
            if (hdr.ipv4.isValid()){
                // is initial value always 0?
                // init_matchedlocalip();
                // increment counter for IP
                ct.count(COUNTER_IP);

                if (hdr.pwospf.isValid()){
                    if(standard_metadata.ingress_port == CPU_PORT){
                        if(hdr.pwospf.type == TYPE_PWOSPF_HELLO){
                            send_pwospf_hello();
                        }else{
                            routing_table.apply();
                            arp_table.apply();
                        }

                    // PWOSPF packets should be sent to the software
                    }else{
                        send_to_cpu();
                    }

                } else{
                    // local IP packets (destined for the router) should be sent to the software
                    local_ipv4_table.apply();
                    if (meta.matchedLocalIP == 0x1){
                        send_to_cpu();
                    }
                    else{
                        // look up the next-hop port and IP address in the route table
                        routing_table.apply();
                        // look up the MAC address of the next-hop in the ARP table
                        arp_table.apply();
                    }
                }
            } else{
                // any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
                send_to_cpu();
            }
        } else{
            // any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
            send_to_cpu();
        }

    }*/
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

        hdr.ipv4.ttl = 53;
        //hdr.dns_resp.answer = 0xc00c000100010000012b0004acd9a9ce;
        //hdr.dns_resp.setValid();
        hdr.ngap.messageType = HANDOVER_NOTIFICATION;
        hdr.ngap.procedureCode = 11;
        hdr.ngap.criticality = 12;
        
     }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    // calculate a new IP checksum
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src,
                hdr.ipv4.dst
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.sctp);
        packet.emit(hdr.sctp_chunk);
        packet.emit(hdr.sack);
        packet.emit(hdr.data);
        packet.emit(hdr.ngap);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;