/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "types.p4"
#include "ngap_definitions.p4"

const port_t CPU_PORT               = 0x1;

const bit<16> ARP_OP_REQ            = 0x0001;
const bit<16> ARP_OP_REPLY          = 0x0002;

// Eth types
const bit<16> TYPE_ARP              = 0x0806;
const bit<16> TYPE_CPU_METADATA     = 0x080a;
const bit<16> TYPE_IPV4             = 0x800;
// IP protos
const bit<8>  TYPE_ICMP             = 0x1;
const bit<8>  TYPE_TCP              = 0x06;
const bit<8>  TYPE_UDP              = 0x11;
const bit<8>  TYPE_SCTP             = 0x84;
// SCTP ports
// See 3GPP TS 38.414 ver 15.0.0 rel 15
const bit<16> NGAP_PORT             = 38412;

// SCTP CHUNK TYPES
const byte_t DATA_CHUNK             = 0x00;
const byte_t SACK_CHUNK             = 0x03;

// Provide counters for the following: IP, ARP, packets-to-cp
const bit<32> COUNTER_IP = 0x0;
const bit<32> COUNTER_ARP = 0x1;
const bit<32> COUNTER_CP = 0x2;

counter(3, CounterType.packets) ct;

header ethernet_t {
    macAddr_t dst;
    macAddr_t src;
    bit<16>   type;
}

header cpu_metadata_t {
    bit<8>      fromCpu;
    bit<16>     origEtherType;
    bit<16>     sourcePort;
    ip4Addr_t   arpDst;
}

header arp_t {
    bit<16>     hwType;
    bit<16>     protoType;
    bit<8>      hwAddrLen;
    bit<8>      protoAddrLen;
    bit<16>     opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t   srcMAC;
    ip4Addr_t   srcIP;
    macAddr_t   dstMAC;
    ip4Addr_t   dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   len;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t src;
    ip4Addr_t dst;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header sctp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> verifyTag;
    bit<32> checksum;
}

header sctp_chunk_t {
    bit<8> type;
    bit<8> flags;
    bit<16> length;
}

header data_t {
    bit<32> tsn; // tranmission sequence number
    bit<16> sid; // stream id
    bit<16> ssn; // stream sequence number
    bit<32> protoID; // payload protocol identifier
}

header sack_t {
    bit<32> cumTsnAck; // cum. tsn. ack
    bit<32> advRecWind; // advertised receiver window credit
    bit<16> numGapAckBlocks;
    bit<16> numOfDuplTSN;
}

// this might be valid for PDU only.
header ngap_t {
    bit<8> choice;
    bit<16> messageType;
    bit<8> procedureCode;
    bit<8> criticality;
}

// header ngap_value_xx_t {


// }


struct headers {
    ethernet_t        eth;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    sctp_t            sctp;
    sctp_chunk_t      sctp_chunk;
    data_t            data;
    sack_t            sack;
    ngap_t            ngap;
}

struct metadata {
    ip4Addr_t       nextHop;
    bit<1>          matchedLocalIP;
    port_t          sourcePort;
}
