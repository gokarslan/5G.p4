#ifndef HEADER_TYPES_P4
#define HEADER_TYPES_P4

// Common types
typedef bit<8>  byte_t;
typedef bit<32> int_t;

// Network types
typedef bit<9>  port_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

#endif