#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <types.h>

struct __attribute__ ((packed)) ethernet_header {
   uint8_t ether_dhost[6];
   uint8_t ether_shost[6];
   uint16_t ether_type;
};

struct __attribute__ ((packed)) arp_header {
  uint16_t hdw_type;
  uint16_t protocol;
  uint8_t ether_addr_len;
  uint8_t protocol_addr_len;
  uint16_t operation;
  uint8_t MAC_src[6];
  uint8_t ip_src[4];
  uint8_t MAC_target[6];
  uint8_t ip_target[4];
};

struct __attribute__ ((packed)) ip_header {
    struct {
      uint8_t IHL : 4; // Length of the header in blocks of 4 bytes
      uint8_t version : 4; // 4
    };
    struct {
      uint8_t ECN : 2; // Notification of network congestion
      uint8_t DSCP : 6; // ToS, used in DiffServ
    };
    uint16_t total_length; // packet size in bytes
    uint16_t identification; // identify the group of fragments in a single packet
    struct {
      uint8_t fragment_offset_1 : 5; // Fragment offset in the packet, in unit of 8-bytes blocks (first part)
      uint8_t zero : 1;
      uint8_t DF : 1; // don't fragment
      uint8_t MF : 1; // more fragment
    };
    uint8_t fragment_offset_2; // second part
    uint8_t TTL;
    uint8_t protocol; // encapsulated protocol
    uint16_t header_checksum;
    uint8_t source_address[4];
    uint8_t destination_address[4];
};

struct __attribute__ ((packed)) ip_option_type {
  uint8_t number : 5;
  uint8_t class : 2;
  uint8_t copie : 1;
};

struct __attribute__ ((packed)) tcp_header {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_number;
  uint32_t ack_number;
  struct {
    uint8_t NS : 1; // ECN-nonce - concealment protection
    uint8_t reserved : 3;
    uint8_t data_offset : 4; // Header size in number of 32-bits words
  };
  union {
    struct {
      uint8_t FIN : 1; // Last packet from sender
      uint8_t SYN : 1; // Synchronize sequence numbers
      uint8_t RST : 1; // Reset the connection
      uint8_t PSH : 1;
      uint8_t ACK : 1; // Acknowledgment is set
      uint8_t URG : 1; // Urgent field is significant
      uint8_t ECE : 1; // network congestion
      uint8_t CWR : 1; // Congestion window reduced
    };
    uint8_t flags;
  };
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_pointer;
};

struct __attribute__ ((packed)) udp_header {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};

struct __attribute__ ((packed)) dns_header {
  uint16_t identification;
  struct {
    uint8_t RD : 1; // recursion desired, for a client query
    uint8_t TC : 1; // Was the message truncated
    uint8_t AA : 1; // Authoritative Answer, is the responding server the authority for the queried hostname
    uint8_t opcode : 4;
    uint8_t QR : 1; // query(0) response(1)
  };
  struct {
    uint8_t RCODE : 4; // response code
    uint8_t zero : 3;
    uint8_t RA : 1; // recursion available, from a server
  };
  uint16_t question_count;
  uint16_t answer_count;
  uint16_t authority_count;
  uint16_t Additional_count;
};

struct __attribute__ ((packed)) icmp_header {
  uint8_t type;
  uint8_t code; // subtype
  uint16_t checksum;
  union {
    uint32_t rest_of_header; // variable content, do not confound with the data part that can follow
    struct { // for ICMP echo
      uint16_t identifier;
      uint16_t seq_number;
    };
  };
};

struct __attribute__ ((packed)) tls_record {
  uint8_t content_type;
  union {
    struct {
      uint8_t major;
      uint8_t minor;
    };
    uint16_t legacy_version;
  };
  uint16_t length;
};

#endif
