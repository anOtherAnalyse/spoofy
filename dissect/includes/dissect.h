#ifndef _DISSECT_H_
#define _DISSECT_H_

#include <types.h>
#include <protocols.h>

#include "parse.h"

// state of packet summary beeing displayed
struct dissect_state {
  uint32_t cursor;
  uint32_t current;
  char* buff; // current packet
  uint32_t buff_len;
};

struct dns_record {
  uint16_t type;
  uint16_t class;
};

/* Read capture from file and record it in buff */
int parse_capture(capture_t* capture);

/* Free recorded capture */
void free_capture();

/* Display recorded capture */
void display_packet_summary();

/* Print line if in current window */
void print_dissect(char* format, ...);

/* Move point of view in screen by shift (up+ or down-) */
void move_summary_cursor(int16_t shift);

/* L2 dissection */
void dissect_ethernet(char* buff, unsigned int size);

/* L3 dissection */
void dissect_ipv4(char* buff, unsigned int size);
char* getIpOptionName(unsigned char type);
void dissect_arp(char* buff, unsigned int size);

/* L4 dissection */
void dissect_tcp(char* buff, unsigned int size);
char* getTcpOptionName(unsigned char type);
void dissect_udp(char* buff, unsigned int size);
void dissect_icmp(char* buff, unsigned int size);

/* L7 dissection */
// DNS
void dissect_dns(char* buff, unsigned int size);
char* getDNSTypeName(unsigned short int type);
char* printfCharacterString(char* head, char* end, char* buff, uint32_t size);
char* printfDNSName(char* buff, char* head, char* end, char* copy, uint32_t size);
char* printfDNSQuestion(char* buff, char* head, char* end, struct dns_record* ret);
char* printfDNSResponse(char* buff, char* head, char* end);

// Raw ascii
void dissect_ascii(char* buff, unsigned int size);
void convert_to_printable(char* c);

// hexa dump
void dissect_hexa_dump(char* buff, unsigned int size);

// copy to string of limited size
void fill_buff(char** buff, uint32_t* len, char* format, ...);

#endif
