#ifndef _FILTER_H_
#define _FILTER_H_

#include <types.h>

#define MAX_FILTER_RULE_LEN 256

#define MAX(a,b) (((a)>(b))?(a):(b))

// A list of addresses
struct address_list {
  // uint16_t addr_length;
  uint16_t length;
  uint8_t* addr;
};

// a raw filter represented by the addresses & protocols expected
struct raw_filter {
  struct address_list ether_src;
  struct address_list ether_dst;
  struct address_list ether_type;
  struct address_list protocol_src;
  struct address_list protocol_dst;
  struct address_list protocol_type;
  struct address_list transport_src;
  struct address_list transport_dst;
  union {
    uint8_t negation;
    struct {
      uint8_t ether_src_neg : 1;
      uint8_t ether_dst_neg : 1;
      uint8_t ether_type_neg : 1;
      uint8_t protocol_src_neg : 1;
      uint8_t protocol_dst_neg : 1;
      uint8_t protocol_type_neg : 1;
      uint8_t transport_src_neg : 1;
      uint8_t transport_dst_neg : 1;
    };
  };
};

// a rule that was flattened = list of raw filters
struct flattened_rule {
  struct raw_filter flat_rule;
  struct flattened_rule* next;
};

// summary of a packet
struct packet_layers {
  uint8_t* ether_src;
  uint8_t* ether_dst;
  uint8_t* ether_type;
  uint8_t* ip_src;
  uint8_t* ip_dst;
  uint8_t* protocol;
  uint8_t* port_src;
  uint8_t* port_dst;
};

/* Elements used in the rule parsing */

// Filters (<= END_FILTER_TOK)
#define ETHER_TOK 0
#define ETHER_ADDR_SRC_TOK 1
#define ETHER_ADDR_DST_TOK 2

#define ARP_TOK 3
#define IP_TOK 4

#define HOST_TOK 5
#define IP_ADDR_SRC_TOK 6
#define IP_ADDR_DST_TOK 7

#define TCP_TOK 8
#define UDP_TOK 9
#define ICMP_TOK 10

#define PORT_TOK 11
#define PORT_SRC_TOK 12
#define PORT_DST_TOK 13

#define END_FILTER_TOK 14

// Logical opperators
#define PAR_OPN 15
#define PAR_CLS 16
#define OPP_OR 17
#define OPP_AND 18
#define OPP_NOT 19

// Used in the final rule form
#define ETHER_TYPE_TOK 20
#define PROTOCOL_TOK 21

/*
  Grammar:
    E -> T
    E -> T and E
    E -> T or E
    T -> not T
    T -> ( E )
    T -> src %u.%u.%u.%u
    T -> dst %u.%u.%u.%u
    T -> host %u.%u.%u.%u
    T -> ether [src | dst] %x:%x:%x:%x:%x:%x
    T -> port [src | dst] %u
    T -> arp
    T -> ip
    T -> udp
    T -> tcp
    T -> icmp
*/

/* A lexeme, lexical unit */
struct token {
  uint32_t type;
  uint16_t length;
  char* value;
};

#define UNARY_TERM 1
#define BINARY_TERM 2
#define NEGATION_TERM 0x80

/* A Term, unary or binary */
struct term {
  uint8_t type;
};

struct unary_term {
  uint8_t type; // UNARY_TERM
  struct token token;
};

struct binary_term {
  uint8_t type; // BINARY_TERM
  struct term* exp_left;
  uint8_t opp;
  struct term* exp_right;
};

struct rule_node {
  uint8_t type;
  uint8_t value[6];
  struct rule_node* next;
  struct rule_node* child;
};

/* ****************************
 * Filter rule creation & usage
 * **************************** */

// main function, parse a string rule into a hierarchical rule
int parseRule(char* rule, struct rule_node** result);

// free an allocated rule
void freeRule(struct rule_node* rule);

// Apply rule to a packet summary
// return 1 if packet correspond, 0 otherwise
int applyRule(struct rule_node* rule, struct packet_layers* packet);

// inflate hierarchical rule from a flat rule
int inflateRule(struct raw_filter* rule, struct rule_node** result);

/* ***************
 * Rule flattening
 * *************** */

// flatten a rule (node) into a list of possibilities: flat rules
// usefull to check rule realisation & re-write it in a way closer to the capture filter actually used
int flattenRule(struct term* node, struct flattened_rule** result);

// dynamic allocation for a flat rules linked list
int allocLinkedFlatRules(struct flattened_rule** result, uint8_t number);

// Free linked list of flatten rules
void freeLinkedFlatRules(struct flattened_rule* list);

// Add an address to an address list
int allocAddrList(struct address_list* addrs, uint8_t* addr, uint16_t length);

// is an address in the adress list
int isInAddrList(struct address_list* addrs, uint8_t* addr, uint16_t length);

// duplicate address list
int copyAddr(struct address_list* dst, struct address_list* src, uint16_t length);

// merge two adress lists, return 1 if not compatible
int mergeAdressesLists(struct address_list* a1, uint8_t a1_neg,
  struct address_list* a2, uint8_t a2_neg, struct address_list* result, uint16_t addr_len);

// merge two raw filters, return 1 if not compatible
int mergeRawFilters(struct raw_filter* r1, struct raw_filter* r2, struct raw_filter* result);

/* ******************
 * Expression parsing
 * ****************** */

// Parse T element from previous grammar, return 0 if success
int parseT(char** rule, struct term** result);

// Parse E element from previous grammar, return 0 if success
int parseE(char** rule, struct term** result);

// Free an expression previously allocted (by a call to parseE or parseT)
void freeExp(struct term* rule);

/* Get next word in string rule, update rule to the start of the term and length to its length
 * Return 0 if success, 1 if no more word in rule */
int nextWord(char** rule, uint16_t* length);

/* Get next token unit in the string rule, move the cursor rule in the same time
 * Return 0 if success, 1 if error in token specification, 2 if no more token in rule */
int nextToken(char** rule, struct token* token);

// Parse addresses and store result in token, return 1 if failure
int parseIPAddr(char** rule, struct token* token);
int parseMACAddr(char** rule, struct token* token);
int parsePort(char** rule, struct token* token);

/* *************
 * debug display
 * ************* */
void printExp(struct term* rule);
void __printExp(struct term* rule); // Do not use, recursive utility
void printAddrList(struct address_list* list, uint8_t neg, uint16_t length);
void printFlatRule(struct flattened_rule* rule); // display flatten rule - raw rules
void printRule(struct rule_node* rule, uint8_t shift);

/* *********
 * Utilities
 * ********* */

// Compare two MAC addresses, return 1 if equal, may be faster than a memcmp
int ethercmp(uint8_t* ether_1, uint8_t* ether_2);

// add a not ip dest rule in the rule
int addSrcIp(struct rule_node* rule, uint32_t ip);

#endif
