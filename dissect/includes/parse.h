#ifndef _PARSE_H_
#define _PARSE_H_

#include <types.h>
#include <filter.h>

// size of buffer used to store a packet
#define MAX_CAP_LEN 2048

typedef struct capture_s {
  struct  __attribute__((packed)) {
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
  };
  uint16_t ether_type;
  struct  __attribute__((packed)) {
    uint8_t ip_src[4];
    uint8_t ip_dst[4];
  };
  uint8_t protocol;
  struct  __attribute__((packed)) {
    uint16_t port_src;
    uint16_t port_dst;
  };
  uint16_t index; // index in the index table
  uint32_t len;

  struct capture_s *next, *previous; // linked list
} capture_t;

struct parse_context {
  int fd;
  uint32_t* index;
  uint32_t capture_len; // total number of packets in the file
  uint32_t filtered_len; // number of packet processed yet & applying to current filter
  uint16_t max_index; // index of last recorded capture in the current set
  capture_t* capture_start;
  capture_t* capture_current;
  struct rule_node* filter;
};

/* Open pcap file for parsing
 * Init the context static variable, the capture length & captures index
 * set up parse index to be on first packet
 */
int open_pcap_file(char* filename);

// Init the captures index for direct access
int init_index();

/* Close the file opened for parsing, free the captures index
 */
void close_pcap_file();

/* Init capture set from start of capture file, for given size
 * Only record captures conforming to given rule
 */
void init_capture_set(uint16_t size, struct rule_node* rule);

/* Move index on the capture set by shift, complete set to given size */
void move_capture_set_index(int8_t shift, uint16_t size);

// complete capture set to given size, return completed size (< size if no more captures)
uint32_t complete_capture_set(uint16_t size);

/* Read file to add capture to capture set, at given place
 */
int add_to_capture_set(capture_t** set, capture_t* previous, uint32_t index, struct rule_node* rule);

/* Free a capture set that has been previously allocated
 */
void free_capture_set(capture_t** capture);

#endif
