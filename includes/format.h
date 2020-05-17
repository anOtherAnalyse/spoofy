#ifndef _FORMAT_H_
#define _FORMAT_H_

#define DEFAULT_OUTPUT_PREFIX "capture_"

#include <sys/time.h>

#include <types.h>

// pcap format file header
typedef struct __attribute__ ((packed)) pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

// pcap per packet capture header
typedef struct __attribute__ ((packed)) pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

static int output_fd = -1;
static char* filename = NULL;

// create new formated file using filename & output_fd static variable
int create_formated_file();

// open new capture file, chose the name
int open_new_capture();

// open new capture file of given name
int open_capture(char* file);

// stop current capture
void close_capture();

// add new capture to capture file
int add_capture(char* buff, uint32_t cap_length, uint32_t real_length, struct timeval* time);

#endif
