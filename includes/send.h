#ifndef _SEND_ARP_H_
#define _SEND_ARP_H_

#define ARP_REQUEST_OP 1
#define ARP_REPLY_OP 2

// Commands send by receiver thread to sender thread
#define SEND_CMD_LOC 0
#define SEND_CMD_RPL 1 // reply to a target
#define SEND_CMD_SPF 2 // re-spoof a target

#include <types.h>
#include <main.h>

// Arguments for the refresh thread
struct poison_loop_arg_t {
  struct spoof_context* context;
  int pip;
};

// constant field fro zero & broadcast MAC addresses
static uint8_t const mac_broadcast[6] = {255,255,255,255,255,255};
static uint8_t const mac_zero[6] = {0,0,0,0,0,0};

// To be accessible from the signal handler used for the poison refresh loop
static struct poison_loop_arg_t* poison_parameters;
static int8_t up_count_1, up_count_2; // Used to known when a target is down

/* Refresh the spoof every given interval, uses a timer */
void refresh_spoof(int signal);

/* Poisonning refresh thread, poison the targets each given interval, & react to query from targets */
void* poison_loop(void* raw_args);

/* Send arp frame of given parameters */
int send_arp(uint16_t op, uint8_t* ether_MAC_src, uint8_t* ether_MAC_dst, uint8_t* arp_MAC_src,
   uint32_t arp_ip_src, uint8_t* arp_MAC_dst, uint32_t arp_ip_dst);

/* Init raw socket to send raw packet on given interface */
int init_raw_sock(char* interface);

/* Send a raw frame buff of given length on the network */
int send_frame(char* buff, unsigned long length);

#endif
