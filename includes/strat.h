#ifndef _START_H_
#define _START_H_

#include <main.h>
#include <types.h>
#include <receive.h>

// different spoof methods
#define SPOOF_WITH_ANNOUNCE 1
#define SPOOF_WITH_REPLY 2
#define SPOOF_WITH_REQUEST 3

// spoof operation
#define OPP_SPOOF 1
#define OPP_REPLY 2

// time to wait for ping answer, in ms
#define WAIT_PING_ANSWER_TIME 50

// Send multiple ping at each iteration in case one get lost
#define PING_INTERVAL 50 // in ms
#define PING_RETRY 2

// poisoning loop parameters
#define REFRESH_LOOP_INT 10 // Interval between two consecutive poisonning
#define HOST_DOWN_AFTER 60 // Number of seconds before a target is considered down, roughly

struct ping_listener_args_t {
  uint32_t ip_1;
  struct spoof_strategy* strat_1;
  uint32_t ip_2;
  struct spoof_strategy* strat_2;
};

// ARP frames shortcut
#define send_arp_annoucement(our_ip, our_ether, target_ether) \
  send_arp(ARP_REQUEST_OP, our_ether, target_ether, our_ether, our_ip, (uint8_t*)mac_zero, our_ip)

#define send_arp_reply(our_ip, our_ether, target_ip, target_ether) \
  send_arp(ARP_REPLY_OP, our_ether, target_ether, our_ether, our_ip, target_ether, target_ip)

#define send_arp_request(our_ip, our_ether, target_ip, target_ether) \
  send_arp(ARP_REQUEST_OP, our_ether, target_ether, our_ether, our_ip, (uint8_t*)mac_zero, target_ip)

// send ICMP echo request
int send_ping(uint8_t* our_ether, uint32_t our_ip, uint8_t* target_ether, uint32_t target_ip, uint16_t seq_number);

#define reply_to_target(context, target) \
  apply_strategy(context, target, OPP_REPLY)

#define spoof_target(context, target) \
  apply_strategy(context, target, OPP_SPOOF)

// spoof a target according to our strategy
int apply_strategy(struct spoof_context* context, uint8_t target, uint8_t opp);

// compute 16 bits checksum
uint16_t compute_checksum(char* buff, uint16_t length);

// listener callback, listen porn ICMP echo replies & update the strategy
int ping_listener(char* buff, struct capture_auxdata_t* aux, void* raw_args);

// ping listener thread, start the ping capture
void* ping_listener_thread(void* raw_args);

// strat to string
char* getStratString(uint8_t strat);

// display strat
void print_strat(struct spoof_strategy* s);

// Define the poison strategy for each target
int define_spoof_strategy(struct spoof_context* context);

#endif
