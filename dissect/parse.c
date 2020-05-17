#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <format.h>
#include <protocols.h>

#include "includes/parse.h"

struct parse_context context = {
  .capture_start = NULL,
  .capture_current = NULL,
  .filter = NULL
};

int open_pcap_file(char* filename) {
  int len;
  pcap_hdr_t header;
  pcaprec_hdr_t cap_header;
  if((context.fd = open(filename, O_RDONLY)) == -1) {
    perror("open");
    return 1;
  }

  if((len = read(context.fd, &header, sizeof(header))) == -1) {
    perror("read");
    return 1;
  }

  if(len < sizeof(header)) {
    fprintf(stderr, "Error: truncated pcap header\n");
    return 1;
  }

  if(header.magic_number != 0xa1b2c3d4) {
    fprintf(stderr, "Error: parser only support 0xa1b2c3d4 magic\n");
    return 1;
  }

  if(header.network != 1) {
    fprintf(stderr, "Error: parser only support ethernet capture\n");
    return 1;
  }

  // init capture_len
  context.capture_len = 0;
  if((len = read(context.fd, &cap_header, sizeof(cap_header))) == -1) {
    perror("read");
    return 1;
  }

  while(len == sizeof(cap_header)) {
    context.capture_len ++;
    lseek(context.fd, cap_header.incl_len, SEEK_CUR);
    if((len = read(context.fd, &cap_header, sizeof(cap_header))) == -1) {
      perror("read");
      return 1;
    }
  }

  if(! context.capture_len) {
    fprintf(stderr, "Error: empty capture file\n");
    return 1;
  }

  return init_index();
}

int init_index() {
  int len, i = 0, index = sizeof(pcap_hdr_t);
  pcaprec_hdr_t header;
  if(!(context.index = malloc(sizeof(uint32_t) * context.capture_len))) {
    perror("malloc");
    return 1;
  }

  lseek(context.fd, sizeof(pcap_hdr_t), SEEK_SET);

  if((len = read(context.fd, &header, sizeof(header))) == -1) {
    perror("read");
    return 1;
  }

  while(len == sizeof(header)) {

    context.index[i++] = index;
    index += header.incl_len + sizeof(header);

    lseek(context.fd, header.incl_len, SEEK_CUR);
    if((len = read(context.fd, &header, sizeof(header))) == -1) {
      perror("read");
      return 1;
    }
  }
  return 0;
}

void close_pcap_file() {
  free(context.index);
  free_capture_set(&(context.capture_start));
  freeRule(context.filter);
  close(context.fd);
}

void free_capture_set(capture_t** capture) {
  capture_t* tmp;
  while(*capture) {
    tmp = *capture;
    *capture = (*capture)->next;
    free(tmp);
  }
}

int add_to_capture_set(capture_t** set, capture_t* previous, uint32_t index, struct rule_node* rule) {
  int len;
  char buff[MAX_CAP_LEN];
  pcaprec_hdr_t header;
  struct packet_layers layers;
  capture_t capture, *nnode;

  // move to correct index
  lseek(context.fd, context.index[index], SEEK_SET);

  // read header
  if((len = read(context.fd, &header, sizeof(header))) == -1) {
    perror("read");
    return -1;
  }

  if(len < sizeof(header)) return -1; // EOF

  // read/pass capture content
  if(sizeof(buff) < header.incl_len) {
    fprintf(stderr, "Packet size(%u) exceed buffer size(%lu)\r\n", header.incl_len, sizeof(buff));
  } else {
    if((len = read(context.fd, buff, header.incl_len)) == -1) {
      perror("read");
      return 1;
    }
    if(len < header.incl_len) return -1;

    // parsing
    memset(&layers, 0, sizeof(layers));
    memset(&capture, 0, sizeof(capture));

    capture.len = len;
    capture.index = index;

    struct ethernet_header* ether_p = (struct ethernet_header*) buff;
    if(len < sizeof(struct ethernet_header)) return 0;
    layers.ether_src = ether_p->ether_shost;
    layers.ether_dst = ether_p->ether_dhost;
    layers.ether_type = (uint8_t*)&(ether_p->ether_type);
    memcpy(&(capture.ether_dst), buff, 12);
    capture.ether_type = ntohs(ether_p->ether_type);
    switch(ether_p->ether_type) {
      case 0x0608: // arp
        {
          struct arp_header* arp_p = (struct arp_header*)(buff + sizeof(struct ethernet_header));
          if(len < sizeof(struct ethernet_header) + sizeof(struct arp_header)) return 0;
          layers.ip_src = arp_p->ip_src;
          layers.ip_dst = arp_p->ip_target;
          *((uint32_t*)capture.ip_src) = *((uint32_t*)arp_p->ip_src);
          *((uint32_t*)capture.ip_dst) = *((uint32_t*)arp_p->ip_target);
          capture.protocol = ((uint8_t*)&(arp_p->operation))[1]; // reply or request
        }
        break;
      case 0x0008: // ip
        {
          struct ip_header* ip_p = (struct ip_header*)(buff + sizeof(struct ethernet_header));
          if(len < sizeof(struct ethernet_header) + sizeof(struct ip_header)) return 0;
          layers.ip_src = ip_p->source_address;
          layers.ip_dst = ip_p->destination_address;
          layers.protocol = &(ip_p->protocol);
          memcpy(&(capture.ip_src), &(ip_p->source_address), 8);
          capture.protocol = ip_p->protocol;
          if(ip_p->protocol == 6 || ip_p->protocol == 17) { // udp or ip
            uint32_t header_len = ip_p->IHL * 4;
            if(len < sizeof(struct ethernet_header) + header_len + 4) return 0;
            layers.port_src = (uint8_t*)buff + sizeof(struct ethernet_header) + header_len;
            layers.port_dst = (uint8_t*)buff + sizeof(struct ethernet_header) + header_len + 2;
            capture.port_src = ntohs(*((uint16_t*)layers.port_src));
            capture.port_dst = ntohs(*((uint16_t*)layers.port_dst));
          }
        }
    }

    // apply filter & record new capture if success
    if(rule == NULL || applyRule(rule, &layers)) {
      if(!(nnode = malloc(sizeof(capture)))) {
        perror("malloc");
        return -1;
      }
      memcpy(nnode, &capture, sizeof(capture));

      // set up links
      nnode->next = *set;
      if(*set) (*set)->previous = nnode;
      nnode->previous = previous;
      *set = nnode;

      context.filtered_len += 1; // account packet

      return 1;
    }
  }

  return 0;
}

void init_capture_set(uint16_t size, struct rule_node* rule) {
  int ret;
  uint32_t i = 0, index = 0;
  capture_t* previous = NULL;
  free_capture_set(&(context.capture_start)); // free previous set

  context.filtered_len = 0; // reset account

  // fill first set
  capture_t** current = &(context.capture_start);
  while(i < size) {
    if((ret = add_to_capture_set(current, previous, index, rule)) == -1) break;
    if(ret) {
      i++;
      previous = *current;
      context.max_index = (*current)->index;
      current = &((*current)->next);
    }
    index += 1;
  }
  context.capture_current = context.capture_start;
  freeRule(context.filter); // free previous rule
  context.filter = rule;
}

uint32_t complete_capture_set(uint16_t size) {
  int ret;
  if(!context.capture_current) return 0;
  context.max_index = context.capture_current->index;
  uint32_t index = context.capture_current->index + 1, count = 1;
  capture_t** current = &(context.capture_current->next), *previous = context.capture_current;
  while(*current && count < size) {
    index = (*current)->index + 1;
    previous = *current;
    context.max_index = (*current)->index;
    current = &((*current)->next);
    count += 1;
  }
  while(count < size) {
    if((ret = add_to_capture_set(current, previous, index, context.filter)) == -1) break;
    if(ret) {
      count += 1;
      previous = *current;
      context.max_index = (*current)->index;
      current = &((*current)->next);
    }
    index += 1;
  }
  return count;
}

void move_capture_set_index(int8_t shift, uint16_t size) {
  int32_t i;

  if(!context.capture_current) return;

  if(shift < 0) {
    for(i = shift; i < 0 && context.capture_current->previous; i ++) context.capture_current = context.capture_current->previous;
    // compute max index
    capture_t* current = context.capture_current;
    uint32_t count = 0;
    while(current && count < size) {
      context.max_index = current->index;
      current = current->next;
      count ++;
    }
  } else if(shift > 0) {
    int ret;
    uint32_t count = 0, index = context.capture_current->index + 1;
    capture_t* previous = context.capture_current;
    capture_t** current = &(context.capture_current->next);
    while(*current && count < shift) { // count already recorded captures
      previous = *current;
      index = (*current)->index + 1;
      current = &((*current)->next);
      count += 1;
    }
    while(count < shift) {
      if((ret = add_to_capture_set(current, previous, index, context.filter)) == -1) break;
      if(ret) {
        count += 1;
        previous = *current;
        current = &((*current)->next);
      }
      index += 1;
    }
    context.capture_current = previous;
    count = complete_capture_set(size);
    for(i = count; i < size && context.capture_current->previous; i ++) { // index backwards if not enough packets
      context.capture_current = context.capture_current->previous;
    }
  }
}
