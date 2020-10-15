#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <math.h>
#include <unistd.h>

#include <format.h>

#include "includes/dissect.h"
#include "includes/display.h"
#include "includes/parse.h"

static struct dissect_state state;
extern screen_context_t win_state;
extern struct parse_context context;

void print_dissect(char* format, ...) {
  if(state.current >= state.cursor && state.current < state.cursor + win_state.winsize.ws_row - 2) {
    va_list args;
    va_start(args, format);
    draw_line_varg(0, format, args);
    va_end(args);
  }
  state.current ++;
}

void print_dissect_header(char* format, ...) {
  if(state.current >= state.cursor && state.current < state.cursor + win_state.winsize.ws_row - 2) {
    va_list args;
    va_start(args, format);
    draw_line_varg(DISP_CENTER | DISP_NEGATIVE, format, args);
    va_end(args);
  }
  state.current ++;
}

int parse_capture(capture_t* capture) {
  pcaprec_hdr_t header;
  lseek(context.fd, context.index[capture->index], SEEK_SET);

  if(read(context.fd, &header, sizeof(header)) != sizeof(header)) {
    write(1, "\x1b[18Dcapture header err", 23);
    return 1;
  }

  if(!(state.buff = malloc(header.incl_len))) {
    write(1, "\x1b[10Dmalloc err", 15);
    return 1;
  }

  if(read(context.fd, state.buff, header.incl_len) != header.incl_len) {
    free(state.buff);
    write(1, "\x1b[16Dread capture err", 21);
    return 1;
  }

  state.buff_len = header.incl_len;
  state.cursor = 0; // Init display cursor
  state.current = 0;

  return 0;
}

void display_packet_summary() {
  state.current = 0;
  dissect_ethernet(state.buff, state.buff_len);
  uint32_t i = state.current;
  while(i < state.cursor + win_state.winsize.ws_row - 2) {
      write(1, "\x1b[K\r\n", 5);
      i ++;
  }
}

void free_capture() {
  free(state.buff);
  state.buff_len = 0;
}

void move_summary_cursor(int16_t shift) {
  int32_t new = state.cursor + shift, last = (int32_t)state.current - (int32_t)win_state.winsize.ws_row + (int32_t)2;
  last = (last < 0 ? 0 : last);
  if(new < 0) state.cursor = 0;
  else if(new > last) state.cursor = last;
  else state.cursor = (uint32_t)new;
  display_scene();
}

/* L2 */

void dissect_ethernet(char* buff, unsigned int size) {
  struct ethernet_header* frame = (struct ethernet_header*)buff;

  if(size < sizeof(struct ethernet_header)) {
    print_dissect("Ethernet: Truncated header");
    return;
  }
  unsigned int size_payload = size - sizeof(struct ethernet_header);
  uint16_t ether_type = ntohs(frame->ether_type);

  print_dissect("\x1b[7mL2\x1b[m Ethernet, payload size %u bytes", size_payload);
  print_dissect("   Source:      %x:%x:%x:%x:%x:%x",
    frame->ether_shost[0], frame->ether_shost[1], frame->ether_shost[2], frame->ether_shost[3], frame->ether_shost[4], frame->ether_shost[5]);
  print_dissect("   Destination: %x:%x:%x:%x:%x:%x",
    frame->ether_dhost[0], frame->ether_dhost[1], frame->ether_dhost[2], frame->ether_dhost[3], frame->ether_dhost[4], frame->ether_dhost[5]);
  if(ether_type > 1536) {
    switch(ether_type) {
        case 0x800:
          dissect_ipv4(buff + sizeof(struct ethernet_header), size_payload);
          break;
        case 0x806:
          dissect_arp(buff + sizeof(struct ethernet_header), size_payload);
          break;
        default:
          print_dissect("   Unsupported ethertype 0x%x", ether_type);
      }
  } else {
    print_dissect("   \x1b[7mtype: Ethernet IEEE 802.3 (parsing not implemented)\x1b[0m");
  }
}

/* L3 */

void dissect_arp(char* buff, unsigned int size) {
  struct arp_header* arp_p = (struct arp_header*)buff;
  if(size < sizeof(struct arp_header)) {
    print_dissect("ARP: Truncated header");
    return;
  }

  print_dissect("\x1b[7mL3\x1b[m ARP %s", (arp_p->operation == 512 ? "is-at" : "who-has"));
  print_dissect("   Source IP:  %u.%u.%u.%u", arp_p->ip_src[0], arp_p->ip_src[1], arp_p->ip_src[2], arp_p->ip_src[3]);
  print_dissect("   Source MAC: %x:%x:%x:%x:%x:%x", arp_p->MAC_src[0], arp_p->MAC_src[1], arp_p->MAC_src[2], arp_p->MAC_src[3], arp_p->MAC_src[4], arp_p->MAC_src[5]);
  print_dissect("   Target IP:  %u.%u.%u.%u", arp_p->ip_target[0], arp_p->ip_target[1], arp_p->ip_target[2], arp_p->ip_target[3]);
  print_dissect("   Target MAC: %x:%x:%x:%x:%x:%x", arp_p->MAC_target[0], arp_p->MAC_target[1], arp_p->MAC_target[2], arp_p->MAC_target[3], arp_p->MAC_target[4], arp_p->MAC_target[5]);
}

void dissect_ipv4(char* buff, unsigned int size) {
  struct ip_header* header = (struct ip_header*)buff;
  if(size < sizeof(struct ip_header)) {
    print_dissect("Ipv4: Truncated header");
    return;
  }

  unsigned int header_size = header->IHL * 4;
  if(header_size < 20) {
    print_dissect("IPv4: invalid header size");
    return;
  }
  unsigned short int total_length = ntohs(header->total_length);
  unsigned short int fragment_offset = header->fragment_offset_1 + 256 * header->fragment_offset_2;
  char* header_end = buff + header_size;

  // Get hostnames
  struct hostent *hp_src, *hp_dst;
  hp_src = gethostbyaddr((void*)header->source_address, 4, AF_INET);
  hp_dst = gethostbyaddr((void*)header->destination_address, 4, AF_INET);
  char host_src[NI_MAXHOST + 16], host_dst[NI_MAXHOST + 16];
  if(hp_src) sprintf(host_src, " [\033[31m%s\033[0m]", hp_src->h_name);
  else host_src[0] = 0;
  if(hp_dst) sprintf(host_dst, " [\033[31m%s\033[0m]", hp_dst->h_name);
  else host_dst[0] = 0;

  print_dissect("\x1b[7mL3\x1b[m IPv4, header size %u bytes, payload size %u bytes", header_size, total_length - header_size);
  print_dissect("   Source:      %u.%u.%u.%u%s", header->source_address[0], header->source_address[1], header->source_address[2], header->source_address[3], host_src);
  print_dissect("   Destination: %u.%u.%u.%u%s", header->destination_address[0], header->destination_address[1], header->destination_address[2], header->destination_address[3], host_dst);
  print_dissect("   Fragmented: %s", (header->MF || fragment_offset) ? "yes" : "no");

  // Print options
  if(header_size > sizeof(struct ip_header)) {
    print_dissect("   Options:");
    unsigned char* byte = (unsigned char*)header + sizeof(struct ip_header);
    while((char*)byte < header_end) {
      struct ip_option_type* type = (struct ip_option_type*)byte;
      print_dissect("     | %s[number %u, class %u, copie %u]", getIpOptionName(*byte), type->number, type->class, type->copie);
      if(*byte <= 1) byte += 1;
      else {
        if((char*)byte + 1 >= header_end) {
          print_dissect("     >< Truncated option");
          break;
        }
        unsigned char length = *(byte + 1);
        if(length < 2) {
          print_dissect("     >< Options length < 2");
          length = 2;
        }
        byte += length;
      }
    }
  }

  if(size < total_length) {
    print_dissect("   >< Truncated IP payload (got %u of %u bytes)", size, total_length);
    total_length = size;
  }

  // build session tracker
  switch(header->protocol) {
    case 1:
      dissect_icmp(header_end, total_length - header_size);
      break;
    case 6:
      dissect_tcp(header_end, total_length - header_size);
      break;
    case 17:
      dissect_udp(header_end, total_length - header_size);
      break;
    default: print_dissect("   Protocol: 0x%x (unsupported)", header->protocol);
  }
}

/* L4 dissection */
void dissect_tcp(char* buff, unsigned int size) {
  struct tcp_header* header = (struct tcp_header*) buff;
  if(size < sizeof(struct tcp_header)) {
    print_dissect("TCP: invalid header size");
    return;
  }

  unsigned int header_size = header->data_offset * 4;
  if(header_size < 20 || size < header_size) {
    print_dissect("TCP: invalid header size");
    return;
  }
  char* header_end = buff + header_size;
  unsigned int payload_size = size - header_size;

  uint16_t port_src = ntohs(header->src_port), port_dst = ntohs(header->dst_port);

  struct servent* port_src_name = getservbyport(header->src_port, NULL);
  struct servent* port_dst_name = getservbyport(header->dst_port, NULL);

  print_dissect("\x1b[7mL4\x1b[m TCP, header size %u, payload size %u", header_size, payload_size);
  if(!port_src_name) print_dissect("   Source:      %hu", port_src);
  else print_dissect("   Source:      %hu [\033[31m%s\033[0m]", port_src, port_src_name->s_name);

  if(!port_dst_name) print_dissect("   Destination: %hu", port_dst);
  else print_dissect("   Destination: %hu [\033[31m%s\033[0m]", port_dst, port_dst_name->s_name);

  // Print flags
  if(header->flags || header->NS) {
    print_dissect("   Flags:");
    if(header->FIN) print_dissect("    | FIN");
    if(header->SYN) print_dissect("    | SYN");
    if(header->RST) print_dissect("    | RST");
    if(header->PSH) print_dissect("    | PSH");
    if(header->ACK) print_dissect("    | ACK");
    if(header->URG) print_dissect("    | URG");
    if(header->ECE) print_dissect("    | ECE");
    if(header->CWR) print_dissect("    | CWR");
    if(header->NS) print_dissect("    | NS");
  }

  // Printf seq & ack
  uint32_t seq_number = ntohl(header->seq_number);
  uint32_t next_seq_number;
  if(header->SYN) next_seq_number = seq_number + 1;
  else next_seq_number = seq_number + payload_size;

  print_dissect("   Seq:      %u", seq_number);
  if(payload_size)
    print_dissect("   Next seq: %u", next_seq_number);
  if(header->ACK)
    print_dissect("   Ack:      %u", ntohl(header->ack_number));

  // Print options
  if(header_size > 20) {
    print_dissect("   Options:");
    unsigned char* byte = (unsigned char*)buff + sizeof(struct tcp_header);
    int i = 0;
    while((char*)byte < header_end) {

      if(*byte <= 1) {
        byte += 1;
        continue;
      }

      print_dissect("    | %s[%u]", getTcpOptionName(*byte), *byte);
      i ++;
      if((char*)byte + 1 >= header_end) {
        print_dissect("    >< Truncated option");
        break;
      }
      byte += *(byte + 1);
    }
  }

  if(payload_size) {
    if(port_src == 80 || port_dst == 80) dissect_ascii(header_end, payload_size);
    /*if(port_src == 443 || port_dst == 443) {
      return dissect_tls(header_end, payload_size, output);
    }*/
    else dissect_hexa_dump(header_end, payload_size);
  }
}

void dissect_udp(char* buff, unsigned int size) {
  struct udp_header* header = (struct udp_header*)buff;
  if(size < sizeof(struct udp_header)) {
    print_dissect("UDP: invalid header size");
    return;
  }

  unsigned short int port_src = ntohs(header->src_port), port_dst = ntohs(header->dst_port), length = ntohs(header->length);
  unsigned short int payload_size = length - sizeof(struct udp_header);

  struct servent* port_src_name = getservbyport(header->src_port, NULL);
  struct servent* port_dst_name = getservbyport(header->dst_port, NULL);

  print_dissect("\x1b[7mL4\x1b[m UDP, header size %lu bytes, payload size %u bytes", sizeof(struct udp_header), payload_size);
  if(!port_src_name) print_dissect("   Source:      %hu", port_src);
  else print_dissect("   Source:      %hu [\033[31m%s\033[0m]", port_src, port_src_name->s_name);
  if(!port_dst_name) print_dissect("   Destination: %hu", port_dst);
  else print_dissect("   Destination: %hu [\033[31m%s\033[0m]", port_dst, port_dst_name->s_name);

  if(size < length) {
    print_dissect("   Truncated UDP payload (got %u of %u bytes)", size - (unsigned int)sizeof(struct udp_header), payload_size);
    payload_size = size - sizeof(struct udp_header);
  }

  if(port_src == 53 || port_dst == 53) dissect_dns(buff + sizeof(struct udp_header), payload_size);
  else if (payload_size) dissect_hexa_dump(buff + sizeof(struct udp_header), payload_size);
}

void dissect_icmp(char* buff, unsigned int size) {
  struct icmp_header* header = (struct icmp_header*) buff;
  if(size < sizeof(struct icmp_header)) {
    print_dissect("ICMP: invalid header size");
    return;
  }

  uint32_t payload_size = size - sizeof(struct icmp_header);

  switch(header->type) {
    case 0:
      print_dissect("\x1b[7mL4\x1b[m ICMP echo reply, header %lu bytes, payload %u bytes", sizeof(struct icmp_header), payload_size);
      break;
    case 8:
      print_dissect("\x1b[7mL4\x1b[m ICMP echo request, header %lu bytes, payload %u bytes", sizeof(struct icmp_header), payload_size);
      break;
    default:
      print_dissect("\x1b[7mL4\x1b[m ICMP, header %lu bytes, payload %u bytes", sizeof(struct icmp_header), payload_size);
      print_dissect("   type %u, code[%u]", header->type, header->code);
  }
}

/* DNS dissection */
void dissect_dns(char* buff, unsigned int size) {
  struct dns_header* header = (struct dns_header*) buff;
  if(size < sizeof(struct dns_header)) {
    print_dissect("DNS: invalid header size");
    return;
  }

  print_dissect("\x1b[7mL7\x1b[m DNS %s, size %u", ((header->QR == 1) ? "response" : "query"), size);
  print_dissect("   Id: %hu", ntohs(header->identification));

  char* head = buff + sizeof(struct dns_header);
  char* end = buff + size;
  unsigned short qry_count = ntohs(header->question_count), rsp_count = ntohs(header->answer_count), auth_count = ntohs(header->authority_count), add_count = ntohs(header->Additional_count);
  unsigned int i;
  if(qry_count) print_dissect("   Question:");
  for(i = 0; i < qry_count; i ++) {
    if((head = printfDNSQuestion(buff, head, end, NULL)) == NULL) return;
  }
  if(rsp_count) print_dissect("   Response:");
  for(i = 0; i < rsp_count; i ++) {
    if((head = printfDNSResponse(buff, head, end)) == NULL) return;
  }
  if(auth_count) print_dissect("   Authority:");
  for(i = 0; i < auth_count; i ++) {
    if((head = printfDNSResponse(buff, head, end)) == NULL) return;
  }
  if(add_count) print_dissect("   Addtional:");
  for(i = 0; i < add_count; i ++) {
    if((head = printfDNSResponse(buff, head, end)) == NULL) return;
  }

}

char* printfDNSQuestion(char* buff, char* head, char* end, struct dns_record* ret) {
  char* name;
  if(!(name = malloc(win_state.winsize.ws_col + 1))) {
    perror("malloc");
    return NULL;
  }
  if((head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1)) == NULL) {
    free(name);
    return NULL;
  }

  if(head + 4 > end) {
    print_dissect("     >< Truncated DNS payload[DNS Qestion type & class]");
    free(name);
    return NULL;
  }
  uint16_t rtype = ntohs(*((uint16_t*)head));
  head += 2;
  uint16_t rclass = ntohs(*((uint16_t*)head));
  head += 2;

  if(ret) {
    ret->type = rtype;
    ret->class = rclass;
  }

  char* type_name = getDNSTypeName(rtype);
  if(type_name) {
    print_dissect("    | %s - type %s, class %s", name, type_name, (rclass == 1 ? "[IN]" : rclass == 255 ? "[*]" : "unknown"));
  } else {
    print_dissect("    | %s - type %u, class %s", name, rtype, (rclass == 1 ? "[IN]" : rclass == 255 ? "[*]" : "unknown"));
  }

  free(name);

  return head;
}

char* printfDNSName(char* buff, char* head, char* end, char* copy, uint32_t size) {

  int len;

  if(head >= end) {
    print_dissect("    >< Truncated DNS payload[length of DNS name]");
    return NULL;
  }
  unsigned char length = *((unsigned char*)head++);

  while(length) {
    if(length >= 0b11000000) { // then offset used for compression
      if(head >= end) {
        print_dissect("    >< Truncated DNS payload[offset of DNS NAME]");
        return NULL;
      }
      unsigned short int offset = ntohs(*((unsigned short int*)(head - 1))) & 0x3fff;
      if(printfDNSName(buff, buff + offset, end, copy, size) == NULL) return NULL;
      return (head + 1);
    } else { // Real list of names
      if(head + length >= end) {
        print_dissect("    >< Truncated DNS payload[DNS name]");
        return NULL;
      }
      len = snprintf(copy, size, "%.*s.", length, head);
      if(len >= size) {
        size = 0;
      } else {
        size -= len;
        copy = copy + len;
      }
      head += length;
      length = *((unsigned char*)head++);
    }
  }

  return head;
}

char* printfCharacterString(char* head, char* end, char* buff, uint32_t size) {
  if(head >= end) {
    print_dissect("    >< Truncated DNS payload[length of character string]");
    return NULL;
  }
  unsigned char length = *((unsigned char*)head++);
  if(head + length > end) {
    print_dissect("    >< Truncated DNS payload[start of character string]");
    return NULL;
  }
  snprintf(buff, size, "%.*s.", length, head);
  head += length;
  return head;
}

char* printfDNSResponse(char* buff, char* head, char* end) {

  char* name;
  struct dns_record record;
  if((head = printfDNSQuestion(buff, head, end, &record)) == NULL) return NULL;

  if(head + 6 > end) {
    print_dissect("    >< Truncated DNS payload[DNS response ttl & rlength]");
    return NULL;
  }
  uint32_t ttl = ntohl(*((uint32_t*)head));
  head += 4;
  uint16_t rlength = ntohs(*((uint16_t*)head));
  head += 2;

  char* rend = head + rlength;
  if(record.class == 1) { // IN

    if(!(name = malloc(win_state.winsize.ws_col + 1))) {
      perror("malloc");
      return NULL;
    }
    name[0] = 0;

    switch(record.type) {
      case 12: // PTR
        head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1);
        print_dissect("      -> PTR: %s", name);
        break;
      case 2: // NS
        head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1);
        print_dissect("      -> NS: %s", name);
        break;
      case 5: // CNAME
        head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1);
        print_dissect("      -> CNAME: %s", name);
        break;
      case 13: // HINFO
        if((head = printfCharacterString(head, end, name, win_state.winsize.ws_col + 1)) == NULL) {
          free(name);
          return NULL;
        }
        print_dissect("      -> CPU: %s", name);
        head = printfCharacterString(head, end, name, win_state.winsize.ws_col + 1);
        print_dissect("      -> OS: %s", name);
        break;
      case 15: // MX
        {
          if(head + 2 > end) {
            print_dissect("    >< Truncated DNS payload[MX record preference]");
            free(name);
            return NULL;
          }
          uint16_t preference = ntohs(*((uint16_t*)head));
          head += 2;
          head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1);
          print_dissect("      -> MX: %s [preference: %u]", name, preference);
        }
        break;
      case 6: // SOA
        {
          if((head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1)) == NULL) {
            free(name);
            return NULL;
          }
          print_dissect("      -> MNAME: %s", name);
          if((head = printfDNSName(buff, head, end, name, win_state.winsize.ws_col + 1)) == NULL) {
            free(name);
            return NULL;
          }
          print_dissect("      -> RNAME: %s", name);
          if(head + 20 > end) {
            print_dissect("     >< Truncated DNS payload[SOA record serial]");
            free(name);
            return NULL;
          }
          uint32_t serial = ntohl(*((uint32_t*)head));
          uint32_t refresh = ntohl(*(((uint32_t*)head) + 1));
          uint32_t retry = ntohl(*(((uint32_t*)head) + 2));
          uint32_t expire = ntohl(*(((uint32_t*)head) + 3));
          uint32_t min = ntohl(*(((uint32_t*)head) + 4));
          print_dissect("      -> Serial:  %u", serial);
          print_dissect("      -> Refresh: %u", refresh);
          print_dissect("      -> Retry:   %u", retry);
          print_dissect("      -> Expire:  %u", expire);
          print_dissect("      -> Minimum: %u", min);
          head += 20;
        }
        break;
      case 16: // TXT
        while(head < rend) {
          if((head = printfCharacterString(head, end, name, win_state.winsize.ws_col + 1)) == NULL) {
            free(name);
            return NULL;
          }
          print_dissect("      -> TXT: %s", name);
        }
        break;
      case 1: // A
        if(head + 4 > end) {
          print_dissect("     >< Truncated DNS payload[A record]");
          free(name);
          return NULL;
        }
        uint8_t* addr = (uint8_t*)head;
        print_dissect("      -> A: %u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
        head += 4;
        break;
      default:
        print_dissect("     Inspection not implemented");
    }
    free(name);
  }
  return head;
}

void convert_to_printable(char* c) {
  if(*c < 32 || *c > 126) *c = '?';
}

void dissect_ascii(char* buff, unsigned int size) {
  uint32_t current_size;
  char* limit = buff + size, *current;

  print_dissect_header("Application layer data, size %u bytes", size);

  while(buff < limit) {
    current = buff;
    for(current_size = 0; current_size < win_state.winsize.ws_col && current < limit; current_size ++) {
      if(current[0] == '\n') {
        current += 1;
        break;
      } else convert_to_printable(current);
      current += 1;
    }
    if(current_size) {
      print_dissect("%.*s", current_size, buff);
    }
    buff = current;
  }
}

void fill_buff(char** buff, uint32_t* len, char* format, ...) {
  uint32_t cpy_len;
  va_list args;
  va_start(args, format);
  cpy_len = vsnprintf(*buff, *len, format, args);
  if(cpy_len >= *len) {
    *len = 0;
  } else {
    *len -= cpy_len;
    *buff += cpy_len;
  }
  va_end(args);
}

void dissect_hexa_dump(char* buff, unsigned int size) {
  uint32_t row_size = (uint32_t)((float)(win_state.winsize.ws_col - 9) / 13.0) * 4;
  uint32_t current_len;
  int len;
  char* row, *current;
  if(!(row = malloc(win_state.winsize.ws_col + 8))) return;

  print_dissect_header("Application layer hexa dump (big-endian), size %u(0x%x) bytes", size, size);
  uint32_t i, j = 0, nb_rows = ceil((float)size / (float)row_size);
  for(i = 0; i < nb_rows; i ++) {

    current = row;
    current_len = win_state.winsize.ws_col + 8;

    fill_buff(&current, &current_len, "\x1b[7m%.4x |\x1b[m", i * row_size);

    // print hexa
    for(j = 0; j < row_size; j ++) {
      if(j % 4 == 0) fill_buff(&current, &current_len, " ");
      if(i*row_size + j < size)
        fill_buff(&current, &current_len, "%.2x", (uint8_t)(buff[i*row_size + j]));
      else fill_buff(&current, &current_len, "  ");
    }

    // print ascii
    fill_buff(&current, &current_len, "   ");
    for(j = 0; j < MIN(row_size, (size - i*row_size)); j ++) {
      uint8_t c = (uint8_t)(buff[i*row_size + j]);
      if(c > 31 && c < 127) fill_buff(&current, &current_len, "%c", c);
      else fill_buff(&current, &current_len, ".");
    }

    print_dissect("%s", row);

  }
  free(row);
}

/* Type to string conversion */

char* getIpOptionName(unsigned char type) {
  switch(type) {
    case 0:
      return "End of Options List";
    case 1:
      return "No Operation";
    case 130:
      return "Security";
    case 131:
      return "Loose Source Route";
    case 68:
      return "Time Stamp";
    case 133:
      return "Extended Security";
    case 134:
      return "Commercial Security";
    case 7:
      return "Record Route";
    case 136:
      return "Stream ID";
    case 137:
      return "Strict Source Route";
    case 10:
      return "Experimental Measurement";
    case 11:
      return "MTU Probe";
    case 12:
      return "MTU Reply";
    case 205:
      return "Experimental Flow Control";
    case 142:
      return "Experimental Access Control";
    case 15:
      return "ENCODE";
    case 144:
      return "IMI Traffic Descriptor";
    case 145:
      return "Extended Internet Protocol";
    case 82:
      return "Traceroute";
    case 147:
      return "Address Extension";
    case 148:
      return "Router Alert";
    case 149:
      return "Selective Directed Broadcast";
    case 151:
      return "Dynamic Packet State";
    case 152:
      return "Upstream Multicast Pkt.";
    case 25:
      return "Quick-Start";
    default:
      return "";
  }
}

char* getTcpOptionName(unsigned char type) {
  switch(type) {
    case 0:
      return "End of options list";
    case 1:
      return "No operation";
    case 2:
      return "Maximum segment size";
    case 3:
      return "Window scale";
    case 4:
      return "Selective Acknowledgement permitted";
    case 5:
      return "Selective ACKnowledgement (SACK)";
    case 8:
      return "TCP Timestamp";
    default:
      return "Unknown option";
  }
}

char* getDNSTypeName(unsigned short int type) {
  switch(type) {
    case 1: return "A";
    case 2: return "NS";
    case 3: return "MD";
    case 4: return "MF";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 7: return "MB";
    case 8: return "MG";
    case 9: return "MR";
    case 10: return "NULL";
    case 11: return "WKS";
    case 12: return "PTR";
    case 13: return "HINFO";
    case 14: return "MINFO";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 242: return "AXFR";
    case 253: return "MAILB";
    case 254: return "MAILA";
    case 255: return "*";
  }
  return "";
}
