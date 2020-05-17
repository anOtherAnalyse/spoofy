#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <receive.h>
#include <filter.h>

static int raw_socket;
unsigned int capture_count = 0;

int init_capture_fd(char* if_name) {

  if((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    perror("socket ");
    return 1;
  }

  struct ifreq if_req;
  strncpy(if_req.ifr_name, if_name, IFNAMSIZ);
  if_req.ifr_name[IFNAMSIZ - 1] = 0;
  if(ioctl(raw_socket, SIOCGIFINDEX, &if_req) == -1) {
    perror("ioctl SIOCGIFINDEX ");
    return 1;
  }

  struct sockaddr_ll sa;
  sa.sll_family = PF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = if_req.ifr_ifindex;
  if(bind(raw_socket, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
    perror("bind ");
    return 1;
  }

  // set promiscuous mode
  struct packet_mreq mreq = {
    .mr_ifindex =  if_req.ifr_ifindex,
    .mr_type = PACKET_MR_PROMISC,
  };
  if(setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(struct packet_mreq)) == -1) {
    perror("setsockopt");
    return 1;
  }

  return 0;
}

int capture(capture_callback_t cb, void* cb_args) {
  char* buff;
  int length;
  struct sockaddr_ll addr;
  struct capture_auxdata_t auxdata;
  socklen_t addr_len;

  if(!(buff = malloc(RECV_BUF_LEN))) {
    perror("malloc ");
    return 1;
  }

  // refresh statistics
  struct tpacket_stats stats;
  socklen_t stats_length = sizeof(struct tpacket_stats);
  if(getsockopt(raw_socket, SOL_PACKET, PACKET_STATISTICS, &stats, &stats_length) == -1) {
    perror("getsockopt");
  }

  capture_count = 0; // reset capture count

  // capture loop
  while(1) {

    // Receive packet
    addr_len = sizeof(struct sockaddr_ll);
    if((length = recvfrom(raw_socket, buff, RECV_BUF_LEN, MSG_TRUNC, (struct sockaddr*)&addr, &addr_len)) < 0) {
      perror("recv");
      return 1;
    }

    // call callback only if incoming packet
    if(addr.sll_pkttype != PACKET_OUTGOING) {
      auxdata.real_len = length; // packet real length

      if(length > RECV_BUF_LEN) {
        fprintf(stderr, "Capture: truncated frame, got %u of %u bytes\n", RECV_BUF_LEN, length);
        length = RECV_BUF_LEN;
      }

      auxdata.cap_len = length; // packet capture length

      if(ioctl(raw_socket, SIOCGSTAMP, &(auxdata.time)) == -1) {
        perror("ioctl SIOCGSTAMP");
        continue;
      }

      if(cb(buff, &auxdata, cb_args)) break;
    }

  }

  return 0;
}

int apply_identifier_filter(uint32_t ip_1, uint32_t ip_2) {
  struct sock_filter filter_rule[] = { // filter = arp from ip_1 or from ip_2
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x806, 0, 4),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 28),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(ip_1), 1, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(ip_2), 0, 1),
    BPF_STMT(BPF_RET+BPF_K, (uint32_t)-1),
    BPF_STMT(BPF_RET+BPF_K, 0)
  };
  struct sock_fprog filter = {
    .len = 7,
    .filter = filter_rule
  };
  if(setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) {
    perror("setsockopt");
    return 1;
  }
  return 0;
}

int apply_ping_filter(uint32_t ip_1, uint32_t ip_2) {
  struct sock_filter filter_rule[] = {
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 9),
    BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 0, 7),
    BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
    BPF_STMT(BPF_LD+BPF_H+BPF_IND, 18),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xefbe, 0, 4),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(ip_1), 1, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(ip_2), 0, 1),
    BPF_STMT(BPF_RET+BPF_K, (uint32_t)-1),
    BPF_STMT(BPF_RET+BPF_K, 0)
  };
  struct sock_fprog filter = {
    .len = 12,
    .filter = filter_rule
  };
  if(setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1) {
    perror("setsockopt");
    return 1;
  }
  return 0;
}

int create_filter(struct rule_node* rule, struct sock_filter* result) {
  int length = 0, negation = (rule->type & NEGATION_TERM);
  uint32_t offset = 0;
  switch(rule->type & 0x7f) {
    case ETHER_ADDR_SRC_TOK:
      offset += 6;
    case ETHER_ADDR_DST_TOK:
      if(result) {
        struct sock_filter tmp[] = {
          BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(((uint32_t*)(rule->value))[0]), 0, negation ? 3 : 2),
          BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset + 4),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(((uint16_t*)(rule->value))[2]), (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 4 * sizeof(struct sock_filter));
      }
      length += 4;
      break;
    case ETHER_TYPE_TOK:
      if((*((uint16_t*)rule->value) == 0x8) && !negation) { // it's ip then
        if(result) {
          struct sock_filter tmp[] = {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 2),
            BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
            BPF_STMT(BPF_JMP+BPF_JA, 1)
          };
          memcpy(result, tmp, 4 * sizeof(struct sock_filter));
        }
        length += 4;
      } else {
        if(result) {
          struct sock_filter tmp[] = {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(*((uint16_t*)rule->value)), (negation == 0), (negation != 0))
          };
          memcpy(result, tmp, 2 * sizeof(struct sock_filter));
        }
        length += 2;
      }
      break;
    case IP_ADDR_DST_TOK:
      offset += 4;
    case IP_ADDR_SRC_TOK:
      offset += 26;
      if(result) {
        struct sock_filter tmp[] = {
          BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(*((uint32_t*)(rule->value))), (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 2 * sizeof(struct sock_filter));
      }
      length += 2;
      break;
    case PROTOCOL_TOK:
      if(result) {
        struct sock_filter tmp[] = {
          BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, rule->value[0], (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 2 * sizeof(struct sock_filter));
      }
      length += 2;
      break;
    case PORT_DST_TOK:
      offset += 2;
    case PORT_SRC_TOK:
      offset += 14;
      if(result) {
        struct sock_filter tmp[] = {
          BPF_STMT(BPF_LD+BPF_H+BPF_IND, offset),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(*((uint16_t*)(rule->value))), (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 2 * sizeof(struct sock_filter));
      }
      length += 2;
  }

  if(rule->child) {
    int child_length = create_filter(rule->child, (result == NULL ? NULL : result + length + 1));
    if(result) {
      struct sock_filter tmp = BPF_STMT(BPF_JMP+BPF_JA, child_length);
        memcpy(result + length, &tmp, sizeof(struct sock_filter));
    }
    length += 1 + child_length;
  }

  if(rule->next) {
    int next_length = create_filter(rule->next, (result == NULL ? NULL : result + length + 2));
    if(result) {
      struct sock_filter tmp[] = {
        BPF_STMT(BPF_JMP+BPF_JA, 1),
        BPF_STMT(BPF_JMP+BPF_JA, next_length + 1)
      };
      memcpy(result + length, tmp, 2 * sizeof(struct sock_filter));
    }
    length += 2 + next_length;
  }

  return length;
}

int apply_filter(struct rule_node* rule, uint8_t* ether_1, uint8_t* ether_2) {
  struct sock_fprog insns;
  struct sock_filter header[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 6),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(*((uint32_t*)ether_1)), 0, 3),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 10),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(((uint16_t*)ether_1)[2]), 4, 0),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 6),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(*((uint32_t*)ether_2)), 0, 4),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 10),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(((uint16_t*)ether_2)[2]), 0, 2),
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x806, 1, 2),
    BPF_STMT(BPF_RET+BPF_K, 0),
    BPF_STMT(BPF_RET+BPF_K, (uint32_t)-1)
  };

  int length = create_filter(rule, NULL);
  insns.len = length + 14;
  if(!(insns.filter = malloc(insns.len * sizeof(struct sock_filter)))) {
    perror("malloc");
    return 1;
  }

  memcpy(insns.filter, header, 12 * sizeof(struct sock_filter));

  create_filter(rule, insns.filter + 12);
  struct sock_filter footer[] = {
    BPF_STMT(BPF_RET+BPF_K, 0), // drop case
    BPF_STMT(BPF_RET+BPF_K, (uint32_t)-1) // accept case
  };
  memcpy(insns.filter + length + 12, footer,  2 * sizeof(struct sock_filter));

  if(setsockopt(raw_socket, SOL_SOCKET, SO_ATTACH_FILTER, &insns, sizeof(insns)) == -1) {
    perror("setsockopt");
    return 1;
  }

  free(insns.filter);
  return 0;
}

int get_capture_stats(uint32_t* recv, uint32_t* captured, uint32_t* drop) {
  struct tpacket_stats stats;
  socklen_t stats_length = sizeof(struct tpacket_stats);
  if(getsockopt(raw_socket, SOL_PACKET, PACKET_STATISTICS, &stats, &stats_length) == -1) {
    perror("getsockopt");
    return 1;
  }
  *recv = stats.tp_packets;
  *drop = stats.tp_drops;
  *captured = capture_count;
  return 0;
}
