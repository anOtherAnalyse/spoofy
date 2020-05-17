#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <receive.h>
#include <filter.h>

static int bpf_fd;
static unsigned int buff_len;
unsigned int capture_count = 0;

int init_capture_fd(char* if_name) {

  unsigned int i;
  char dev[11] = {0};
  buff_len = RECV_BUF_LEN;

  for(i = 0; i < 99; ++i) {
      sprintf(dev, "/dev/bpf%i", i);
      if((bpf_fd = open(dev, O_RDONLY)) != -1) break;
  }

  if(bpf_fd == -1) {
    fprintf(stderr, "Unable to find available bpf device node\n");
    return 1;
  }

  if(ioctl(bpf_fd, BIOCSBLEN, &buff_len) == -1) { // set capture buffer length
      perror("ioctl BIOCSBLEN");
      return 1;
  }

  struct ifreq if_req;
  strlcpy(if_req.ifr_name, if_name, IFNAMSIZ);
  if(ioctl(bpf_fd, BIOCSETIF, &if_req) == -1) {
        perror("ioctl BIOCSETIF");
        return 1;
  }

  unsigned int enable = 1;
  if(ioctl(bpf_fd, BIOCIMMEDIATE, &enable) == -1) { // read return just after receiving a packet
      perror("ioctl BIOCIMMEDIATE");
      return 1;
  }

  if(ioctl(bpf_fd, BIOCPROMISC, NULL) == -1) { // promiscious mode
      perror("ioctl BIOCPROMISC");
      return 1;
  }

  unsigned int zero = 0;
  if(ioctl(bpf_fd, BIOCSSEESENT, &zero) == -1) { // only get incoming packets
    perror("ioctl BIOCSSEESENT");
    return 1;
  }

  return 0;
}

int apply_identifier_filter(uint32_t ip_1, uint32_t ip_2) {
  struct bpf_insn filter_rule[] = { // filter = arp from ip_1 or from ip_2
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x806, 0, 4),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 28),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(ip_1), 1, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(ip_2), 0, 1),
    BPF_STMT(BPF_RET+BPF_K, (uint32_t)-1),
    BPF_STMT(BPF_RET+BPF_K, 0)
  };
  struct bpf_program filter = {
    .bf_len = 7,
    .bf_insns = filter_rule
  };
  if(ioctl(bpf_fd, BIOCSETFNR, &filter) == -1) {
    perror("ioctl BIOCSETFNR");
    return 1;
  }
  return 0;
}

int apply_ping_filter(uint32_t ip_1, uint32_t ip_2) {
  struct bpf_insn filter_rule[] = {
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
  struct bpf_program filter = {
    .bf_len = 12,
    .bf_insns = filter_rule
  };
  if(ioctl(bpf_fd, BIOCSETFNR, &filter) == -1) {
    perror("ioctl BIOCSETFNR");
    return 1;
  }
  return 0;
}

int capture(capture_callback_t cb, void* cb_args) {
  struct bpf_hdr* bpf_p;
  struct capture_auxdata_t auxdata;
  char *buff, *current;
  int length;

  if(!(buff = malloc(buff_len))) {
    perror("malloc");
    return 1;
  }

  // flush buffer of incoming packets
  if(ioctl(bpf_fd, BIOCFLUSH, NULL) == -1) {
    perror("ioctl BIOCFLUSH");
    return 1;
  }

  capture_count = 0; // reset capture count

  while(1) {

    // Receive packet
    if((length = read(bpf_fd, buff, buff_len)) == -1) {
      perror("read bpf");
      return 1;
    }
    current = buff;

    while(current < buff + length) {
      bpf_p = (struct bpf_hdr*)current;

      if(bpf_p->bh_caplen != bpf_p->bh_datalen) {
        fprintf(stderr, "Capture: truncated frame, got %u of %u bytes\n", bpf_p->bh_caplen, bpf_p->bh_datalen);
      }

      auxdata.cap_len = bpf_p->bh_caplen;
      auxdata.real_len = bpf_p->bh_datalen;
      auxdata.time.tv_sec = bpf_p->bh_tstamp.tv_sec;
      auxdata.time.tv_usec = bpf_p->bh_tstamp.tv_usec;
      if(cb(current + bpf_p->bh_hdrlen, &auxdata, cb_args)) return 0; // cb asked for return

      current += BPF_WORDALIGN(bpf_p->bh_hdrlen + bpf_p->bh_caplen);
    }

  }

  return 0;
}

int get_capture_stats(uint32_t* recv, uint32_t* captured, uint32_t* drop) {
  struct bpf_stat stats;
  if(ioctl(bpf_fd, BIOCGSTATS, &stats) == -1) {
    perror("ioctl BIOCGSTATS");
    return 1;
  }

  *recv = stats.bs_recv; // number of packets received by the descriptor since last flush
  *captured = capture_count; // number of packets captured by filter
  *drop = stats.bs_drop; // number of packets dropped because of queue overflow (app not keeping up with traffic)

  return 0;
}

int create_filter(struct rule_node* rule, struct bpf_insn* result) {
  int length = 0, negation = (rule->type & NEGATION_TERM);
  uint32_t offset = 0;
  switch(rule->type & 0x7f) {
    case ETHER_ADDR_SRC_TOK:
      offset += 6;
    case ETHER_ADDR_DST_TOK:
      if(result) {
        struct bpf_insn tmp[] = {
          BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(((uint32_t*)(rule->value))[0]), 0, negation ? 3 : 2),
          BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset + 4),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(((uint16_t*)(rule->value))[2]), (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 4 * sizeof(struct bpf_insn));
      }
      length += 4;
      break;
    case ETHER_TYPE_TOK:
      if((*((uint16_t*)rule->value) == 0x8) && !negation) { // it's ip then
        if(result) {
          struct bpf_insn tmp[] = {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, 2),
            BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
            BPF_STMT(BPF_JMP+BPF_JA, 1)
          };
          memcpy(result, tmp, 4 * sizeof(struct bpf_insn));
        }
        length += 4;
      } else {
        if(result) {
          struct bpf_insn tmp[] = {
            BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
            BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(*((uint16_t*)rule->value)), (negation == 0), (negation != 0))
          };
          memcpy(result, tmp, 2 * sizeof(struct bpf_insn));
        }
        length += 2;
      }
      break;
    case IP_ADDR_DST_TOK:
      offset += 4;
    case IP_ADDR_SRC_TOK:
      offset += 26;
      if(result) {
        struct bpf_insn tmp[] = {
          BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohl(*((uint32_t*)(rule->value))), (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 2 * sizeof(struct bpf_insn));
      }
      length += 2;
      break;
    case PROTOCOL_TOK:
      if(result) {
        struct bpf_insn tmp[] = {
          BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, rule->value[0], (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 2 * sizeof(struct bpf_insn));
      }
      length += 2;
      break;
    case PORT_DST_TOK:
      offset += 2;
    case PORT_SRC_TOK:
      offset += 14;
      if(result) {
        struct bpf_insn tmp[] = {
          BPF_STMT(BPF_LD+BPF_H+BPF_IND, offset),
          BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ntohs(*((uint16_t*)(rule->value))), (negation == 0), (negation != 0))
        };
        memcpy(result, tmp, 2 * sizeof(struct bpf_insn));
      }
      length += 2;
  }

  if(rule->child) {
    int child_length = create_filter(rule->child, (result == NULL ? NULL : result + length + 1));
    if(result) {
      struct bpf_insn tmp = BPF_STMT(BPF_JMP+BPF_JA, child_length);
        memcpy(result + length, &tmp, sizeof(struct bpf_insn));
    }
    length += 1 + child_length;
  }

  if(rule->next) {
    int next_length = create_filter(rule->next, (result == NULL ? NULL : result + length + 2));
    if(result) {
      struct bpf_insn tmp[] = {
        BPF_STMT(BPF_JMP+BPF_JA, 1),
        BPF_STMT(BPF_JMP+BPF_JA, next_length + 1)
      };
      memcpy(result + length, tmp, 2 * sizeof(struct bpf_insn));
    }
    length += 2 + next_length;
  }

  return length;
}

int apply_filter(struct rule_node* rule, uint8_t* ether_1, uint8_t* ether_2) {
  struct bpf_program insns;
  struct bpf_insn header[] = {
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
  insns.bf_len = length + 14;
  if(!(insns.bf_insns = malloc(insns.bf_len * sizeof(struct bpf_insn)))) {
    perror("malloc");
    return 1;
  }

  memcpy(insns.bf_insns, header, 12 * sizeof(struct bpf_insn));

  create_filter(rule, insns.bf_insns + 12);
  struct bpf_insn footer[] = {
    BPF_STMT(BPF_RET+BPF_K, 0), // drop case
    BPF_STMT(BPF_RET+BPF_K, (uint32_t)-1) // accept case
  };
  memcpy(insns.bf_insns + length + 12, footer,  2 * sizeof(struct bpf_insn));

  if(ioctl(bpf_fd, BIOCSETFNR, &insns) == -1) {
    perror("ioctl BIOCSETFNR");
    return 1;
  }

  free(insns.bf_insns);
  return 0;
}
