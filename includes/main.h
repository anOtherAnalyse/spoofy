#ifndef _MAIN_H_
#define _MAIN_H_

#define SPY_ETHER "\xb0\x0b\xde\xad\xbe\xef"
#define DAEMON_LOG_FILE "sniffer.log"

// Arguments flags
#define SPF_DAEMON 0x1
#define SPF_MAC_ADDR 0x2
#define SPF_DUMP_FILE 0x4

#include <types.h>
#include <net/if.h>

// context flags
#define PERMANENT_T1 1
#define PERMANENT_T2 2
#define TARGETS_SPOOFED 4

// define a spoofing strategy, which arp type to use
struct spoof_strategy {
  uint8_t ht_spoof;
  uint8_t ht_reply;
};

// spoofing context
struct spoof_context {
  uint8_t target_1_ether[6];
  uint8_t target_2_ether[6];
  uint8_t our_ether[6];
  uint32_t target_1_ip;
  uint32_t target_2_ip;
  uint32_t our_ip;
  struct spoof_strategy s1;
  struct spoof_strategy s2;
  char interface_name[IFNAMSIZ];
  uint8_t flags;
};

static struct spoof_context context = {
  .flags = 0,
  .interface_name = {0}
};

// Manage system config
int manage_system_conf(uint8_t enable, char* conf_name);

// system dependent macros
#ifdef __linux__
  #define enable_forwarding(enable) manage_system_conf(enable, "/proc/sys/net/ipv4/ip_forward")
  int enable_icmp_redirect_on_interface(uint8_t enable, char* ifname);
#elif __MACH__
  #define enable_forwarding(enable) manage_system_conf(enable, "net.inet.ip.forwarding")
  #define enable_icmp_redirect(enable) manage_system_conf(enable, "net.inet.ip.redirect")
#endif

// SIGINT & SIGTERM handler (call exit routine)
void signal_exit(int signal);

// At exit
void exit_routine();

#endif
