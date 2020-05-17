#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef __MACH__
  #include <net/if_dl.h>
  #define AF_PACKET AF_LINK
#elif __linux__
  #include <linux/if_packet.h>
#endif

#include <interface.h>

uint32_t getSuitableInterface(uint32_t ip_1, uint32_t ip_2, char* if_name) {

  struct ifaddrs *ifs, *current;
  struct in_addr network_addr, interface_addr, mask_addr;

  if(getifaddrs(&ifs)) {
    perror("getifaddrs ");
    return 0;
  }

  current = ifs;
  while(current) {

    if(!current->ifa_addr) continue;

    if(current->ifa_addr->sa_family == AF_INET) { // We only use ipv4 adresses

      interface_addr = ((struct sockaddr_in*)current->ifa_addr)->sin_addr;
      mask_addr = ((struct sockaddr_in*)current->ifa_netmask)->sin_addr;

      network_addr.s_addr = interface_addr.s_addr & mask_addr.s_addr; // Looking for matching interface
      if(network_addr.s_addr == (ip_1 & mask_addr.s_addr) && network_addr.s_addr == (ip_2 & mask_addr.s_addr)) {

        strncpy(if_name, current->ifa_name, IFNAMSIZ);
        if_name[IFNAMSIZ - 1] = 0;

        freeifaddrs(ifs);
        return interface_addr.s_addr;
      }

    }

    current = current->ifa_next;
  }
  freeifaddrs(ifs);

  return 0;
}

int getInterfaceEther(char* if_name, uint8_t* ether) {
  struct ifaddrs *ifs, *current;

  if(getifaddrs(&ifs)) {
    perror("getifaddrs ");
    return 1;
  }

  current = ifs;
  while(current) {

    if(!current->ifa_addr) continue;

    if(current->ifa_addr->sa_family == AF_PACKET && !strncmp(if_name, current->ifa_name, IFNAMSIZ)) { // Check for matching interface

      #ifdef __MACH__
        struct sockaddr_dl* addr = (struct sockaddr_dl*)current->ifa_addr;
        memcpy(ether, addr->sdl_data + addr->sdl_nlen, 6);
      #elif __linux__
        struct sockaddr_ll* addr = (struct sockaddr_ll*)current->ifa_addr;
        memcpy(ether, addr->sll_addr, 6);
      #endif

      freeifaddrs(ifs);
      return 0;
    }

    current = current->ifa_next;
  }

  freeifaddrs(ifs);
  return 1;
}
