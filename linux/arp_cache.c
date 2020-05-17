#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arp_cache.h>

int del_arp_entry(uint8_t* ip) {

  int inet_fd;
  if((inet_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket ");
    return 1;
  }

  struct arpreq arp_entry;
  memset(&arp_entry, 0, sizeof(struct arpreq));

  struct sockaddr_in* ip_addr = (struct sockaddr_in*)&(arp_entry.arp_pa);
  ip_addr->sin_family = AF_INET;
  ip_addr->sin_addr.s_addr = *((uint32_t*)ip);

  arp_entry.arp_flags = ATF_PERM | ATF_COM;

  if(ioctl(inet_fd, SIOCDARP, &arp_entry)) {
    // perror("ioctl ");
    return 1;
  }

  close(inet_fd);
  return 0;
}

int add_arp_entry(uint8_t* ether, uint8_t* ip) {

  int inet_fd;
  if((inet_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket ");
    return 1;
  }

  struct arpreq arp_entry;
  memset(&arp_entry, 0, sizeof(struct arpreq));

  struct sockaddr_in* ip_addr = (struct sockaddr_in*)&(arp_entry.arp_pa);
  ip_addr->sin_family = AF_INET;
  ip_addr->sin_addr.s_addr = *((uint32_t*)ip);

  arp_entry.arp_ha.sa_family = ARPHRD_ETHER;
  memcpy(&arp_entry.arp_ha.sa_data, ether, 6);

  arp_entry.arp_flags = ATF_PERM | ATF_COM;

  if(ioctl(inet_fd, SIOCSARP, &arp_entry)) {
    perror("ioctl ");
    return 1;
  }

  close(inet_fd);
  return 0;
}
