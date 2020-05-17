#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <send.h>

static int raw_socket;
static struct sockaddr_ll sa;

int init_raw_sock(char* interface) {
  if((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    perror("socket ");
    return 1;
  }

  struct ifreq if_req;
  strncpy(if_req.ifr_name, interface, IFNAMSIZ);
  if_req.ifr_name[IFNAMSIZ - 1] = 0;
  if(ioctl(raw_socket, SIOCGIFINDEX, &if_req) == -1) {
    perror("ioctl SIOCGIFINDEX ");
    return 1;
  }

  sa.sll_family = PF_PACKET;
  sa.sll_protocol = htons(ETH_P_ALL);
  sa.sll_ifindex = if_req.ifr_ifindex;
  if(bind(raw_socket, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
    perror("bind ");
    return 1;
  }

  return 0;
}

int send_frame(char* buff, unsigned long length) {

  // static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

  // pthread_mutex_lock(&lock);

    if(sendto(raw_socket, buff, length, 0, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
      perror("sendto ");
      // pthread_mutex_unlock(&lock);
      return 1;
    }

  // pthread_mutex_unlock(&lock);

  return 0;
}
