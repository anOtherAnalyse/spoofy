#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ndrv.h>

#include <send.h>

static int raw_socket;
static struct sockaddr_ndrv sa_ndrv;

int init_raw_sock(char* interface) {
  if((raw_socket = socket(PF_NDRV, SOCK_RAW, 0)) == -1) {
    perror("socket ");
    return 1;
  }
  stpncpy((char*)sa_ndrv.snd_name, interface, sizeof(sa_ndrv.snd_name));
  sa_ndrv.snd_family = PF_NDRV;
  sa_ndrv.snd_len = sizeof(sa_ndrv);

  if(bind(raw_socket, (struct sockaddr*)&sa_ndrv, sizeof(sa_ndrv)) == -1) {
    perror("bind ");
    return 1;
  }

  return 0;
}

int send_frame(char* buff, unsigned long length) {

  // static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

  // pthread_mutex_lock(&lock);

    if(sendto(raw_socket, buff, length, 0, (struct sockaddr *)&sa_ndrv, sizeof(sa_ndrv)) == -1) {
      perror("sendto ");
      // pthread_mutex_unlock(&lock);
      return 1;
    }

  // pthread_mutex_unlock(&lock);

  return 0;
}
