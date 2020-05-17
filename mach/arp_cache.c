#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#include <arp_cache.h>

struct m_rtmsg_t {
  struct rt_msghdr m_rtm;
  char m_space[512];
};

static int s = -1;

int rtmsg(int cmd, struct m_rtmsg_t *m_rtmsg, struct sockaddr_inarp sin_m, struct sockaddr_dl sdl_m);

int del_arp_entry(uint8_t* ip) {

  struct m_rtmsg_t m_rtmsg;
  struct rt_msghdr *rtm = &(m_rtmsg.m_rtm);
  struct sockaddr_inarp *sin, sin_m = {sizeof(struct sockaddr_inarp), AF_INET};
  struct sockaddr_dl *sdl, sdl_m;
  sin_m.sin_addr.s_addr = *((uint32_t*)ip);

  if(rtmsg(RTM_GET, &m_rtmsg, sin_m, sdl_m)) {
		return 1;
	}
	sin = (struct sockaddr_inarp *)(rtm + 1);
	sdl = (struct sockaddr_dl *)(sin->sin_len + (char *)sin);
  if(sdl->sdl_alen != 6) return 1; // There is nothing to delete

  if (sdl->sdl_family != AF_LINK) {
		fprintf(stderr, "no AF_LINK interface for given host\n");
		return 1;
	}

	return rtmsg(RTM_DELETE, &m_rtmsg, sin_m, sdl_m);
}

int add_arp_entry(uint8_t* ether, uint8_t* ip) {

  struct m_rtmsg_t m_rtmsg;

  struct sockaddr_inarp* sin, sin_m = {sizeof(struct sockaddr_inarp), AF_INET};
  struct sockaddr_dl *sdl, sdl_m = {sizeof(struct sockaddr_dl), AF_LINK};
  struct rt_msghdr *rtm = &(m_rtmsg.m_rtm);
  u_char* ea;

  sin_m.sin_addr.s_addr = *((uint32_t*)ip);

  ea = (u_char *)LLADDR(&sdl_m);
  memcpy(ea, ether, 6);
  sdl_m.sdl_alen = 6;

  if (rtmsg(RTM_GET, &m_rtmsg, sin_m, sdl_m)) {
		return 1;
	}
  sin = (struct sockaddr_inarp *)(rtm + 1);
	sdl = (struct sockaddr_dl *)(sin->sin_len + (char *)sin);

  if (sdl->sdl_family != AF_LINK) {
		fprintf(stderr, "no AF_LINK interface for given host\n");
		return 1;
	}

  sdl_m.sdl_type = sdl->sdl_type;
	sdl_m.sdl_index = sdl->sdl_index;

  return rtmsg(RTM_ADD, &m_rtmsg, sin_m, sdl_m);
}

int rtmsg(int cmd, struct m_rtmsg_t *m_rtmsg, struct sockaddr_inarp sin_m, struct sockaddr_dl sdl_m) {
  static int seq;
  pid_t pid = getpid();
  int rlen, l;

  struct rt_msghdr *rtm = &(m_rtmsg->m_rtm);
  char *cp = m_rtmsg->m_space;

  if(s < 0) {
    if((s = socket(PF_ROUTE, SOCK_RAW, 0)) == -1) {
      perror("arp: socket ");
      return 1;
    }
  }

  errno = 0;
  if (cmd == RTM_DELETE)
		goto doit;

  bzero((char *)m_rtmsg, sizeof(struct m_rtmsg_t));
	rtm->rtm_version = RTM_VERSION;

  switch (cmd) {
  	default:
  		fprintf(stderr, "arp: internal wrong cmd\n");
  		return 1;
  	case RTM_ADD:
  		rtm->rtm_addrs |= RTA_GATEWAY;
  		rtm->rtm_inits = RTV_EXPIRE;
  		rtm->rtm_flags |= (RTF_HOST | RTF_STATIC);
  	case RTM_GET:
  		rtm->rtm_addrs |= RTA_DST;
	}

  #define NEXTADDR(w, s) \
  	if (rtm->rtm_addrs & (w)) { \
  		bcopy((char *)&s, cp, sizeof(s)); cp += sizeof(s);}

  	NEXTADDR(RTA_DST, sin_m);
  	NEXTADDR(RTA_GATEWAY, sdl_m);

    rtm->rtm_msglen = cp - (char *)m_rtmsg;
doit:
    l = rtm->rtm_msglen;
  	rtm->rtm_seq = ++seq;
  	rtm->rtm_type = cmd;
    if ((rlen = write(s, (char *)m_rtmsg, l)) < 0) {
  		if (errno != ESRCH || cmd != RTM_DELETE) {
  			perror("writing to routing socket ");
  			return 1;
  		}
  	}
    do {
  		l = read(s, (char *)m_rtmsg, sizeof(struct m_rtmsg_t));
  	} while (l > 0 && (rtm->rtm_seq != seq || rtm->rtm_pid != pid));
  	if (l < 0)
  		(void) fprintf(stderr, "arp: read from routing socket: %s\n",
  		    strerror(errno));

    return 0;
}
