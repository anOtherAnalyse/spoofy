#ifndef _ARP_CACHE_H_
#define _ARP_CACHE_H_

#include <types.h>

/* Del static entry from arp cache */
int del_arp_entry(uint8_t* ip);

/* Add permanent entry in arp cache */
int add_arp_entry(uint8_t* ether, uint8_t* ip);

#endif
