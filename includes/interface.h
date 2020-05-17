#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include <types.h>

/* Give interface (in if_name) for the network containing both ip_1 & ip_2
 * return 0 if error/not found, interface ip addr if success
 */
uint32_t getSuitableInterface(uint32_t ip_1, uint32_t ip_2, char* if_name);

/* Get interface if_name ether address, returned in ether
 * return 0 if success
 */
int getInterfaceEther(char* if_name, uint8_t* ether);

#endif
