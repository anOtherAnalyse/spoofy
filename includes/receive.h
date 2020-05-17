#ifndef _RECEIVE_H_
#define _RECEIVE_H_

#define RECV_BUF_LEN 2048 // capture buffer length
#define ID_RETRY_INT 5 // interval of time between two consecutive arp who-has for target identification

#include <sys/time.h>

#include <types.h>
#include <protocols.h>
#include <filter.h>

// data about a captured packet
struct capture_auxdata_t {
  uint32_t cap_len;
  uint32_t real_len;
  struct timeval time;
};

/* Callback function for every frame captured
 * args : raw frame, frame auxdata & callback parameters
 * return : 0 = continue capture, other = return
*/
typedef int (*capture_callback_t)(char*, struct capture_auxdata_t*, void*);

/* Arguments for the capture callback function */
struct capture_arg_t {
  uint8_t* ether_1;
  uint8_t* ether_2;
  uint32_t ip_1;
  uint32_t ip_2;
  struct rule_node* filter;
  int pip;
};

/* Arguments for the target identifier thread */
struct identifier_arg_t {
  uint32_t ip_1;
  uint32_t ip_2;
  uint8_t* ret_ether_1;
  uint8_t* ret_ether_2;
  int pip;
};

/* target identifier thread */
void* target_identifier(void* raw_args);

/* Callback for the capture function */
int capture_callback(char* buff, struct capture_auxdata_t* aux, void* raw_args);

/* Callback for the identifier function */
int identifier_callback(char* buff, struct capture_auxdata_t* aux, void* raw_args);


/* ****************************
 * OS dependent implementations
 * **************************** */

/* Init the capture device on specified interface
 * first method to call, return 0 if success
 */
int init_capture_fd(char* if_name);

/* Set filter for next capture to be the target identifier filter (arp & (from ip_1 or from ip_2))
 * return 0 if success
 */
int apply_identifier_filter(uint32_t ip_1, uint32_t ip_2);

/* Filter for capturing ping packet for destination ip_1 or ip_2 */
int apply_ping_filter(uint32_t ip_1, uint32_t ip_2);

/*  Apply the given filter for the next capture
* arguments ethers are used to capture only spoofed packets
* return 0 if success
*/
int apply_filter(struct rule_node* rule, uint8_t* ether_1, uint8_t* ether_2);

/* Start the capture of frames for the current filter
 * cb callback function, cb_args callback parameters
 */
int capture(capture_callback_t cb, void* cb_args);

/* Get statistics for the last performed capture
 * return recv number of packets received by the filter
 * drop number of packets dropped because queue was full (app can not keep up with traffic)
 */
int get_capture_stats(uint32_t* recv, uint32_t* captured, uint32_t* drop);

#endif
