#ifndef _CMD_H_
#define _CMD_H_

#include <types.h>

/* Available commands:
 * filter <rule>
 * no filter
*/

/* execute given command
 * 0 - ok
 * 1 - cmd invalid
 * 2 - args invalid
 */
int execute_cmd(char* cmd, uint32_t cmd_len);

#endif
