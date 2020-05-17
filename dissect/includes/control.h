#ifndef _CONTROL_H_
#define _CONTROL_H_

#define MAX_CMD_LEN 256

#define CMD_ERR -1
#define CMD_UNKNOWN 0
#define CMD_UP 1
#define CMD_DOWN 2
#define CMD_ESC 3
#define CMD_PAGEUP 4
#define CMD_PAGEDOWN 5
#define CMD_EXIT 6
#define CMD_COMMAND 7
#define CMD_ENTER 8
#define CMD_NEXT 9
#define CMD_PREVIOUS 10

#include <types.h>

/* return next typed command, blocking opperation
 * return CMD_ERR if error
 */
int next_command();

/* Enter command state, read command and execute it
 */
void command_loop();

/* Get & compute input from user */
void input_loop();

#endif
