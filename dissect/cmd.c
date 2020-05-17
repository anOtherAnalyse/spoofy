#include <stdio.h>
#include <string.h>

#include "includes/cmd.h"
#include "includes/parse.h"
#include "includes/display.h"

extern struct parse_context context;
extern screen_context_t win_state;

int execute_cmd(char* cmd, uint32_t cmd_len) {
  if(cmd_len >= 6 && !memcmp("filter", cmd, 6)) { // filter cmd
    struct rule_node* filter;
    if(parseRule(cmd + 6, &filter)) return 2;
    init_capture_set(win_state.winsize.ws_row - 2, filter);
    win_state.cursor = NULL;
    return 0;
  } else if(cmd_len >= 3 && !memcmp("no ", cmd, 3)) {
    if(cmd_len >= 9 && ! memcmp("filter", cmd + 3, 6)) {
      init_capture_set(win_state.winsize.ws_row - 2, NULL);
      win_state.cursor = NULL;
    }
    else return 2;
    return 0;
  }
  else return 1;
}
