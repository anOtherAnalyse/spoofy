#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "includes/display.h"
#include "includes/dissect.h"
#include "includes/cmd.h"
#include "includes/control.h"
#include "includes/parse.h"

extern screen_context_t win_state;

void command_loop() {
  uint32_t len;
  int command;
  uint16_t cmd_len, display_cmd_len;
  char cmd[MAX_CMD_LEN], buff[32], c;

  display_scene(); // clear display
  cmd[0] = '/';
  cmd_len = 1;
  display_cmd_len = 1;

  // read command loop
  while(1) {
    display_cmd_len = cmd_len > win_state.winsize.ws_col ? win_state.winsize.ws_col : cmd_len;
    if(cmd_len < win_state.winsize.ws_col) {
      len = snprintf(buff, sizeof(buff), "\x1b[%uD\x1b[K\x1b[7m", display_cmd_len);
      write(1, buff, len);
    } else write(1, "\r", 1);
    write(1, cmd, display_cmd_len);
    if(read(0, &c, 1) != 1) return;
    if(((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '.' || c == ':') && (cmd_len < MAX_CMD_LEN - 1)) {
      if(c >= 'A' && c <= 'Z') c = (c - 'A') + 'a';
      cmd[cmd_len++] = c;
    } else if(c == 127) { // erase
      if(cmd_len > 1) {
          cmd_len --;
          display_scene();
      } else {
        display_scene();
        return;
      }
    } else if(c == '\r') { // enter cmd

      // execute cmd
      cmd[cmd_len] = 0;
      switch(execute_cmd(cmd + 1, cmd_len - 1)) {
        case 1:
          display_scene();
          write(1, "\x1b[15D\x1b[K\x1b[7mUnknown command\x1b[m", 30);
          break;
        case 2:
          display_scene();
          write(1, "\x1b[12D\x1b[K\x1b[7mInvalid args\x1b[m", 27);
          break;
        case 0:
          display_scene();
      }
      break;
    }
  }
}

void input_loop() {
  int command;

  while((command = next_command()) != CMD_ERR) {
    if(command == CMD_EXIT) break;
    if(win_state.view == VIEW_LIST) { // view on list of captures
      switch(command) {
        case CMD_UP:
          move_cursor(CUR_UP);
          display_scene();
          break;
        case CMD_DOWN:
          move_cursor(CUR_DOWN);
          display_scene();
          break;
        case CMD_PAGEUP:
          win_state.cursor = NULL;
          move_capture_set_index(- win_state.winsize.ws_row + 2, win_state.winsize.ws_row - 2);
          display_scene();
          break;
        case CMD_PAGEDOWN:
          win_state.cursor = NULL;
          move_capture_set_index(win_state.winsize.ws_row - 2, win_state.winsize.ws_row - 2);
          display_scene();
          break;
        case CMD_ENTER:
          if(win_state.cursor && !parse_capture(win_state.cursor)) {
            win_state.view = VIEW_SUMMARY;
            display_scene();
          }
          break;
        case CMD_COMMAND:
          command_loop();
          break;
      }
    } else { // view on particular packet
      switch(command) {
        case CMD_ESC:
          free_capture();
          win_state.view = VIEW_LIST;
          display_scene();
          break;
        case CMD_UP:
          move_summary_cursor(-1); break;
        case CMD_DOWN:
          move_summary_cursor(1); break;
        case CMD_PAGEUP:
          move_summary_cursor(-win_state.winsize.ws_row + 2); break;
          break;
        case CMD_PAGEDOWN:
          move_summary_cursor(win_state.winsize.ws_row - 2); break;
          break;
        case CMD_NEXT:
          {
            capture_t* old_cursor = win_state.cursor;
            uint16_t old_cursor_row = win_state.cursor_row;
            move_cursor(CUR_DOWN);
            if(win_state.cursor) { // has next
              free_capture();
              parse_capture(win_state.cursor);
              display_scene();
            } else { // end of list
              win_state.cursor = old_cursor;
              win_state.cursor_row = old_cursor_row;
            }
          }
          break;
        case CMD_PREVIOUS:
            move_cursor(CUR_UP);
            if(win_state.cursor) {
              free_capture();
              parse_capture(win_state.cursor);
              display_scene();
            }
          break;
      }
    }
  }
}

int next_command() {
  int len;
  char c;

  if((len = read(0, &c, 1)) == 1) {

    // Convert key to command
    switch(c) {
      case '\x1b': // ESCAPE
        {
          // set up read timeout
          struct termios save, tto;
          if(tcgetattr(0, &save) == -1) {
            perror("tcgetattr");
            return 1;
          }
          tto = save;
          tto.c_cc[VMIN] = 0;
          tto.c_cc[VTIME] = 1;
          if(tcsetattr(0, TCSANOW, &tto) == -1) {
            perror("tcsetattr");
            return 1;
          }
          len = read(0, &c, 1);

          // restore tty
          if(tcsetattr(0, TCSANOW, &save) == -1) {
            perror("tcsetattr");
            return 1;
          }

          if(len == 1) {
            if(c == '[') {
              if((len = read(0, &c, 1)) != 1) return CMD_ERR;
              switch(c) {
                case 'A': return CMD_UP;
                case 'B': return CMD_DOWN;
                case 'C': return CMD_NEXT;
                case 'D': return CMD_PREVIOUS;
                default: return CMD_UNKNOWN;
              }
            } else return CMD_UNKNOWN;
          } else return CMD_ESC;
        }
      case CTRL_KEY('q'): return CMD_EXIT;
      case CTRL_KEY('b'): return CMD_PAGEUP;
      case ' ': return CMD_PAGEDOWN;
      case 13: return CMD_ENTER;
      case '/': return CMD_COMMAND;
      default: return CMD_UNKNOWN;
    }
  }

  return CMD_ERR;
}
