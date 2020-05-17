#ifndef _DISPLAY_H_
#define _DISPLAY_H_

#include <termios.h>
#include <sys/ioctl.h>

#include <types.h>

#include "parse.h"

#define LINE_BUFF_LEN 512

#define MIN(x,y) (x > y ? y : x)

#define CTRL_KEY(k) ((k) & 0x1f)
#define clear_screen() write(0, "\x1b[2J", 4)
#define hide_cursor() write(0, "\x1b[?25l", 6)
#define show_cursor() write(0, "\x1b[?25h", 6)

#define VIEW_LIST 0
#define VIEW_SUMMARY 1

typedef struct screen_context_s {
  char* filename;
  char* buff;
  struct termios save;
  struct winsize winsize;
  capture_t* cursor;
  uint16_t cursor_row;
  uint8_t view;
} screen_context_t;

/* Truncate line to fit into screen
 * update len of the buffer
 * return number of printable characters that were in the line
 */
uint32_t truncate_line(char* line, uint32_t* len, uint32_t row_len);

#define DISP_CENTER 1
#define DISP_NEGATIVE 2

/* Draw a line at screen */
void draw_line(uint8_t flags, char* format, ...);

/* Draw line with va_list arguments */
void draw_line_varg(uint8_t flags, char* format, va_list args);

/* Init screen context */
int init_screen(char* filename);

/* reset & free scree n context */
int reset_screen();

#define CUR_UP 0
#define CUR_DOWN 1
// move cursor position
void move_cursor(uint8_t cmd);

int setup_raw_mode();
int get_winsize();
void sigwinch_handler(int sig);

void display_capture(capture_t* current);
void display_scene();

#endif
