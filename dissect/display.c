#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <math.h>

#include "includes/display.h"
#include "includes/dissect.h"

extern struct parse_context context;

screen_context_t win_state = {
  .buff = NULL,
  .cursor = NULL,
  .cursor_row = 0,
  .view = VIEW_LIST
};

uint32_t truncate_line(char* line, uint32_t* len, uint32_t row_len) {
  uint32_t i = 0, j = 0, last, penultimate;
  while(i < *len) {
    if(line[i] == '\x1b') {
      while((++i < *len) && (line[i] < 'a' || line[i] > 'z') && (line[i] < 'A' || line[i] > 'Z'));
    } else {
      j ++;
      if(j == row_len-1) penultimate = i;
      else if(j == row_len) last = i;
      else if (j > row_len) {
        uint32_t k = i;
        while(k < *len - 1) {
          line[k] = line[k + 1];
          k ++;
        }
        i --;
        *len -= 1;
      }
    }
    i ++;
  }
  if(j > row_len) {
    line[last] = '.';
    line[penultimate] = '.';
  }
  return MIN(j, row_len);
}

void draw_line(uint8_t flags, char* format, ...) {
  va_list args;
  va_start(args, format);
  draw_line_varg(flags, format, args);
  va_end(args);
}

void draw_line_varg(uint8_t flags, char* format, va_list args) {

  uint32_t len, print_len, margin;

  len = vsnprintf(win_state.buff, LINE_BUFF_LEN, format, args);
  print_len = truncate_line(win_state.buff, &len, win_state.winsize.ws_col);

  if(flags & DISP_CENTER) {
    margin = (uint32_t)ceil((win_state.winsize.ws_col - print_len) / 2.0);
    if(!margin) flags &= ~DISP_CENTER;
    else memset(win_state.buff + LINE_BUFF_LEN - margin, ' ', margin);
  }

  if(flags & DISP_NEGATIVE) write(1, "\x1b[K\x1b[7m", 7);
  else write(1, "\x1b[K", 3);

  if(flags & DISP_CENTER) write(1, win_state.buff + LINE_BUFF_LEN - margin, margin);

  write(1, win_state.buff, len);

  if((flags & DISP_CENTER) && (flags & DISP_NEGATIVE)) write(1, win_state.buff + LINE_BUFF_LEN - margin, win_state.winsize.ws_col - print_len - margin);

  if(flags & DISP_NEGATIVE) write(1, "\x1b[m\r\n", 5);
  else write(1, "\r\n", 2);
}

int init_screen(char* filename) {

  if(setup_raw_mode()) return 1;

  win_state.filename = filename;

  if(get_winsize()) return 1;

  if(!(win_state.buff = malloc(LINE_BUFF_LEN))) {
    perror("malloc");
    return 1;
  }

  if(signal(SIGWINCH, sigwinch_handler) == SIG_ERR) {
    perror("signal");
    return 1;
  }

  init_capture_set(win_state.winsize.ws_row - 2, NULL);

  hide_cursor();
  clear_screen();
  display_scene();

  return 0;
}

int get_winsize() {
  char buff[32];
  int i = 0;
  if(ioctl(1, TIOCGWINSZ, &(win_state.winsize)) == -1) {
    write(1, "\x1b[7\x1b[999B\x1b[999C\x1b[6n\x1b[8", 22);
    while(i < sizeof(buff)) {
      read(0, buff + i, 1);
      if(buff[i] == 'R') break;
      i ++;
    }
    if(sscanf(buff, "\x1b[%hu;%huR", &(win_state.winsize.ws_row), &(win_state.winsize.ws_col)) != 2) {
      fprintf(stderr, "Error: can not get tty window size\n");
      return 1;
    }
  }
  return 0;
}

void display_capture(capture_t* current) {
  uint32_t padd = (uint32_t)(log2((double)context.max_index) / 4.0) + 1;

  if(current->ether_type == 0x806) {
    if(current->protocol == 1) {
      draw_line(0, "\x1b[%sm0x%.*x\x1b[m ARP who-has %u.%u.%u.%u from %u.%u.%u.%u[%x:%x:%x:%x:%x:%x]", (current == win_state.cursor ? "41" : "7"), padd, current->index,
        current->ip_dst[0], current->ip_dst[1], current->ip_dst[2], current->ip_dst[3],
        current->ip_src[0], current->ip_src[1], current->ip_src[2], current->ip_src[3],
        current->ether_src[0], current->ether_src[1], current->ether_src[2], current->ether_src[3], current->ether_src[4], current->ether_src[5]);
    } else {
      draw_line(0, "\x1b[%sm0x%.*x\x1b[m ARP is-at %u.%u.%u.%u[%x:%x:%x:%x:%x:%x] to %u.%u.%u.%u[%x:%x:%x:%x:%x:%x]", (current == win_state.cursor ? "41" : "7"), padd, current->index,
        current->ether_src[0], current->ether_src[1], current->ether_src[2], current->ether_src[3], current->ether_src[4], current->ether_src[5],
        current->ether_dst[0], current->ether_dst[1], current->ether_dst[2], current->ether_dst[3], current->ether_dst[4], current->ether_dst[5],
        current->ip_src[0], current->ip_src[1], current->ip_src[2], current->ip_src[3],
        current->ip_dst[0], current->ip_dst[1], current->ip_dst[2], current->ip_dst[3]);
    }
  } else if(current->ether_type == 0x800) {

    // resolve hostnames
    struct hostent *hp_src, *hp_dst;
    hp_src = gethostbyaddr((void*)current->ip_src, 4, AF_INET);
    hp_dst = gethostbyaddr((void*)current->ip_dst, 4, AF_INET);
    char host_src[NI_MAXHOST + 16], host_dst[NI_MAXHOST + 16];
    if(hp_src) sprintf(host_src, "[\033[1m%s\033[m]", hp_src->h_name);
    else host_src[0] = 0;
    if(hp_dst) sprintf(host_dst, "[\033[1m%s\033[m]", hp_dst->h_name);
    else host_dst[0] = 0;

    switch(current->protocol) {
      case 1:
        draw_line(0, "\x1b[%sm0x%.*x\x1b[m ICMP from %u.%u.%u.%u%s to %u.%u.%u.%u%s", (current == win_state.cursor ? "41" : "7"), padd, current->index,
          current->ip_src[0], current->ip_src[1], current->ip_src[2], current->ip_src[3], host_src,
          current->ip_dst[0], current->ip_dst[1], current->ip_dst[2], current->ip_dst[3], host_dst);
        break;
      case 6:
      case 17:
        draw_line(0, "\x1b[%sm0x%.*x\x1b[m %s from %u.%u.%u.%u%s port %hu to %u.%u.%u.%u%s port %hu", (current == win_state.cursor ? "41" : "7"), padd, current->index, (current->protocol == 6 ? "TCP" : "UDP"),
          current->ip_src[0], current->ip_src[1], current->ip_src[2], current->ip_src[3], host_src, current->port_src,
          current->ip_dst[0], current->ip_dst[1], current->ip_dst[2], current->ip_dst[3], host_dst, current->port_dst);
          break;
      default:
      draw_line(0, "\x1b[%sm0x%.*x\x1b[m IP from %u.%u.%u.%u%s to %u.%u.%u.%u%s, protocol %hhu", (current == win_state.cursor ? "41" : "7"), padd, current->index,
        current->ip_src[0], current->ip_src[1], current->ip_src[2], current->ip_src[3], host_src,
        current->ip_dst[0], current->ip_dst[1], current->ip_dst[2], current->ip_dst[3], host_dst, current->protocol);
    }
  } else {
    draw_line(0, "\x1b[%sm0x%.*x\x1b[m Frame from %x:%x:%x:%x:%x:%x to %x:%x:%x:%x:%x:%x, ether-type 0x%x", (current == win_state.cursor ? "41" : "7"), padd, current->index,
      current->ether_src[0], current->ether_src[1], current->ether_src[2], current->ether_src[3], current->ether_src[4], current->ether_src[5],
      current->ether_dst[0], current->ether_dst[1], current->ether_dst[2], current->ether_dst[3], current->ether_dst[4], current->ether_dst[5],
      current->ether_type);
  }
}

void display_scene() {
  int len, i;
  char buff[64];

  // draw header
  uint32_t row_len = MIN(win_state.winsize.ws_col, LINE_BUFF_LEN);
  memset(win_state.buff, ' ', row_len);
  // printf filename
  len = snprintf(win_state.buff, row_len, "File: %s", win_state.filename);
  if(len < row_len) win_state.buff[len] = ' ';
  // printf spoofy
  uint32_t margin;
  if(win_state.view == VIEW_LIST) len = snprintf(buff, sizeof(buff), "Captures list");
  else len = snprintf(buff, sizeof(buff), "Capture 0x%x", win_state.cursor->index);
  margin = (row_len - len) / 2;
  len = snprintf(win_state.buff + margin, row_len - margin, "%s", buff);
  if(len + margin < row_len) win_state.buff[margin + len] = ' ';
  // printf captures count
  len = snprintf(buff, sizeof(buff), "filtered: %u/%u", context.filtered_len, context.capture_len);
  margin = MAX(row_len - len, 0);
  len = snprintf(win_state.buff + margin, row_len, "%s", buff);
  write(1, "\x1b[H\x1b[K\x1b[7m", 10);
  write(1, win_state.buff, row_len);
  write(1, "\x1b[m\n\r", 5);

  // display scene
  if(win_state.view == VIEW_LIST) {
    capture_t* current = context.capture_current;
    if(! win_state.cursor) {
        win_state.cursor = context.capture_current;
        win_state.cursor_row = 0;
    }

    i = 1;
    while(current && i < win_state.winsize.ws_row - 1) {
      display_capture(current);
      i ++;
      current = current->next;
    }
    while(i < win_state.winsize.ws_row - 1) {
      write(1, "\x1b[K\n\r", 5);
      i ++;
    }
  } else {
    display_packet_summary();
  }

  // draw footer
  memset(win_state.buff, ' ', row_len);
  len = snprintf(win_state.buff, row_len, "^q - Exit");
  if(len < row_len) win_state.buff[len] = ' ';
  write(1, "\x1b[K\x1b[7m", 7);
  write(1, win_state.buff, row_len);
  write(1, "\x1b[m", 3);
}

int setup_raw_mode() {
  struct termios raw;
  if(tcgetattr(0, &(win_state.save)) == -1) {
    perror("tcgetattr");
    return 1;
  }
  raw = win_state.save;
  raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
  raw.c_oflag &= ~(OPOST);
  raw.c_cflag |= (CS8);
  raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
  if(tcsetattr(0, TCSAFLUSH, &raw) == -1) {
    perror("tcsetattr");
    return 1;
  }
  return 0;
}

void move_cursor(uint8_t cmd) {
  if(cmd == CUR_UP && win_state.cursor) {
    if(win_state.cursor_row > 0)  { // move cursor in window
      win_state.cursor_row--;
      win_state.cursor = win_state.cursor->previous;
    } else { // move cursor out of window
      move_capture_set_index(-1, win_state.winsize.ws_row - 2);
      win_state.cursor = context.capture_current;
    }
  } else if (win_state.cursor) {
    if(win_state.cursor_row < win_state.winsize.ws_row - 3) {
      win_state.cursor_row++;
      win_state.cursor = win_state.cursor->next;
    } else {
      move_capture_set_index(1, win_state.winsize.ws_row - 2);
      win_state.cursor = win_state.cursor->next;
    }
  }
}

void sigwinch_handler(int sig) {
  get_winsize();

  // move cursor if out of screen
  while(win_state.cursor_row >= win_state.winsize.ws_row - 2) {
    win_state.cursor_row --;
    if(win_state.cursor) win_state.cursor = win_state.cursor->previous;
  }

  complete_capture_set(win_state.winsize.ws_row - 2);

  display_scene();
}

int reset_screen() {
  if(tcsetattr(0, TCSAFLUSH, &(win_state.save)) == -1) {
    perror("tcsetattr");
    return 1;
  }
  free(win_state.buff);
  show_cursor();
  clear_screen();
  write(1, "\x1b[H", 3);
  return 0;
}
