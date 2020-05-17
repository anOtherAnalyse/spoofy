#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "includes/display.h"
#include "includes/control.h"
#include "includes/parse.h"

void usage(char* cmd) {
  fprintf(stderr, "Usage: %s <dumpfile.pcap>\n", cmd);
}

int main(int argc, char* const argv[]) {
  int err_fd;

  if(argc > 1) {

    // Init
    if(open_pcap_file(argv[1])) return 1;

    // close stderr so errors won't disturb the display
    if((err_fd = open("/dev/null", O_WRONLY)) == -1) {
      perror("open /dev/null");
      return 1;
    }
    close(2); dup(err_fd); // redirect stderr to /dev/null

    if(init_screen(argv[1])) return 1;

    input_loop();

    close_pcap_file();

    // reset tty config
    reset_screen();

  } else usage(argv[0]);
  return 0;
}
