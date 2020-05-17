#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <format.h>

int create_formated_file() {
  if((output_fd = open(filename, O_WRONLY|O_CREAT, 0644)) == -1) {
    perror("open");
    return 1;
  }
  pcap_hdr_t header = {
    .magic_number = 0xa1b2c3d4,
    .version_major = 2,
    .version_minor = 4,
    .thiszone = 0,
    .sigfigs = 0,
    .snaplen = 65535,
    .network = 1
  };
  if(write(output_fd, &header, sizeof(header)) == -1) {
    perror("write");
    return 1;
  }

  return 0;
}

int open_new_capture() {
  uint32_t i;
  struct stat buff;

  if(!(filename = malloc(sizeof(DEFAULT_OUTPUT_PREFIX) + 9))) {
    perror("malloc");
    return 1;
  }

  for(i = 0; i < 999; i ++) {
    sprintf(filename, DEFAULT_OUTPUT_PREFIX"%u.pcap", i);
    if(stat(filename, &buff) == -1) break;
  }

  if(i < 999 && errno != ENOENT) {
    perror("stat");
    return 1;
  }

  return create_formated_file();
}

int open_capture(char* file) {
  filename = file;
  return create_formated_file();
}

void close_capture() {
  if(output_fd > 0) {
    printf("Capture saved to %s\n", filename);
    close(output_fd);
  }
}

int add_capture(char* buff, uint32_t cap_length, uint32_t real_length, struct timeval* time) {
  pcaprec_hdr_t header = {
    .ts_sec = time->tv_sec,
    .ts_usec = time->tv_usec,
    .incl_len = cap_length,
    .orig_len = real_length
  };
  if(write(output_fd, &header, sizeof(header)) == -1 || write(output_fd, buff, cap_length) == -1) {
    perror("write");
    return 1;
  }

  return 0;
}
