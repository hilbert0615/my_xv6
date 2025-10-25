#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "kernel/fs.h"
#include "kernel/stat.h"
#include "user/user.h"

#define NUMBLOCKS 1024

char buf[BSIZE] = { 0 };

int
main(int argc, char *argv[])
{
  int fd;

  for (int i = 0; i < 10; i++) {
    fd = open("alargefile.txt", O_CREATE | O_TRUNC | O_RDWR);
    if (fd < 0) {
      printf("cannot open alargefile.txt\n");
      exit(1);
    }

    for (int b = 0; b < NUMBLOCKS; b++) {
      buf[0] = b & 0xFF;
      if (write(fd, buf, sizeof(buf)) <= 0) {
        printf("write failed at block number %d on attempt %d\n", b, i);
        exit(1);
      }
    }

    close(fd);

    fd = open("alargefile.txt", O_RDONLY);
    if (fd < 0) {
      printf("cannot open alargefile.txt\n");
      exit(1);
    }

    for (int b = 0; b < NUMBLOCKS; b++) {
      if (read(fd, buf, sizeof(buf)) < sizeof(buf)) {
        printf("read failed at block number %d on attempt %d\n", b, i);
        exit(1);
      }
      if (buf[0] != (b & 0xFF)) {
        printf("read returned incorrect data at block number %d on attempt %d\n", b, i);
        exit(1);
      }
    }

    close(fd);
  }

  if (unlink("alargefile.txt") < 0) {
    printf("cannot unlink alargefile.txt\n");
    exit(1);
  }

  printf("passed\n");
  exit(0);
}
