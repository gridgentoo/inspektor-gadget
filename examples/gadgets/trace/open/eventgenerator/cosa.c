#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

static volatile int keepRunning = 1;

void intHandler(int dummy) {
    keepRunning = 0;
}

int main(int argc, char *argv[]) {
        int fd;
        long delayns = 10;
        unsigned long int counter = 0;

        if (argc > 1) {
                delayns = atoi(argv[1]);
        }

        struct timespec t = {
               .tv_sec = 0,        /* seconds */
               .tv_nsec = delayns,       /* nanoseconds */
        };

        signal(SIGINT, intHandler);

        while(keepRunning) {
                if (delayns) {
                        nanosleep(&t, NULL);
                }

                counter++;

                fd = open("/dev/null", O_RDONLY);
                if (fd < 0) {
                        printf("error opening file\n");
                        continue;
                }

                close(fd);
        }


        printf("%ld operations were executed\n", counter);

        return 0;
}