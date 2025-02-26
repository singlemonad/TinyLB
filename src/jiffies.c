//
// Created by tedqu on 24-11-24.
//

#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "../include/jiffies.h"

#define HZ 1000

uint64_t get_jiffies(void)
{
    struct timespec ts;
    struct timeval  tv;
    uint64_t jiffies;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0) {
        return -1;
    }

    if (gettimeofday(&tv, NULL)) {
        return -1;
    }

    jiffies = ts.tv_sec * HZ + (uint64_t)ts.tv_nsec * HZ / 1E9;

    return jiffies;
}
