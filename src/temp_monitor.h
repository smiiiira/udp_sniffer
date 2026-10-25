#ifndef TEMP_MONITOR_H
#define TEMP_MONITOR_H
#include <pthread.h>

#define TEMP_POLL_INTERVAL 10

struct temp_stats {
    double current_temp;
    double min_temp;
    double max_temp;
    double sum_temp;
    int count;
    pthread_mutex_t lock;
};

extern struct temp_stats temp;
extern int capture_running; // Флаг берется из main.c

void* temperature_polling_thread(void *arg);

#endif