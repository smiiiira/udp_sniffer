#include "utils.h"
#include <stdio.h>
#include <time.h>

void clear_screen() { printf("\033[2J\033[H"); }

void get_current_time(char *buf, size_t sz) {
    time_t t; struct tm *tm; time(&t); tm = localtime(&t);
    strftime(buf, sz, "%H:%M:%S", tm);
}

void format_number(long num, char *buf) {
    if (num < 1000) sprintf(buf, "%ld", num);
    else if (num < 1000000) sprintf(buf, "%.1fK", num / 1000.0);
    else sprintf(buf, "%.1fM", num / 1000000.0);
}

void format_period(double ms, char *buf) {
    if (ms < 1.0) sprintf(buf, "%.1fμs", ms * 1000);
    else if (ms < 1000) sprintf(buf, "%.2fms", ms);
    else sprintf(buf, "%.3fs", ms / 1000);
}