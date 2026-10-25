#ifndef UTILS_H
#define UTILS_H
#include <stddef.h>

void clear_screen();
void get_current_time(char *buf, size_t sz);
void format_number(long num, char *buf);
void format_period(double ms, char *buf);

#endif