#include "stats.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

struct global_stats stats = {0};

double timeval_diff_stats(const struct timeval *t1, const struct timeval *t2) {
    double sec = t1->tv_sec - t2->tv_sec;
    double usec = (t1->tv_usec - t2->tv_usec) / 1000000.0;
    return sec + usec;
}

struct ip_port_stats* find_or_create_ip_port(const char* ip, uint16_t port) {
    for (int i = 0; i < stats.ip_count; i++) {
        if (stats.ips[i].port == port && strcmp(stats.ips[i].src_ip, ip) == 0)
            return &stats.ips[i];
    }
    if (stats.ip_count < MAX_IPS) {
        struct ip_port_stats *s = &stats.ips[stats.ip_count++];
        memset(s, 0, sizeof(struct ip_port_stats)); // Инициализация нулями
        strcpy(s->src_ip, ip);
        s->port = port;
        return s;
    }
    return NULL;
}

void update_period_stats(struct ip_port_stats *s, const struct timeval *now) {
    if (s->packets <= 1) {
        s->prev_time = *now;
        return;
    }
    double interval_ms = timeval_diff_stats(now, &s->prev_time) * 1000.0;
    s->total_interval_time += interval_ms / 1000.0;
    s->interval_count++;
    if (interval_ms < s->min_period_ms || s->packets == 2) s->min_period_ms = interval_ms;
    if (interval_ms > s->max_period_ms) s->max_period_ms = interval_ms;
    if (s->interval_count > 0) {
        s->avg_period_ms = (s->total_interval_time * 1000.0) / s->interval_count;
        double dev = fabs(interval_ms - s->avg_period_ms);
        s->jitter_ms = (s->jitter_ms * (s->interval_count - 1) + dev) / s->interval_count;
    }
    s->prev_time = *now;
}

// Функция сохранения вынесена сюда. Данные о температуре передаются как аргументы
void save_results(const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) return;

    fprintf(f, "# Глобальная статистика\n");
    fprintf(f, "total_packets,%ld\n", stats.total_packets);
    fprintf(f, "total_bytes,%ld\n", stats.total_bytes);
    fprintf(f, "total_payload_bytes,%ld\n", stats.total_payload_bytes);
    fprintf(f, "dropped_by_kernel_start,%ld\n", stats.dropped_by_kernel_start);
    fprintf(f, "dropped_by_kernel_end,%ld\n", stats.dropped_by_kernel_end);
    fprintf(f, "dropped_by_kernel,%ld\n", stats.dropped_by_kernel);

    fprintf(f, "\n# IP:ПОРТ статистика\n");
    fprintf(f, "ip,port,packets,bytes,avg_period_ms,min_period_ms,max_period_ms,jitter_ms,first_seq,last_seq,loss_count\n");
    for (int i = 0; i < stats.ip_count; i++) {
        struct ip_port_stats *s = &stats.ips[i];
        if (s->packets > 0) {
            fprintf(f, "%s,%d,%ld,%ld,%.2f,%.2f,%.2f,%.2f,%ld,%ld,%ld\n",
                    s->src_ip, s->port, s->packets, s->bytes,
                    s->avg_period_ms, s->min_period_ms, s->max_period_ms, s->jitter_ms,
                    s->first_seq, s->last_seq, s->loss_count);
        }
    }
    fclose(f);
}