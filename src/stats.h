#ifndef STATS_H
#define STATS_H

#include <stdint.h>
#include <sys/time.h>

#define MAX_IPS 200
#define SEQ_OVERFLOW_THRESHOLD 1000000000L

struct ip_port_stats {
    uint16_t port;
    char src_ip[16];
    long packets;
    long bytes;
    struct timeval first_seen;
    struct timeval last_seen;
    long first_seq;
    long last_seq;
    long loss_count;
    int has_seq;
    double total_interval_time;
    long interval_count;
    double avg_period_ms;
    double min_period_ms;
    double max_period_ms;
    double jitter_ms;
    struct timeval prev_time;
};

struct global_stats {
    long total_packets;
    long total_bytes;
    long total_payload_bytes;
    long dropped_by_kernel_start;
    long dropped_by_kernel_end;
    long dropped_by_kernel;
    struct ip_port_stats ips[MAX_IPS];
    int ip_count;
};

// Глобальная переменная статистики (доступна из других файлов)
extern struct global_stats stats;

struct ip_port_stats* find_or_create_ip_port(const char* ip, uint16_t port);
void update_period_stats(struct ip_port_stats *s, const struct timeval *now);
void save_results(const char *filename);

#endif // STATS_H