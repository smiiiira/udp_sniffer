#include "output.h"
#include "stats.h"
#include "temp_monitor.h"
#include "utils.h"
#include <stdio.h>
#include <time.h>
#include <pthread.h>

void print_current_stats() {
    char timebuf[32], pktbuf[16], bytebuf[16];
    get_current_time(timebuf, sizeof(timebuf));
    format_number(stats.total_packets, pktbuf);
    format_number(stats.total_payload_bytes, bytebuf);
    clear_screen();

    printf("\n=== ПРОМЫШЛЕННЫЙ UDP АНАЛИЗАТОР v3.4 (SSH+sshpass) ===\n");
    printf("Время: %s | Пакетов: %s | Данные: %s\n", timebuf, pktbuf, bytebuf);
    printf("Активных источников: %d\n", stats.ip_count);

    pthread_mutex_lock(&temp.lock);
    if (temp.count > 0) {
        printf("Температура: %.1f°C (мин: %.1f°, макс: %.1f°)\n",
               temp.current_temp, temp.min_temp, temp.max_temp);
    } else {
        printf("Температура: ожидание данных...\n");
    }
    pthread_mutex_unlock(&temp.lock);

    if (stats.dropped_by_kernel > 0)
        printf("⚠️ ДРОППЫ ЯДРА: %ld\n", stats.dropped_by_kernel);
    printf("------------------------------------------------------------\n");
    printf("%-25s %-15s %-15s %-7s %-6s\n", "IP:Порт", "Пакеты", "Период", "Jitter", "Потери");

    int found = 0;
    for (int i = 0; i < stats.ip_count; i++) {
        struct ip_port_stats *s = &stats.ips[i];
        if (s->port == target_port && s->packets > 0) {
            char ipport[32], pkt[10], period[12], jitter[10], loss[8];
            snprintf(ipport, sizeof(ipport), "%s:%d", s->src_ip, s->port);
            format_number(s->packets, pkt);
            format_period(s->avg_period_ms, period);
            format_period(s->jitter_ms, jitter);
            format_number(s->loss_count, loss);
            printf("\033[1;32m%-20s %-8s %-10s %-8s %-6s\033[0m\n", ipport, pkt, period, jitter, loss);
            found = 1;
        }
    }
    if (!found) printf("нет целевых данных\n");
    printf("\nCtrl+C=выход | Логи: udp_log.csv, results.csv, temperature_log.csv\n");
    fflush(stdout);
}

void print_final_stats() {
    printf("\n\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("✅ ИТОГОВАЯ СТАТИСТИКА v3.4\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Пакетов всего:     %ld\n", stats.total_packets);
    printf("Байт (с загр.):    %ld (%.2f MB)\n", stats.total_bytes, stats.total_bytes/1024.0/1024.0);
    printf("Полезных данных:   %ld (%.2f MB)\n", stats.total_payload_bytes, stats.total_payload_bytes/1024.0/1024.0);

    pthread_mutex_lock(&temp.lock);
    if (temp.count > 0) {
        printf("\n--- СТАТИСТИКА ТЕМПЕРАТУРЫ КОММУТАТОРА ---\n");
        printf("  Всего измерений: %d\n", temp.count);
        printf("  Средняя: %.1f°C\n", temp.sum_temp / temp.count);
        printf("  Минимальная: %.1f°C\n", temp.min_temp);
        printf("  Максимальная: %.1f°C\n", temp.max_temp);
    }
    pthread_mutex_unlock(&temp.lock);

    if (stats.dropped_by_kernel > 0) {
        double drop_pct = (double)stats.dropped_by_kernel / (stats.total_packets + stats.dropped_by_kernel) * 100;
        printf("\n🚨 ОШИБКА! DROPPED_BY_KERNEL=%ld (%.2f%%)\n", stats.dropped_by_kernel, drop_pct);
        printf("   → Увеличьте буферы: ethtool -G <iface> rx 4096 tx 4096\n");
    } else {
        printf("\n✅ DROPPED_BY_KERNEL=0 (ИДЕАЛЬНО)\n");
    }
    
    printf("\n📊 IP:ПОРТ СТАТИСТИКА (порт %d):\n", target_port);
    printf("%-23s %10s %17s %6s %9s %15s\n",
           "IP:Порт", "Пакеты", "Период(ms)", "Jitter", "Min/Max", "Потери");
           
    for (int i = 0; i < stats.ip_count; i++) {
        struct ip_port_stats *s = &stats.ips[i];
        if (s->port == target_port && s->packets > 5) {
            char ipport[32], pkt[10], period[12], jitter[10], minmax[12], loss[10];
            snprintf(ipport, sizeof(ipport), "%s:%d", s->src_ip, s->port);
            format_number(s->packets, pkt);
            format_period(s->avg_period_ms, period);
            format_period(s->jitter_ms, jitter);
            snprintf(minmax, sizeof(minmax), "%.1f/%.1f", s->min_period_ms, s->max_period_ms);
            format_number(s->loss_count, loss);
            printf("\033[1;33m%-18s %8s %10s %8s %10s %8s\033[0m\n",
                   ipport, pkt, period, jitter, minmax, loss);
        }
    }
    printf("═══════════════════════════════════════════════════════════════\n");
}