#include "temp_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

struct temp_stats temp = {0, 999.0, -999.0, 0.0, 0, PTHREAD_MUTEX_INITIALIZER};

// Эти переменные определяются в main.c и передаются через extern
extern char snmp_target_ip[16];
extern char ssh_password[64];
extern FILE *temp_log_file;

double get_temperature_ssh(const char *ip, const char *password) {
    char command[512];
    char buffer[128];
    double t = -999.0;
    FILE *fp;

    snprintf(command, sizeof(command),
             "sshpass -p '%s' ssh -o StrictHostKeyChecking=no admin@%s \"show env temperature\" 2>/dev/null | grep 'Current Temperature' | awk '{print $4}' | tr -d 'C'",
             password, ip);

    fp = popen(command, "r");
    if (fp == NULL) return -999.0;

    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        t = atof(buffer);
    }
    pclose(fp);
    return t;
}

void *temperature_polling_thread(void *arg) {
    time_t last_poll = 0;
    char timestamp[32];

    while (capture_running) {
        time_t now = time(NULL);
        if (now - last_poll >= TEMP_POLL_INTERVAL) {
            last_poll = now;

            double t = get_temperature_ssh(snmp_target_ip, ssh_password);

            if (t > -100.0) {
                pthread_mutex_lock(&temp.lock);
                temp.current_temp = t;
                temp.count++;
                temp.sum_temp += t;
                if (t < temp.min_temp) temp.min_temp = t;
                if (t > temp.max_temp) temp.max_temp = t;
                pthread_mutex_unlock(&temp.lock);

                if (temp_log_file) {
                    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
                    fprintf(temp_log_file, "%s,%.1f\n", timestamp, t);
                    fflush(temp_log_file);
                }
                printf("[SSH] Температура: %.1f°C\n", t);
            } else {
                fprintf(stderr, "[SSH] Не удалось получить температуру\n");
            }
        }
        sleep(1);
    }
    return NULL;
}