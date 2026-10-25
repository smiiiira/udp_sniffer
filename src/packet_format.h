#ifndef PACKET_FORMAT_H
#define PACKET_FORMAT_H

#include <time.h>
#include <sys/time.h>

#pragma pack(push, 1)
struct headerbuffer {
    unsigned char flagbegin;
    unsigned char proto;
    int indinput;
    int indoutput;
    short sizemessage;
    long numberpack;
    struct timespec timepack;
    struct timeval timereadsys;
    struct timespec timeread;
};

struct footerbuffer {
    int ksumm;
    char flagend;
    char flagend1;
};
#pragma pack(pop)

#endif // PACKET_FORMAT_H