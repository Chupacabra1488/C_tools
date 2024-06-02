#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <linux/filter.h>
#include <curses.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>

#define TRUE 1
#define FALSE 0
#define STRING_SIZE 64
#define TIME_SIZE 6

void print_number(const int number,char* str);
void print_colon(char* str);
void set_time(int* array,const struct tm* tt);
void set_date(const struct tm* time_st,char* str);