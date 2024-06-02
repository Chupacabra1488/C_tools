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

char get_char();