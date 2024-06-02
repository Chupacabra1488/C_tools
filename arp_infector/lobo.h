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
//#include <netpacket/packet.h>
#include <linux/filter.h>

#define TRUE 1
#define FALSE 0
#define BUFFER_SIZE 1500
#define SEND_SIZE 128
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_CODE 0
#define MAC_ADDR_LEN 6
#define DEVICE "wlp3s0"
#define PORT_NUM 7501
#define ETHERNET_PUP 0x0200 //    Xerox PUP
#define ETHERNET_SPRITE 0x0500 //   Sprite
#define ETHERNET_IP 0x0800 //   IP
#define ETHERNET_ARP 0x0806 //  ARP
#define ETHERNET_RARP 0x8035 // Reverse ARP
#define ETHERNET_AT 0x809B //   AppleTalk protocol
#define ETHERNET_AARP 0x80F3 // AppleTalk ARP
#define ETHERNET_VLAN 0x8100 // IEEE 802.1Q VLAN tagging
#define ETHERNET_IPX 0x8137 // IPX
#define ETHERNET_IPV6 0x86dd // IP protocol version 6
#define ETHERNET_LOOPBACK 0x9000 //used to test interfaces
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define IP_ADDR_LEN 4
#define ARP_PACKET_LEN 42
#define ARP_HDR_ETHERNET 1

struct ethernet_header
{
    u_int8_t dest_addr[MAC_ADDR_LEN];
    u_int8_t source_addr[MAC_ADDR_LEN];
    u_int16_t protocol;
};

struct ip_header
{
    unsigned char header_lenght:4,
                  version:4;
    u_int8_t type_of_service;
    u_int16_t total_lenght;
    u_int16_t identification;
    u_int16_t frag_off;
    u_int8_t time_to_live;
    u_int8_t protocol;
    u_int16_t check_sum;
    struct in_addr source_addr;
    struct in_addr dest_addr;
};

struct icmp_header
{
    u_int8_t type_of_message;
    u_int8_t code_of_message;
    u_int16_t check_sum;
    u_int16_t identification;
    u_int16_t sequence;
};

struct pseudo_header
{
    struct in_addr sourde_addr;
    struct in_addr dest_addr;
    u_int8_t zero_field;
    u_int8_t protocol;
    u_int16_t total_length;
};

struct udp_header
{
    u_int16_t source_port;
    u_int16_t dest_port;
    u_int16_t length;
    u_int16_t check_sum;
};

struct tcp_header
{
    u_int16_t source_port;
    u_int16_t dest_port;
    u_int32_t seq_number;
    u_int32_t ack_number;
    u_int16_t data_offset:4,
              reserved:4,
              cwr:1,
              ece:1,
              urg:1,
              ack:1,
              psh:1,
              rst:1,
              syn:1,
              fin:1;
    u_int16_t window_size;
    u_int16_t check_sum;
    u_int16_t urg_ptr;
};

struct arp_header
{
    u_int16_t hw_type;
    u_int16_t proto_type;
    u_int8_t hw_addr_len;
    u_int8_t proto_addr_len;
    u_int16_t opt_code;
    u_int8_t sender_hwaddr[MAC_ADDR_LEN];
    u_int8_t sender_ipaddr[IP_ADDR_LEN];
    u_int8_t target_hwaddr[MAC_ADDR_LEN];
    u_int8_t target_ipaddr[IP_ADDR_LEN];
};

typedef struct ethernet_header eth_hdr;
typedef struct ip_header ip_hdr;
typedef struct icmp_header icmp_hdr;
typedef struct pseudo_header ps_hdr;
typedef struct udp_header udp_hdr;
typedef struct tcp_header tcp_hdr;
typedef struct arp_header arp_hdr;

void fill_struct(struct sockaddr_ll* addr);
void check_function(const int status,const char* func_name);
void fill_buffer(char* buffer,const char* addr,const int fd);
void print_arp(const char* buffer,size_t len);
void arp_infector(const int fd,const char* addr_name,const char* false_addr);
void print_data(const char* buffer,ssize_t len);