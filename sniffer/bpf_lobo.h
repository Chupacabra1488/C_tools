#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

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

void bpf_set_arp(const int fd);
void bpf_set_ip(const int fd);
void bpf_set_pup(const int fd);
void bpf_set_rarp(const int fd);
void bpf_set_at(const int fd);
void bpf_set_aarp(const int fd);
void bpf_set_vlan(const int fd);
void bpf_set_ipx(const int fd);
void bpf_set_ipv6(const int fd);
void bpf_set_loopback(const int fd);
void bpf_set_ip_addr(const in_addr_t addr,const int fd);
void bpf_set_two_ip_addr(const in_addr_t first_ip,const in_addr_t second_ip,
const int fd);
void bpf_set_tcp(const int fd);
void bpf_set_udp(const int fd);
void bpf_set_icmp(const int fd);
void bpf_set_port(const u_int16_t port,const int fd);
void show_help();