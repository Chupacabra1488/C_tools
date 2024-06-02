#include "bpf_lobo.h"

void bpf_set_arp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_ARP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_ip(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_pup(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_PUP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_sprite(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_SPRITE,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_rarp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_RARP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_at(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_AT,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_aarp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_AARP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_vlan(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_VLAN,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_ipx(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IPX,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_ipv6(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IPV6,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_loopback(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_LOOPBACK,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=4,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_ip_addr(const in_addr_t addr,const int fd)
{
    const u_int32_t test_addr=ntohl(addr);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,5), 
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,test_addr,2,0), 
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,test_addr,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=8,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_two_ip_addr(const in_addr_t first_ip,const in_addr_t second_ip,
const int fd)
{
    u_int32_t first_addr=ntohl(first_ip);
    u_int32_t second_addr=ntohl(second_ip);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,7), 
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,first_addr,1,0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,second_addr,0,4),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,first_addr,1,0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,second_addr,0,1), 
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=10,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_tcp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,3), 
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS,23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,IPPROTO_TCP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=6,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_udp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,3), 
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS,23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,IPPROTO_UDP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=6,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_icmp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,3), 
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS,23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,IPPROTO_ICMP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=6,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void bpf_set_port(const u_int16_t port,const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,9),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS,23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,IPPROTO_TCP,1,0), 
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,IPPROTO_UDP,0,6), 
        BPF_STMT(BPF_LDX+BPF_B+BPF_MSH,14),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND,14),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,port,2,0),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND,16),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,port,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=12,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void show_help()
{
    printf("==== ==== ==== ==== CHUPACABRA SNIFFER ==== ==== ==== ====\n");
    printf("\tUsage: <./lobo> <options>\n");
    printf("\tOptions:\n");
    printf("\t1. -c <count> - 'numbers of packets'\n");
    printf("\t2. -arp - 'arp filter'\n");
    printf("\t3. -ip - 'ip filter'\n");
    printf("\t4. -pup -'pup filter'\n");
    printf("\t5. -rarp - 'rarp filter'\n");
    printf("\t6. -at - 'at filter'\n");
    printf("\t7. -aarp - 'aarp filter'\n");
    printf("\t8. -vlan - 'vlan filter'\n");
    printf("\t9. -ipx - 'ipx filter'\n");
    printf("\t10. -ipv6 - 'ipv6 filter'\n");
    printf("\t11. -loopback - 'loopback filter'\n");
    printf("\t12. -ipaddr <IP address> - 'filter of IP address'\n");
    printf("\t13. -ipaddr2 <first IP> <second IP> 'filter between two IP'\n");
    printf("\t14. -tcp - 'tcp filter'\n");
    printf("\t15. -udp - 'udp filter'\n");
    printf("\t16. -icmp - 'icmp filter'\n");
    printf("\t17. -port <port number> - 'port filter'\n");
    printf("==== ==== ==== ==== ====  END  ==== ==== ==== ==== ====\n");
}