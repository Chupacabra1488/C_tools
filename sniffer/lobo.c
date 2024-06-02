#include "lobo.h"
#include "bpf_lobo.h"

int main(int argc,char** argv)
{
    if(argc==2 && ((strcmp(argv[1],"-h")==0 ) || strcmp(argv[1],"--help")==0))
    {
        show_help();
        return 0;
    }

    int sock_fd;
    sock_fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    check_function(sock_fd,"socket");
    set_illegible_mode(sock_fd);
    setuid(getuid());

    set_illegible_mode(sock_fd);
    long counter=0;
    struct sockaddr_ll recv_addr;
    socklen_t addr_len=sizeof(struct sockaddr_ll);
    memset(&recv_addr,0,addr_len);
    char recv_buffer[BUFFER_SIZE];
    int num_bytes;
    int status;
    int num_of_pack;
    in_addr_t first_addr;
    in_addr_t second_addr;
    u_int16_t port_num;

    if(argc==2 && (strcmp(argv[1],"-arp")==0)) bpf_set_arp(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-ip")==0)) bpf_set_ip(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-pup")==0)) bpf_set_pup(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-rarp")==0)) bpf_set_rarp(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-at")==0)) bpf_set_at(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-aarp")==0)) bpf_set_aarp(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-vlan")==0)) bpf_set_vlan(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-ipx")==0)) bpf_set_ipx(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-ipv6")==0)) bpf_set_ipv6(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-loopback")==0)) bpf_set_loopback(sock_fd);
    if(argc==3 && (strcmp(argv[1],"-ipaddr")==0))
    {
        first_addr=inet_addr(argv[2]);
        if(first_addr==INADDR_NONE)
        {
            fprintf(stderr,"Error of inet_addr calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        bpf_set_ip_addr(first_addr,sock_fd);
    }
    if(argc==4 && (strcmp(argv[1],"-ipaddr2")==0))
    {
        first_addr=inet_addr(argv[2]);
        if(first_addr==INADDR_NONE)
        {
            fprintf(stderr,"Error of inet_addr calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        second_addr=inet_addr(argv[3]);
        if(second_addr==INADDR_NONE)
        {
            fprintf(stderr,"Error of inet_addr calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        bpf_set_two_ip_addr(first_addr,second_addr,sock_fd);
    }
    if(argc==2 && (strcmp(argv[1],"-tcp")==0)) bpf_set_tcp(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-udp")==0)) bpf_set_udp(sock_fd);
    if(argc==2 && (strcmp(argv[1],"-icmp")==0)) bpf_set_icmp(sock_fd);
    if(argc==3 && (strcmp(argv[1],"-port")==0)) 
    {
        port_num=atoi(argv[2]);
        bpf_set_port(port_num,sock_fd);
    }

    while(TRUE)
    {
        memset(recv_buffer,0,BUFFER_SIZE);
        num_bytes=recvfrom(sock_fd,recv_buffer,BUFFER_SIZE,0,
        (struct sockaddr*)&recv_addr,&addr_len);
        check_function(num_bytes,"recvfrom");

        show_packet(recv_buffer,num_bytes,counter);

        counter++;
        if(argc==3 && (strcmp(argv[1],"-c")==0))
        {
            num_of_pack=atoi(argv[2]);
            if(counter==num_of_pack) break;
        }
    }

    return 0;
}