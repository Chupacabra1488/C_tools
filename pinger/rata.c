#include "rata.h"

int main(int argc,char** argv)
{
    int status;
    struct sockaddr_in target_addr;
    socklen_t addr_len=sizeof(struct sockaddr_in);
    struct hostent* host_st=NULL;
    memset(&target_addr,0,addr_len);
    target_addr.sin_family=AF_INET;
    status=check_arguments(argc,argv);
    if(status==NAME_EXIT_STATUS)
    {
        host_st=gethostbyname(argv[2]);
        if(host_st==NULL)
        {
            fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        target_addr.sin_addr=*((struct in_addr*)host_st->h_addr_list[0]);
    }
    if(status==IP_EXIT_STATUS)
    {
        target_addr.sin_addr.s_addr=inet_addr(argv[2]);
    }
    printf("\t\t==== Ping of %s ====\n\n",inet_ntoa(target_addr.sin_addr));
    printf("**** ICMP request is trying:\n");
    icmp_ping(&target_addr);
    icmp_read(target_addr.sin_addr.s_addr);
    printf("\n----------------------------------------------------\n\n");
    printf("**** UDP request is trying:\n");
    udp_pinger(&target_addr);
    udp_read(target_addr.sin_addr.s_addr);
    printf("\n----------------------------------------------------\n\n");

    return 0;
}