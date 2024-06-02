#include "rata.h"

int main(int argc,char** argv)
{
    struct hostent* host_st=NULL;
    struct sockaddr_in target_addr;
    socklen_t addr_len=sizeof(struct sockaddr_in);
    memset(&target_addr,0,addr_len);
    int status;
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
    else if(status==IP_EXIT_STATUS)
    {
        target_addr.sin_addr.s_addr=inet_addr(argv[2]);
    }
    else
    {   
        print_help();
    }

    int sock_fd;
    sock_fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    check_function(sock_fd,"socket");
    setuid(getuid());
    int ttl=0;
    target_addr.sin_family=AF_INET;
    int exit_status;

    for(int i=1;i<256;++i)
    {
        ttl=i;
        printf("%d. ",i);
        exit_status=pinger(sock_fd,ttl,&target_addr);
        if(exit_status==GOAL_ADDR) break;
    }

    close(sock_fd);
    return 0;
}