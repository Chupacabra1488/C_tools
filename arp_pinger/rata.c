#include "rata.h"

int main(int argc,char** argv)
{
    if(argc==2 && (strcmp(argv[1],"-h"))==0) help_function();
    struct in_addr first;
    struct in_addr last;
    int num_of_addrs = check_arguments(argc,argv,&first,&last);
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(struct sockaddr_ll);
    fill_struct(&addr);
    int sock_fd;
    sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
    check_function("socket",sock_fd);
    setuid(getuid());
    char buffer[ARP_PACKET_LEN];

    int status;
    ssize_t num_of_bytes;
    char recv_buf[BUFFER_LEN];
    struct sockaddr_ll recv_addr;

    while(num_of_addrs--)
    {
        fill_struct(&addr);
        fill_buffer(buffer,&first,sock_fd);
        status = sendto(sock_fd,buffer,ARP_PACKET_LEN,0,(struct sockaddr*)&addr,addr_len);
        check_function("sendto",status);
        fd_set set;
        struct timeval _time;
        _time.tv_sec = 0;
        _time.tv_usec = 500000;
        FD_ZERO(&set);
        FD_SET(sock_fd,&set);
        memset(&recv_addr,0,addr_len);

        status = select(sock_fd+1,&set,NULL,NULL,&_time);
        if(status>0)
        {
            memset(recv_buf,0,BUFFER_LEN);
            num_of_bytes = recvfrom(sock_fd,recv_buf,BUFFER_LEN,0,
            (struct sockaddr*)&recv_addr,&addr_len);
            check_function("recvfrom",num_of_bytes);
            if(check_addr(recv_buf,&first))
            {
                //printf("Host:\t%s\texists.\n",inet_ntoa(first));
                print_mac(recv_buf);
            }
        }
        else if(status==0)
        {
            printf("Host:\t%s\tdoesn't exists.\n",inet_ntoa(first));
        }
        else
        {
            fprintf(stderr,"Error of select calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        increment_adrr(&first);
    }

    return 0;
}