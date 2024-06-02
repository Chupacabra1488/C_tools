#include "rata.h"

int counter;
int num_of_sec;
char file_name[NAME_LEN];
int fd = 0;
int ind = 0;
pack_st* packets;
void handler(int);

int main(int argc,char** argv)
{
    parse_arguments(&counter,&num_of_sec,file_name,argc,argv);

    int sock_fd;
    sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sock_fd == -1)
    {
        fprintf(stderr,"Error of socket calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    setuid(getuid());
    if(strlen(file_name))
    {
        fd = open(file_name,O_CREAT | O_WRONLY);
        if(fd == -1)
        {
            fprintf(stderr,"Error of open calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    char buffer[BUFFER_LEN];
    ssize_t num_of_bytes;
    data_st data;
    bool_t flag;
    struct in_addr hunter_addr;
    get_hunter_address(&hunter_addr,sock_fd);
    packets = (pack_st*)malloc(PACK_ARR_LEN * sizeof(pack_st));
    struct itimerval timer;
    timer.it_value.tv_sec = num_of_sec;
    timer.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL,&timer,NULL);
    struct sigaction act;
    act.sa_handler = &handler;
    sigaction(SIGINT,&act,NULL);
    sigaction(SIGALRM,&act,NULL);

    while(TRUE)
    {
        flag = FALSE;
        if(ind == counter) break;
        memset(buffer,0,BUFFER_LEN);
        num_of_bytes = recvfrom(sock_fd,buffer,BUFFER_LEN,0,NULL,NULL);
        if(num_of_bytes == -1)
        {
            fprintf(stderr,"Error of recvfrom calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        flag = set_data(buffer,num_of_bytes,&data);
        if(flag)
        {
            check_data(&data,&ind,packets,&hunter_addr);
        }
    }

    if(fd) write_to_file(file_name,packets,ind);
    else print_data(packets,ind);

    return 0;
}

void handler(int signum)
{
    if(signum == SIGINT)
    {
        if(fd) write_to_file(file_name,packets,ind);
        else print_data(packets,ind);
        exit(EXIT_SUCCESS);
    }
    if(signum == SIGALRM)
    {
        if(fd) write_to_file(file_name,packets,ind);
        else print_data(packets,ind);
        exit(EXIT_SUCCESS);
    }
}