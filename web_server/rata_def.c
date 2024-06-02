#include "rata.h"

void check_function(const char* func_name,const int exit_status)
{
    if(exit_status == -1)
    {
        fprintf(stderr,"Error of %s calling: %s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void fill_struct(const int fd,struct sockaddr_in* addr)
{
    struct ifreq ifr_st;
    int status;
    memset(&ifr_st,0,sizeof(struct ifreq));
    strcpy(ifr_st.ifr_name,DEVICE);
    status = ioctl(fd,SIOCGIFADDR,&ifr_st);
    check_function("ioctl",status);
    memset(addr,0,sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(PORT_NUMBER);
    struct sockaddr_in* addr_st;
    addr_st = (struct sockaddr_in*)&ifr_st.ifr_addr;
    addr->sin_addr.s_addr = addr_st->sin_addr.s_addr;
}

void fill_buffer(const struct sockaddr_in* addr,char* buffer)
{
    memset(buffer,0,BUFFER_LEN);
    char* temp_buf = (char*)malloc(BUFFER_LEN * sizeof(char));
    int fd;
    fd = open("rata.html",O_RDONLY);
    check_function("open",fd);
    int status;
    status = read(fd,temp_buf,BUFFER_LEN);
    check_function("read",status);
    sprintf(buffer,"HTTP/1.1 200 OK\r\n\r\n%s",temp_buf);
}