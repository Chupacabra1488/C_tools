#include "rata.h"

void check_function(const char* func_name,const int exit_status)
{
    if(exit_status == -1)
    {
        fprintf(stderr,"Error of %s calling: %s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void fill_struct(struct sockaddr_in* addr,char* server)
{
    struct hostent* host_st = NULL;
    host_st = gethostbyname(server);
    if(host_st == NULL)
    {
        fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(addr,0,sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(80);
    addr->sin_addr = *((struct in_addr*)host_st->h_addr_list[0]);
}

bool_t data_parser(const char* buffer,size_t num,char* data)
{
    char buf[BUF_LEN];
    memset(buf,0,BUF_LEN);
    memset(data,0,BUFFER_LEN);
    int i = 0;
    while(TRUE)
    {
        if(buffer[i] == '\n')
        {
            data[i] = '\0';
            break;
        }
        data[i] = buffer[i];
        i++;
    }
}