#include "rata.h"
#include <stdarg.h>

int main(int argc,char** argv)
{
    if(argc != 2)
    {
        fprintf(stderr,"Usage: <%s> <host name>.\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock_fd;
    sock_fd = socket(AF_INET,SOCK_STREAM,0);
    check_function("socket",sock_fd);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    fill_struct(&addr,argv[1]);
    FILE* file;
    const char* file_name = "cgi-bugs.dat";
    file = fopen(file_name,"r");
    if(file == NULL)
    {
        fprintf(stderr,"Error of fopen calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    char buffer[BUF_LEN];
    char send_buffer[BUFFER_LEN];
    char recv_buffer[BUFFER_LEN];
    ssize_t num_of_bytes = 0;
    memset(buffer,0,BUF_LEN);
    char data[BUFFER_LEN];
    int status = 0;

    status = connect(sock_fd,(struct sockaddr*)&addr,addr_len);
    check_function("connect",status);
    int i = 0;

    while(fgets(buffer,BUF_LEN,file))
    {
        buffer[strlen(buffer)-2] = '\0';
        memset(send_buffer,0,BUFFER_LEN);
        sprintf(send_buffer,"GET %s HTTP/1.1\r\nHost: %s:80\r\n\r\n",buffer,argv[1]);
        printf("\t\tNUMBER %d\n",++i);
        printf("==================================================================\n\n");
        printf("Request: \t%s\n",buffer);
        memset(buffer,0,BUF_LEN);
        status = write(sock_fd,send_buffer,strlen(send_buffer));
        check_function("write",status);
        memset(recv_buffer,0,BUFFER_LEN);
        num_of_bytes = read(sock_fd,recv_buffer,BUFFER_LEN);
        check_function("read",num_of_bytes);
        data_parser(recv_buffer,num_of_bytes,data);
        printf("%s\n\n",data);
    }

    fclose(file);
    close(sock_fd);
    return 0;
}      