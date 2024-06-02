#include "rata.h"

int main(int argc,char** argv)
{
    int sock_fd;
    sock_fd = socket(AF_INET,SOCK_STREAM,0);
    check_function("socket",sock_fd);

    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    fill_struct(sock_fd,&server_addr);
    printf("[*] Server is listening on %s:%d\n",inet_ntoa(server_addr.sin_addr),
    ntohs(server_addr.sin_port));

    int status;
    int on = 1;
    status = setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int));
    check_function("setsockopt",status);
    status = bind(sock_fd,(struct sockaddr*)&server_addr,addr_len);
    check_function("bind",status);

    status = listen(sock_fd,5);
    check_function("listen",status);
    struct sockaddr_in client_addr;

    int client_sock_fd;
    char recv_buffer[BUFFER_LEN];
    ssize_t num_of_bytes;
    char buffer[BUFFER_LEN];

    while(TRUE)
    {
        memset(&client_addr,0,addr_len);
        client_sock_fd = accept(sock_fd,(struct sockaddr*)&client_addr,&addr_len);
        check_function("accept",client_sock_fd);
        num_of_bytes = read(client_sock_fd,recv_buffer,BUFFER_LEN);
        check_function("read",num_of_bytes);
        printf("Accepted connection with: %s:%d",inet_ntoa(client_addr.sin_addr),
        ntohs(client_addr.sin_port));
        printf("\n%s\n",recv_buffer);
        fill_buffer(&client_addr,buffer);
        num_of_bytes = write(client_sock_fd,buffer,strlen(buffer));
        check_function("write",num_of_bytes);
        close(client_sock_fd);
    }

    close(sock_fd);
    return 0;
}