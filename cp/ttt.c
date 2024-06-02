#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <utmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BUFFER_SIZE 128
#define FILE_MODE 0644

int main(int argc,char** argv)
{
    if(argc != 3)
    {
        printf("Usage: <%s> <source file> <destination file>\n",argv[0]);
    }

    int source_fd;
    source_fd = open(argv[1],O_RDONLY);
    if(source_fd == -1)
    {
        fprintf(stderr,"Error of open calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    int dest_fd;
    dest_fd = open(argv[2],O_CREAT | O_WRONLY,FILE_MODE);
    if(dest_fd == -1)
    {
        fprintf(stderr,"Error of open calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    ssize_t num_of_bytes;
    char buffer[BUFFER_SIZE];
    while((num_of_bytes = read(source_fd,buffer,BUFFER_SIZE)) > 0)
    {
        if(write(dest_fd,buffer,num_of_bytes) == -1)
        {
            fprintf(stderr,"Error of write calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        memset(buffer,0,BUFFER_SIZE);
    }

    close(source_fd);
    close(dest_fd);
    return 0;
}