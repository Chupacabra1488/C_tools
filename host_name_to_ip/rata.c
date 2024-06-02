#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

int main(int argc,char** argv)
{
    if(argc != 2)
    {
        fprintf(stderr,"Usage: <%s> <host name>\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    struct hostent* host_st = NULL;
    host_st = gethostbyname(argv[1]);
    if(host_st == NULL)
    {
        fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("Officail name:\t%s\n",host_st->h_name);
    printf("Aliases:\n");
    char** ptr = host_st->h_aliases;
    while(*ptr != NULL)
    {
        printf("%s\n",*ptr);
        ptr++;
    }
    printf("Addr type:\t%d\n",host_st->h_addrtype);
    printf("Addr length:\t%d\n",host_st->h_length);
    printf("Addresses:\n");
    int counter = 0;
    char str[64];
    for(ptr=host_st->h_addr_list;*ptr!=NULL;++ptr)
    {
        printf("\t%d. %s\n",++counter,inet_ntop(host_st->h_addrtype,*ptr,str,64));
    }

    return 0;
}