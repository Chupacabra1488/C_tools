#include "lobo.h"
#include <gcrypt.h>

int main(void)
{
    struct servent* serv_st=NULL;
    serv_st=getservbyport(htons(80),"tcp");
    if(serv_st==NULL)
    {
        fprintf(stderr,"Error of getservbyport calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    printf("%s\n",serv_st->s_name);

    return 0;
}