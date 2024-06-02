#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <utmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void print_utmp(const struct utmp* utmp_st);

int main(void)
{
    struct utmp utmp_st;
    size_t utmp_len = sizeof(struct utmp);
    int utmp_fd;
    utmp_fd = open(UTMP_FILE,O_RDONLY);
    if(utmp_fd == -1)
    {
        fprintf(stderr,"Error of open calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    while(read(utmp_fd,&utmp_st,utmp_len) == utmp_len)
    {
        print_utmp(&utmp_st);
    }

    close(utmp_fd);
    return 0;
}

void print_utmp(const struct utmp* utmp_st)
{
    time_t tt = utmp_st->ut_tv.tv_sec;
    char* ct = ctime(&tt);
    ct[strlen(ct)-1] = ' ';
    printf("%s %s\t%s (%s)\n",utmp_st->ut_user,utmp_st->ut_line,ct,utmp_st->ut_host);
}