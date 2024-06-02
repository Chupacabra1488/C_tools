#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <utmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#define DIR_LEN 256

void print_dir(const char* dir_name);
void mode_to_str(const mode_t mode,char* str);
char* uid_to_name(const uid_t uid);
char* gid_to_name(const gid_t gid);
char* time_to_str(const time_t* time);

int main(int argc,char** argv)
{
    char directory[DIR_LEN];
    memset(directory,0,DIR_LEN);
    if(argc == 1) strncpy(directory,".",DIR_LEN);
    else strncpy(directory,argv[1],DIR_LEN);

    DIR* dir_ptr = NULL;
    dir_ptr = opendir(directory);
    if(dir_ptr == NULL)
    {
        fprintf(stderr,"Cannot open the directory <%s> : %s\n",directory,strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct dirent* dir_st = NULL;
    int counter = 0;

    while((dir_st = readdir(dir_ptr)) != NULL)
    {
        print_dir(dir_st->d_name);
    }

    closedir(dir_ptr);
    return 0;
}

void print_dir(const char* dir_name)
{
    struct stat stat_st;
    int status;
    status = stat(dir_name,&stat_st);
    if(status == -1)
    {
        fprintf(stderr,"Error of stat calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    /*printf("\t*******************************\n");
    printf("st_dev: \t%ld\n",stat_st.st_dev);
    printf("st_ino: \t%ld\n",stat_st.st_ino);
    printf("st_mode:\t%d\n",stat_st.st_mode);
    printf("st_nlink:\t%ld\n",stat_st.st_nlink);
    printf("st_uid: \t%d\n",stat_st.st_uid);
    printf("st_gid: \t%d\n",stat_st.st_gid);
    printf("st_rdev:\t%ld\n",stat_st.st_rdev);
    printf("st_size:\t%ld\n",stat_st.st_size);
    printf("st_blksize:\t%ld\n",stat_st.st_blksize);
    printf("st_blocks:\t%ld\n",stat_st.st_blocks);
    printf("st_atime:\t%ld\n",stat_st.st_atime);
    printf("st_mtime:\t%ld\n",stat_st.st_mtime);
    printf("st_ctime:\t%ld\n",stat_st.st_ctime);
    printf("\n");*/
    char mode_str[10];
    memset(mode_str,0,10);
    mode_to_str(stat_st.st_mode,mode_str);
    printf("%s ",mode_str);
    printf("%d ",(int)stat_st.st_nlink);
    printf("%12s ",uid_to_name(stat_st.st_uid));
    printf("%12s ",gid_to_name(stat_st.st_gid));
    printf("%8ld ",stat_st.st_size);
    printf("%s ",time_to_str(&stat_st.st_ctime));
    printf("%s ",dir_name);
    printf("\n");
}

void mode_to_str(const mode_t mode,char* str)
{
    strcpy(str,"----------");
    if(S_ISDIR(mode)) str[0] = 'd';
    if(S_ISCHR(mode)) str[0] = 'c';
    if(S_ISBLK(mode)) str[0] = 'b';
    if(mode & S_IRUSR) str[1] = 'r';
    if(mode & S_IWUSR) str[2] = 'w';
    if(mode & S_IXUSR) str[3] = 'x';
    if(mode & S_IRGRP) str[4] = 'r';
    if(mode & S_IWGRP) str[5] = 'w';
    if(mode & S_IXGRP) str[6] = 'x';
    if(mode & S_IROTH) str[7] = 'r';
    if(mode & S_IWOTH) str[8] = 'w';
    if(mode & S_IXOTH) str[9] = 'x';
}

char* uid_to_name(const uid_t uid)
{
    return getpwuid(uid)->pw_name;
}

char* gid_to_name(const gid_t gid)
{
    return getgrgid(gid)->gr_name;
}

char* time_to_str(const time_t* time)
{
    char* temp = ctime(time);
    size_t size = strlen(temp);
    temp[size-1] = '\0';
    return temp;
}