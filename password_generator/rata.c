#include "rata.h"

int main(int argc,char** argv)
{
    srand(time(NULL));
    if(argc!=2)
    {
        fprintf(stderr,"Enter the password's length.\n");
        exit(EXIT_FAILURE);
    }
    int pass_length;
    pass_length=atoi(argv[1]);
    char* password;
    password=(char*)malloc(pass_length*sizeof(char));
    for(size_t i=0;i<pass_length;++i)
    {
        password[i]=get_char();
    }
    fprintf(stdout,"%s\n",password);

    free(password);
    return 0;
}