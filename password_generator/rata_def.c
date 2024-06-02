#include "rata.h"

char get_char()
{
    int val;
    val=rand()%(126-33+1)+33;
    char res=(char)val;
    return res;
}