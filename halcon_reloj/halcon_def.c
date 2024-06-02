#include "halcon.h"

void print_number(const int number,char* str)
{
    if(number>9 || number<0)
    {
        fprintf(stderr,"Incorrect number.\n");
        exit(EXIT_FAILURE);
    }
    memset(str,0,STRING_SIZE);
    if(number==0)
    {
        sprintf(str,"******\n******\n**  **\n**  **\n**  **\n**  **\n**  **\n**  **\n******\n******\n");
    }
    if(number==1)
    {
        sprintf(str,"    **\n    **\n    **\n    **\n    **\n    **\n    **\n    **\n    **\n    **\n");
    }
    if(number==2)
    {
        sprintf(str,"******\n******\n    **\n    **\n******\n******\n**    \n**    \n******\n******\n");
    }
    if(number==3)
    {
        sprintf(str,"******\n******\n    **\n    **\n******\n******\n    **\n    **\n******\n******\n");
    }
    if(number==4)
    {
        sprintf(str,"**  **\n**  **\n**  **\n**  **\n******\n******\n    **\n    **\n    **\n    **\n");
    }
    if(number==5)
    {
        sprintf(str,"******\n******\n**    \n**    \n******\n******\n    **\n    **\n******\n******\n");
    }
    if(number==6)
    {
        sprintf(str,"******\n******\n**    \n**    \n******\n******\n**  **\n**  **\n******\n******\n");
    }
    if(number==7)
    {
        sprintf(str,"******\n******\n    **\n    **\n    **\n    **\n    **\n    **\n    **\n    **\n");
    }
    if(number==8)
    {
        sprintf(str,"******\n******\n**  **\n**  **\n******\n******\n**  **\n**  **\n******\n******\n");
    }
    if(number==9)
    {
        sprintf(str,"******\n******\n**  **\n**  **\n******\n******\n    **\n    **\n    **\n    **\n");
    }
}

void print_colon(char* str)
{
    memset(str,0,STRING_SIZE);
    sprintf(str,"      \n      \n  **  \n  **  \n      \n      \n  **  \n  **  \n      \n      \n");
}

void set_time(int* array,const struct tm* tt)
{
    for(size_t i=0;i<TIME_SIZE;++i) array[i]=0;
    int val;
    int temp;
    val=tt->tm_hour;
    for(int i=0;i<2;++i)
    {
        temp=val%10;
        array[1-i]=temp;
        val/=10;
    }
    val=tt->tm_min;
    for(int i=0;i<2;++i)
    {
        temp=val%10;
        array[3-i]=temp;
        val/=10;
    }
    val=tt->tm_sec;
    for(int i=0;i<2;++i)
    {
        temp=val%10;
        array[5-i]=temp;
        val/=10;
    }
}

void set_date(const struct tm* time_st,char* str)
{
    memset(str,0,STRING_SIZE);
    if(time_st->tm_mon==0)
    {
        sprintf(str,"JANUARY, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==1)
    {
        sprintf(str,"FEBRUARY, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==2)
    {
        sprintf(str,"MARCH, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==3)
    {
        sprintf(str,"APRIL, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==4)
    {
        sprintf(str,"MAY, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==5)
    {
        sprintf(str,"JUNE, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==6)
    {
        sprintf(str,"JULY, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==7)
    {
        sprintf(str,"AUGUST, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==8)
    {
        sprintf(str,"SEPTEMBER, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==9)
    {
        sprintf(str,"OCTOBER, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==10)
    {
        sprintf(str,"NOVEMBER, %d",time_st->tm_mday);
    }
    else if(time_st->tm_mon==11)
    {
        sprintf(str,"DECEMBER, %d",time_st->tm_mday);
    }
    else
    {
        sprintf(str,"FUCK OFF");
    }
}