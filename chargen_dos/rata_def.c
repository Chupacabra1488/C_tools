#include "rata.h"

void print_help()
{
    fprintf(stdout,"<source address> <source port> ");
    fprintf(stdout,"<destination address> <destination port>\n");
    exit(EXIT_SUCCESS);
}

void check_function(int exit_status,char* function_name)
{
    if(exit_status==-1)
    {
        fprintf(stderr,"Error of %s calling: %s\n",function_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

unsigned short get_check_sum(unsigned short* addr,int len)
{
    unsigned short result;
    unsigned int sum=0;
    while(len>1)
    {
        sum+=*addr++;
        len-=2;
    }
    if(len==1)
    {
        sum+=*(unsigned char*)addr;
    }
    sum=(sum>>16)+(sum & 0xFFFF);
    sum+=(sum>>16);
    result=~sum;
    return result;
}

double get_time(const struct timeval* tm_recv,const struct timeval* tm_curr)
{
    struct timeval temp;
    temp.tv_sec=tm_curr->tv_sec-tm_recv->tv_sec;
    temp.tv_usec=tm_curr->tv_usec-tm_recv->tv_usec;
    if(temp.tv_usec<0)
    {
        temp.tv_usec+=1000000;
        temp.tv_sec++;
    }
    int tt=temp.tv_sec*1000000+temp.tv_usec;
    double res=(double)tt/1000000;
    return res;
}

void check_arguments(int argc,char** argv)
{
    if(argc!=5)
    {
        fprintf(stdout,"Usage: %s ",argv[0]);
        print_help();
    }
}

void fill_addr(const char* ip,const char* port,struct sockaddr_in* addr)
{
    struct hostent* host_st=NULL;
    u_int16_t port_number;

    host_st=gethostbyname(ip);
    if(host_st==NULL)
    {
        fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    port_number=atoi(port);

    memset(addr,0,sizeof(struct sockaddr_in));
    addr->sin_addr=*((struct in_addr*)host_st->h_addr_list[0]);
    addr->sin_family=AF_INET;
    addr->sin_port=htons(port_number);
}

void fill_buffer(const struct sockaddr_in* target,const struct sockaddr_in* source,
char* buffer,size_t buf_len)
{
    memset(buffer,0,buf_len);
    ip_hdr* ip=NULL;
    size_t ip_len=0;

    ip=(ip_hdr*)buffer;
    ip->header_lenght=5;
    ip->version=4;
    ip->type_of_service=0;
    ip->total_lenght=htons(sizeof(ip_hdr)+sizeof(udp_hdr));
    ip->identification=0;
    ip->time_to_live=255;
    ip->protocol=IPPROTO_UDP;
    ip->check_sum=0;
    ip->source_addr=source->sin_addr;
    ip->dest_addr=target->sin_addr;
    ip->check_sum=get_check_sum((unsigned short*)buffer,sizeof(ip_hdr));
    ip_len=ip->header_lenght<<2;

    size_t temp_len=sizeof(ps_hdr)+sizeof(udp_hdr);
    char temp_buf[temp_len];
    memset(temp_buf,0,temp_len);

    ps_hdr* ps=(ps_hdr*)temp_buf;
    ps->sourde_addr=source->sin_addr;
    ps->dest_addr=target->sin_addr;
    ps->protocol=IPPROTO_UDP;
    ps->zero_field=0;
    ps->total_length=htons(sizeof(udp_hdr));

    udp_hdr* udp=(udp_hdr*)(temp_buf+sizeof(ps_hdr));
    udp->source_port=source->sin_port;
    udp->dest_port=target->sin_port;
    udp->length=htons(sizeof(udp_hdr));
    udp->check_sum=0;
    udp->check_sum=get_check_sum((unsigned short*)temp_buf,temp_len);

    memcpy(buffer+ip_len,temp_buf+sizeof(ps_hdr),sizeof(udp_hdr));
}