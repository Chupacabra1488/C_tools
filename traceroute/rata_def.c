#include "rata.h"

void print_help()
{
    printf("==== Welcome to traceroute by Chupacabra. ====\n");
    printf("\tKey --name or -n <target name>.\n");
    printf("\tKey --ip or -i <ip address>.\n");
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

int check_arguments(int argc,char** argv)
{
    if(argc<2 || argc>3)
    {
        fprintf(stderr,"Usage ping_ch --help or -h.\n");
        exit(EXIT_FAILURE);
    }
    if(argc==2 && (strcmp(argv[1],"--help")==0 || strcmp(argv[1],"-h")==0))
    {
        print_help();
    }
    else if(argc==3 && (strcmp(argv[1],"--name")==0 || strcmp(argv[1],"-n")==0)) 
    {
        return NAME_EXIT_STATUS;
    }
    else if(argc==3 && (strcmp(argv[1],"--ip")==0 || strcmp(argv[1],"-i")==0))
    {
        return IP_EXIT_STATUS;
    }
    else
    {
        print_help();
        exit(EXIT_FAILURE);
    }
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

int pinger(const int sock_fd,int ttl,struct sockaddr_in* addr)
{
    int exit_status=HOP_ADDR;
    char buffer[BUFFER_SIZE];
    size_t buffer_len;
    buffer_len=fill_buffer(buffer);
    int status;
    status=setsockopt(sock_fd,SOL_IP,IP_TTL,&ttl,sizeof(ttl));
    check_function(status,"setsockopt");
    socklen_t addr_len=sizeof(struct sockaddr_in);

    status=sendto(sock_fd,buffer,buffer_len,0,(struct sockaddr*)addr,addr_len);
    check_function(status,"sendto");

    ssize_t num_of_bytes=0;
    fd_set set;
    struct timeval _time;
    _time.tv_sec=1;
    _time.tv_usec=0;
    FD_ZERO(&set);
    FD_SET(sock_fd,&set);
    char recv_buffer[BUFFER_SIZE];
    struct sockaddr_in recv_addr;

    status=select(sock_fd+1,&set,NULL,NULL,&_time);
    if(status>0)
    {
        memset(recv_buffer,0,BUFFER_SIZE);
        memset(&recv_addr,0,addr_len);
        num_of_bytes=recvfrom(sock_fd,recv_buffer,BUFFER_SIZE,0,
        (struct sockaddr*)&recv_addr,&addr_len);
        check_function(status,"recvfrom");
        exit_status=print_data(recv_buffer,num_of_bytes,&recv_addr);
    }
    else if(status==0)
    {
        printf("*** *** *** *** *** *** *** *** *** *** *** ***\n");
    }
    else
    {
        fprintf(stderr,"Error of select calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    return exit_status;
}

size_t fill_buffer(char* buffer)
{
    size_t length=0;
    icmp_hdr* icmp=(icmp_hdr*)buffer;
    icmp->code_of_message=ECHO_CODE;
    icmp->type_of_message=ECHO_REQUEST;
    icmp->identification=14;
    icmp->sequence=0;
    icmp->check_sum=0;
    size_t icmp_len=sizeof(icmp_hdr);

    struct timeval* _time=(struct timeval*)(buffer+icmp_len);
    int status;
    status=gettimeofday(_time,NULL);
    check_function(status,"gettimeofday");
    length=icmp_len+sizeof(struct timeval);

    icmp->check_sum=get_check_sum((unsigned short*)buffer,length);

    return length;
}

int print_data(const char* buffer,ssize_t len,struct sockaddr_in* addr)
{
    struct hostent* host_st=NULL;
    int exit_status=0;
    struct in_addr address=addr->sin_addr;
        char name[256];
    memset(name,0,256);
    strcpy(name,"unknown");
    host_st=gethostbyaddr((void*)&address,4,AF_INET);
    if(host_st)
    {
        memset(name,0,256);
        strncpy(name,host_st->h_name,256);
    }
    struct timeval curr_time;
    int status;
    status=gettimeofday(&curr_time,NULL);
    check_function(status,"gettimeofday");
    double time_to_live;
    size_t time_len=sizeof(struct timeval);
    struct timeval* recv_time;
    size_t time_offset=len-time_len;
    recv_time=(struct timeval*)(buffer+time_offset);
    time_to_live=get_time(recv_time,&curr_time);

    ip_hdr* ip=(ip_hdr*)buffer;
    size_t ip_len=ip->header_lenght<<2;
    
    icmp_hdr* icmp=(icmp_hdr*)(buffer+ip_len);
    if((icmp->code_of_message==TIME_EXCEEDED_CODE_0 || icmp->code_of_message==TIME_EXCEEDED_CODE_1) &&
    icmp->type_of_message==TIME_EXCEEDED_TYPE)
    {
        exit_status=HOP_ADDR;
    }
    else if(icmp->code_of_message==ECHO_CODE && icmp->type_of_message==ECHO_REPLY)
    {
        exit_status=GOAL_ADDR;
    }

    printf("Host - %s  < %s > \n",inet_ntoa(addr->sin_addr),name);
    return exit_status;
}