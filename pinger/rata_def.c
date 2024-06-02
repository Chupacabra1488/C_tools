#include "rata.h"

void print_help()
{
    printf("==== Welcome to ping by Chupacabra. ====\n");
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

void icmp_ping(struct sockaddr_in* target_addr)
{
    int sock_fd;
    int status;
    char buffer[BUFFER_SIZE];
    sock_fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    check_function(sock_fd,"socket");
    memset(buffer,0,BUFFER_SIZE);
    const int on=1;
    status=setsockopt(sock_fd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));
    check_function(status,"setsockopt");

    icmp_hdr* icmp=NULL;
    size_t icmp_len=sizeof(icmp_hdr);
    struct timeval* time=NULL;
    size_t packet_length=0;
    icmp=(icmp_hdr*)buffer;
    icmp->code_of_message=ECHO_CODE;
    icmp->type_of_message=ECHO_REQUEST;
    icmp->identification=0;
    icmp->sequence=0;
    icmp->check_sum=0;
    time=(struct timeval*)(buffer+icmp_len);
    status=gettimeofday(time,NULL);
    check_function(status,"gettimeofday");
    packet_length=icmp_len+sizeof(struct timeval);
    icmp->check_sum=get_check_sum((unsigned short*)buffer,packet_length);

    status=sendto(sock_fd,buffer,packet_length,0,(struct sockaddr*)target_addr,
    sizeof(struct sockaddr_in));
    check_function(status,"sendto");
}

void bpf_set_icmp(const int fd)
{
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETHERNET_IP,0,3), 
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS,23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,IPPROTO_ICMP,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0)
    };

    struct sock_fprog prog={
        .len=6,
        .filter=code
    };

    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    if(status==-1)
    {
        fprintf(stderr,"Error of setsockopt calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void icmp_read(const in_addr_t addr)
{
    int sock_fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
    bpf_set_icmp(sock_fd);
    int status;
    ssize_t num_of_bytes;
    char buffer[BUFFER_SIZE];
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sock_fd,&set);
    struct timeval time;
    time.tv_sec=5;
    time.tv_usec=0;
    struct in_addr address;
    address.s_addr=addr;

    while(TRUE)
    {
        status=select(sock_fd+1,&set,NULL,NULL,&time);
        if(status>0)
        {
            memset(buffer,0,BUFFER_SIZE);
            num_of_bytes=recvfrom(sock_fd,buffer,BUFFER_SIZE,0,NULL,NULL);
            check_function(num_of_bytes,"recvfrom");
            if(check_ip(buffer,num_of_bytes,addr))
            {
                print_icmp(buffer,num_of_bytes,&address);
                break;
            }
        }
        else if(status==0)
        {
            printf("Host %s didn't answer.\n",inet_ntoa(address));
            break;
        }
        else
        {
            fprintf(stderr,"Error of select calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    close(sock_fd);
}

bool_t check_ip(const char* buffer,size_t len,const in_addr_t addr)
{
    if(len<(sizeof(eth_hdr)+sizeof(ip_hdr)))
    {
        printf("Too small packet.\n");
        exit(EXIT_FAILURE);
    }
    ip_hdr* ip=(ip_hdr*)(buffer+sizeof(eth_hdr));
    if(ip->source_addr.s_addr==addr) return TRUE;
    else return FALSE;
}

void print_icmp(const char* buffer,size_t len,struct in_addr* addr)
{
    size_t data_offset=sizeof(eth_hdr)+sizeof(ip_hdr);
    icmp_hdr* icmp=(icmp_hdr*)(buffer+data_offset);
    struct timeval* recv_time=(struct timeval*)(buffer+data_offset+sizeof(icmp_hdr));
    struct timeval curr_time;
    gettimeofday(&curr_time,NULL);
    double ttl=get_time(recv_time,&curr_time);
    if(icmp->code_of_message==ECHO_CODE && icmp->type_of_message==ECHO_REPLY)
    {
        printf("Host %s is working now. Time - %lf sec\n",inet_ntoa(*addr),ttl);
    }
    else
    {
        printf("Host %s is unreachable: code - %u, type - %u\n",
        inet_ntoa(*addr),icmp->code_of_message,icmp->type_of_message);
    }
}

void udp_pinger(struct sockaddr_in* addr)
{
    socklen_t addr_len=sizeof(struct sockaddr_in);
    u_int16_t port_number;
    int sock_fd;
    sock_fd=socket(AF_INET,SOCK_DGRAM,0);
    check_function(sock_fd,"socket");
    const size_t buffer_len=sizeof(struct timeval);
    struct timeval* _time=NULL;
    srand(time(NULL));
    int status;
    char buffer[buffer_len];
    _time=(struct timeval*)buffer;
    
    for(size_t i=0;i<5;++i)
    {
        
        port_number=rand()%(60000-10000+1)+10000;
        addr->sin_port=htons(port_number);
        addr->sin_family=AF_INET;
        status=gettimeofday(_time,NULL);
        check_function(status,"gettimeofday");
        status=sendto(sock_fd,buffer,buffer_len,0,(struct sockaddr*)addr,addr_len);
        check_function(status,"sendto");
    }
    close(sock_fd);
}

void udp_read(const in_addr_t addr)
{
    int sock_fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
    bpf_set_icmp(sock_fd);
    int status;
    ssize_t num_of_bytes;
    char buffer[BUFFER_SIZE];
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sock_fd,&set);
    struct timeval time;
    time.tv_sec=5;
    time.tv_usec=0;
    struct in_addr address;
    address.s_addr=addr;

    while(TRUE)
    {
        status=select(sock_fd+1,&set,NULL,NULL,&time);
        if(status>0)
        {
            memset(buffer,0,BUFFER_SIZE);
            num_of_bytes=recvfrom(sock_fd,buffer,BUFFER_SIZE,0,NULL,NULL);
            check_function(num_of_bytes,"recvfrom");
            if(check_ip(buffer,num_of_bytes,addr))
            {
                print_udp(buffer,num_of_bytes,&address);
                break;
            }
        }
        else if(status==0)
        {
            printf("Host %s didn't answer.\n",inet_ntoa(address));
            break;
        }
        else
        {
            fprintf(stderr,"Error of select calling: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    close(sock_fd);
}

void print_udp(const char* buffer,ssize_t len,struct in_addr* addr)
{
    ip_hdr* ip=(ip_hdr*)(buffer+sizeof(eth_hdr));
    size_t ip_len=ip->header_lenght<<2;
    size_t data_offset=sizeof(eth_hdr)+ip_len;
    icmp_hdr* icmp=(icmp_hdr*)(buffer+data_offset);
    data_offset+=sizeof(icmp_hdr);
    data_offset+=sizeof(udp_hdr);
    struct timeval* recv_time=(struct timeval*)(buffer+data_offset+ip_len);
    struct timeval curr_time;
    gettimeofday(&curr_time,NULL);
    double ttl=get_time(recv_time,&curr_time);
    if(icmp->code_of_message==DESTINATION_UNREACHABLE
     && icmp->type_of_message==PORT_UNREACHABLE)
    {
        printf("Host %s is working now. Time - %lf sec\n",inet_ntoa(*addr),ttl);
    }
    else
    {
        printf("Host %s is unreachable: code - %u, type - %u\n",
        inet_ntoa(*addr),icmp->code_of_message,icmp->type_of_message);
    }
}