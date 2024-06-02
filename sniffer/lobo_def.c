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

void set_illegible_mode(const int fd)
{
    struct ifreq ifr_st;
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    
    status=ioctl(fd,SIOCGIFFLAGS,&ifr_st);
    check_function(status,"ioctl");

    ifr_st.ifr_flags |= IFF_PROMISC;

    status=ioctl(fd,SIOCSIFFLAGS,&ifr_st);
    check_function(status,"ioctl");
}

void show_packet(const char* buffer,size_t len,const int num_of_packet)
{
    printf("==== ==== PACKET %6d : %4ld BYTES ==== ====\n",num_of_packet,len);
    printf("\t**** ETHERNET HEADER ****\n");
    eth_hdr* eth=NULL;
    size_t eth_len=sizeof(eth_hdr);
    size_t data_offset=0;

    eth=(eth_hdr*)buffer;
    data_offset+=eth_len;
    printf("\t\tDest hwaddr - ");
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        printf("%.2x",eth->dest_addr[i]);
        if(i==MAC_ADDR_LEN-1) printf("\n");
        else printf(":");
    }
    printf("\t\tSource hwaddr - ");
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        printf("%.2x",eth->source_addr[i]);
        if(i==MAC_ADDR_LEN-1) printf("\n");
        else printf(":");
    }
    printf("\t\tProtocol - 0x%x ",ntohs(eth->protocol));
    switch (ntohs(eth->protocol))
    {
    case ETHERNET_PUP:
        printf("Xerox PUP\n");
        break;
    case ETHERNET_SPRITE:
        printf("Sprite\n");
        break;
    case ETHERNET_IP:
        printf("IP version 4\n");
        print_ip(buffer+data_offset,len-data_offset);
        break;
    case ETHERNET_ARP:
        printf("ARP\n");
        print_arp(buffer+data_offset,len-data_offset);
        break;
    case ETHERNET_RARP:
        printf("RARP\n");
        break;
    case ETHERNET_AT:
        printf("AppleTalk protocol\n");
        break;
    case ETHERNET_AARP:
        printf("AppleTalk ARP\n");
        break;
    case ETHERNET_VLAN:
        printf("IEEE 802.1Q VLAN tagging\n");
        break;
    case ETHERNET_IPX:
        printf("IPX\n");
        break;
    case ETHERNET_IPV6:
        printf("IP version 6\n");
        break;
    case ETHERNET_LOOPBACK:
        printf("used to test interfaces\n");
        break;
    default:
        printf("Unknown\n");
        break;
    }
}

void print_ip(const char* buffer,size_t len)
{
    printf("\t**** IP HEADER ****\n");
    ip_hdr* ip=NULL;
    size_t ip_len;
    size_t data_offset=0;
    
    ip=(ip_hdr*)buffer;
    ip_len=ip->header_lenght<<2;
    data_offset+=ip_len;
    printf("\t\tHeader length - %u\n",ip->header_lenght<<2);
    printf("\t\tVersion - %u\n",ip->version);
    printf("\t\tTOS - %u\n",ip->type_of_service);
    printf("\t\tTotal length - %d\n",ntohs(ip->total_lenght));
    printf("\t\tID - %d\n",ntohs(ip->identification));
    printf("\t\tFrag and offset - %d\n",ntohs(ip->frag_off));
    printf("\t\tTime to live - %u\n",ip->time_to_live);
    printf("\t\tProtocol - %u ",ip->protocol);
    switch (ip->protocol)
    {
    case IPPROTO_ICMP:
        printf("(ICMP)\n");
        break;
    case IPPROTO_IGMP:
        printf("(IGMP)\n");
        break;
    case IPPROTO_TCP:
        printf("(TCP)\n");
        break;
    case IPPROTO_UDP:
        printf("(UDP)\n");
        break;
    default:
        printf("(unknown)\n");
        break;
    }
    printf("\t\tCheck sum - %d\n",ip->check_sum);
    printf("\t\tSource addr - %s ",inet_ntoa(ip->source_addr));
    struct hostent* host_st=gethostbyaddr(&ip->source_addr,sizeof(struct in_addr),AF_INET);
    if(host_st==NULL) printf("(unknown)\n");
    else printf("(%s)\n",host_st->h_name);
    printf("\t\tDest addr - %s ",inet_ntoa(ip->dest_addr));
    host_st=gethostbyaddr(&ip->dest_addr,sizeof(struct in_addr),AF_INET);
    if(host_st==NULL) printf("(unknown)\n");
    else printf("(%s)\n",host_st->h_name);
    switch (ip->protocol)
    {
    case IPPROTO_ICMP:
        print_icmp(buffer+data_offset,len-data_offset);
        break;
    case IPPROTO_UDP:
        print_udp(buffer+data_offset,len-data_offset);
        break;
    case IPPROTO_TCP:
        print_tcp(buffer+data_offset,len-data_offset);
        break;
    default:
        break;
    }
}

void print_icmp(const char* buffer,size_t len)
{
    icmp_hdr* icmp=NULL;
    size_t icmp_len=sizeof(icmp_hdr);
    size_t data_offset=0;

    icmp=(icmp_hdr*)buffer;
    printf("\t**** ICMP HEADER ****\n");
    printf("\t\tType of message - %u\n",icmp->type_of_message);
    printf("\t\tCode of message - %u\n",icmp->code_of_message);
    printf("\t\tCheck sum - %d\n",icmp->check_sum);
    printf("\t\tID - %d\n",ntohs(icmp->identification));
    printf("\t\tSequence - %d\n",ntohs(icmp->sequence));
    data_offset+=icmp_len;
    print_data(buffer+data_offset,len-data_offset);
}

void print_udp(const char* buffer,size_t len)
{
    udp_hdr* udp=NULL;
    size_t udp_len=sizeof(udp_hdr);
    size_t data_offset=0;

    udp=(udp_hdr*)buffer;
    printf("\t**** UDP HEADER ****\n");
    printf("\t\tSource port - %d ",ntohs(udp->source_port));
    struct servent* serv_st=NULL;
    serv_st=getservbyport(udp->source_port,"udp");
    if(serv_st==NULL) printf("(unknown)\n");
    else printf("(%s)\n",serv_st->s_name);
    printf("\t\tDest port - %d ",ntohs(udp->dest_port));
    serv_st=getservbyport(udp->dest_port,"udp");
    if(serv_st==NULL) printf("(unknown)\n");
    else printf("(%s)\n",serv_st->s_name);
    printf("\t\tLength - %d\n",ntohs(udp->length));
    printf("\t\tCheck sum - %d\n",udp->check_sum);
    data_offset+=udp_len;
    print_data(buffer+data_offset,len-data_offset);
}

void print_tcp(const char* buffer,size_t len)
{
    tcp_hdr* tcp=NULL;
    size_t tcp_len=sizeof(tcp_hdr);
    size_t data_offset=0;

    tcp=(tcp_hdr*)buffer;
    printf("\t**** TCP HEADER ****\n");
    printf("\t\tSource port - %d ",ntohs(tcp->source_port));
    struct servent* serv_st=NULL;
    serv_st=getservbyport(tcp->source_port,"tcp");
    if(serv_st==NULL) printf("(unknown)\n");
    else printf("(%s)\n",serv_st->s_name);
    printf("\t\tDest port - %d ",ntohs(tcp->dest_port));
    serv_st=getservbyport(tcp->dest_port,"tcp");
    if(serv_st==NULL) printf("(unknown)\n");
    else printf("(%s)\n",serv_st->s_name);
    printf("\t\tSeq number - %d\n",ntohl(tcp->seq_number));
    printf("\t\tAck number - %u\n",ntohl(tcp->ack_number));
    printf("\t\tData offset - %d\n",tcp->data_offset);
    printf("\t\tReserved - %d\n",tcp->reserved);
    printf("\t\tcwr - %d\n",tcp->cwr);
    printf("\t\tece - %d\n",tcp->ece);
    printf("\t\turg - %d\n",tcp->urg);
    printf("\t\tack - %d\n",tcp->ack);
    printf("\t\tpsh - %d\n",tcp->psh);
    printf("\t\trst - %d\n",tcp->rst);
    printf("\t\tsyn - %d\n",tcp->syn);
    printf("\t\tfin - %d\n",tcp->fin);
    printf("\t\tWindow size - %d\n",ntohs(tcp->window_size));
    printf("\t\tCheck sum - %d\n",tcp->check_sum);
    printf("\t\tUrg ptr - %d\n",ntohs(tcp->urg_ptr));
    data_offset+=tcp_len;
    print_data(buffer+data_offset,len-data_offset);
}

void print_data(const char* buffer,size_t len)
{
    printf("\t**** DATA ****\n\t");
    for(size_t i=0;i<len;++i)
    {
        printf("%c ",buffer[i]);
        if((i+1)%16==0 || i==len-1) printf("\n");
    }
}

void set_ip_addr_filter(const char* addr,const int fd)
{
    
    struct in_addr addr_st;
    addr_st.s_addr=inet_addr(addr);
    struct sock_filter code[]={
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS,12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,ETH_P_IP,0,5), 
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,26),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,addr_st.s_addr,2,3),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K,addr_st.s_addr,0,1),
        BPF_STMT(BPF_RET+BPF_K,1500),
        BPF_STMT(BPF_RET+BPF_K,0),
    };
    struct sock_fprog prog=
    {
        .len=8,
        .filter=code,
    };
    int status;
    status=setsockopt(fd,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
    check_function(status,"setsockopt");
}

void print_arp(const char* buffer,size_t len)
{
    arp_hdr* arp=NULL;
    size_t arp_len=sizeof(arp_hdr);
    arp=(arp_hdr*)buffer;
    printf("\t**** ARP HEADER ****\n");
    printf("\t\tHw type - %d\n",ntohs(arp->hw_type));
    printf("\t\tProtocol type - 0x%x\n",ntohs(arp->protocol_type));
    printf("\t\tHw addr len - %u\n",arp->hw_addr_len);
    printf("\t\tProto addr len - %u\n",arp->proto_addr_len);
    printf("\t\tOpt code - %d\n",ntohs(arp->op_code));
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