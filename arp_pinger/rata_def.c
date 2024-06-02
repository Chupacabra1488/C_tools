#include "rata.h"

void set_password(char* hash)
{
    printf("Please set the password -> ");
    char password[PASSWORD_LEN];
    memset(password,0,PASSWORD_LEN);

    struct termios term_attr;
    memset(&term_attr,0,sizeof(term_attr));
    int status;
    status = tcgetattr(STDIN_FILENO,&term_attr);
    if(status == -1)
    {
        fprintf(stderr,"Error of tcgetattr calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    term_attr.c_lflag &= ~ECHO;
    term_attr.c_lflag &= ~ICANON;
    status = tcsetattr(STDIN_FILENO,TCSANOW,&term_attr);
    if(status == -1)
    {
        fprintf(stderr,"Error of tcsetattr calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    char c;
    u_int16_t counter = 0;
    u_int32_t i = 0;
    while(TRUE)
    {
        c = getchar();
        printf("*");
        if(c == (char)10 || counter == (PASSWORD_LEN - 1)) break;
        password[i] = c;
        counter++;
        i++;
    }
    term_attr.c_lflag |= ECHO;
    term_attr.c_lflag |= ICANON;
    status = tcsetattr(STDIN_FILENO,TCSANOW,&term_attr);
    if(status == -1)
    {
        fprintf(stderr,"Error of tcsetattr calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    MD5(password,strlen(password),hash);
}

void check_function(const char* function,const int exit_status)
{
    if(exit_status == -1)
    {
        fprintf(stderr,"Error of %s calling: %s.\n",function,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void fill_struct(struct sockaddr_ll* addr)
{
    struct ifreq ifr_st;
    memset(&ifr_st,0,sizeof(struct ifreq));
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    int fd;
    fd = socket(AF_INET,SOCK_STREAM,0);
    check_function("socket",fd);
    status = ioctl(fd,SIOCGIFINDEX,&ifr_st);
    check_function("ioctl",status);
    addr->sll_ifindex = ifr_st.ifr_ifindex;
    addr->sll_halen = MAC_ADDR_LEN;
    addr->sll_family = AF_PACKET;
    status = ioctl(fd,SIOCGIFHWADDR,&ifr_st);
    check_function("ioctl",status);
    u_char* ptr = NULL;
    ptr = (u_char*)(&ifr_st.ifr_hwaddr.sa_data);
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        addr->sll_addr[i] = ptr[i];
    }
}

void help_function()
{
    printf("==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ====\n");
    printf("==== ==== ====          ARP PINGER           ==== ==== ====\n");
    printf("==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ====\n\n\n");
    printf("-a <IP address>\t\t-\tping Ip address\n");
    printf("-d <first Ip> <second Ip>\t-\tping range Ip\n\n\n");
    printf("==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ====\n");
    printf("==== ==== ====                END            ==== ==== ====\n");
    printf("==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ==== ====\n");
    exit(EXIT_SUCCESS);
}

void increment_adrr(struct in_addr* addr)
{
    addr->s_addr = ntohl(addr->s_addr);
    addr->s_addr ++;
    addr->s_addr = htonl(addr->s_addr);
}

int check_arguments(int argc,char** argv,struct in_addr* first,struct in_addr* last)
{
    if(argc == 3 && (strcmp(argv[1],"-a"))==0)
    {
        first->s_addr = inet_addr(argv[2]);
        last->s_addr = inet_addr(argv[2]);
    }
    else if(argc == 4 && (strcmp(argv[1],"-d"))==0)
    {
        first->s_addr = inet_addr(argv[2]);
        last->s_addr = inet_addr(argv[3]);
    }
    else
    {
        printf("Usage: <%s> -h.\n",argv[0]);
        exit(EXIT_FAILURE);
    }

    int num_of_addrs = 1;
    while(TRUE)
    {
        if(first->s_addr == last->s_addr) break;
        increment_adrr(first);
        num_of_addrs++;
    }
    first->s_addr = inet_addr(argv[2]);
    return num_of_addrs;
}

void fill_buffer(char* buffer,const struct in_addr* addr,const int sock_fd)
{
    memset(buffer,0,ARP_PACKET_LEN);
    eth_hdr* eth = NULL;
    size_t eth_len = sizeof(eth_hdr);

    eth = (eth_hdr*)buffer;
    eth->protocol = htons(ETH_P_ARP);
    for(size_t i=0;i<MAC_ADDR_LEN;++i) eth->dest_addr[i] = 0xff;
    struct ifreq ifr_st;
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    status = ioctl(sock_fd,SIOCGIFHWADDR,&ifr_st);
    check_function("ioctl",status);
    u_int8_t* ptr = (u_int8_t*)&ifr_st.ifr_hwaddr.sa_data;
    for(size_t i=0;i<MAC_ADDR_LEN;++i) eth->source_addr[i] = ptr[i];

    arp_hdr* arp = NULL;
    size_t arp_len = sizeof(arp_hdr);
    arp = (arp_hdr*)(buffer+eth_len);
    arp->hw_type = htons(ARP_HDR_ETHERNET);
    arp->proto_type = htons(ETH_P_IP);
    arp->hw_addr_len = MAC_ADDR_LEN;
    arp->proto_addr_len = IP_ADDR_LEN;
    arp->opt_code = htons(ARP_REQUEST);
    for(size_t i=0;i<MAC_ADDR_LEN;++i) arp->sender_hwaddr[i] = eth->source_addr[i];
    for(size_t i=0;i<MAC_ADDR_LEN;++i) arp->target_hwaddr[i] = 0x00;
    status = ioctl(sock_fd,SIOCGIFADDR,&ifr_st);
    check_function("ioctl",status);
    struct sockaddr_in* addr_st;
    addr_st = (struct sockaddr_in*)&ifr_st.ifr_addr;
    ptr = (u_int8_t*)&addr_st->sin_addr.s_addr;
    for(size_t i=0;i<IP_ADDR_LEN;++i) arp->sender_ipaddr[i] = ptr[i];
    ptr = (u_int8_t*)&addr->s_addr;
    for(size_t i=0;i<IP_ADDR_LEN;++i) arp->target_ipaddr[i] = ptr[i];
}

bool_t check_addr(const char* buffer,const struct in_addr* addr)
{
    u_int8_t test_addr[IP_ADDR_LEN];
    u_int8_t* ptr = (u_int8_t*)addr;
    for(size_t i=0;i<IP_ADDR_LEN;++i)
    {
        test_addr[i] = ptr[i];
    }
    arp_hdr* arp = (arp_hdr*)(buffer+sizeof(eth_hdr));
    ptr = (u_int8_t*)arp->sender_ipaddr;
    bool_t check = TRUE;
    for(size_t i=0;i<IP_ADDR_LEN;++i)
    {
        if(ptr[i] != test_addr[i]) check = FALSE;
    }
    return check;
}

void print_mac(const char* buffer)
{
    printf("Host:\t");
    arp_hdr* arp = (arp_hdr*)(buffer+sizeof(eth_hdr));
    for(size_t i=0;i<IP_ADDR_LEN;++i)
    {
        printf("%u",arp->sender_ipaddr[i]);
        if(i==(IP_ADDR_LEN-1)) printf("\t");
        else printf(".");
    }
    printf("with MAC:\t");
    for(size_t i=0;i<MAC_ADDR_LEN;++i)
    {
        printf("%.2x",arp->sender_hwaddr[i]);
        if(i == (MAC_ADDR_LEN-1)) printf("\t");
        else printf(":");
    }
    printf("exists.\n");
}