#include "rata.h"

unsigned short get_check_sum(unsigned short* addr,int len)
{
    unsigned short result;
    unsigned int sum = 0;
    while(len>1)
    {
        sum += *addr++;
        len -= 2;
    }
    if(len==1)
    {
        sum += *(unsigned char*)addr;
    }
    sum = (sum>>16) + (sum & 0xFFFF);
    sum += (sum>>16);
    result = ~sum;
    return result;
}

void set_illegible_mode(const int fd)
{
    struct ifreq ifr_st;
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;

    status = ioctl(fd,SIOCGIFFLAGS,&ifr_st);
    if(status==-1)
    {
        fprintf(stderr,"Error of ioctl calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    ifr_st.ifr_flags |= IFF_PROMISC;
    status = ioctl(fd,SIOCSIFFLAGS,&ifr_st);
    if(status==-1)
    {
        fprintf(stderr,"Error of ioctl calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void help_function()
{
    printf("\t==== ==== ADDRESS COLLECTOR ==== ====\n\n");
    printf("\tUsage: <./rata> <options>\n");
    printf("\n\t**************************\n\n");
    printf("\tOptions:\n");
    printf("\t\t<-h> or <--help> - Read 'help' and exit.\n");
    printf("\t\t<-c> or <--count> - Collect 'count' ip addresses\n");
    printf("\t\t<-t> or <--time> - Working 'time' seconds\n");
    printf("\t\t<-f> or <--file> <file name> - Read to 'file name'\n");
    printf("\t\tTo exit press Ctrl C");
    printf("\n\t==== ==== \tEND\t ==== ====\n");
}

bool_t set_data(const char* buffer,size_t buf_len,data_st* data)
{
    bool_t flag = FALSE;
    size_t eth_len = sizeof(eth_hdr);
    if(buf_len < (eth_len + sizeof(ip_hdr))) return flag;
    eth_hdr* eth = (eth_hdr*)buffer;
    if(eth->protocol != ntohs(ETHERNET_IP)) return flag;
    ip_hdr* ip = (ip_hdr*)(buffer + eth_len);
    data->dest_addr = ip->dest_addr;
    data->source_addr = ip->source_addr;
    flag = TRUE;
    return flag;
}

void get_hunter_address(struct in_addr* hunter_addr,const int fd)
{
    struct ifreq ifr_st;
    strcpy(ifr_st.ifr_name,DEVICE);
    int status;
    status = ioctl(fd,SIOCGIFADDR,&ifr_st);
    if(status == -1)
    {
        fprintf(stderr,"Error of ioctl calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in* addr;
    addr = (struct sockaddr_in*)(&ifr_st.ifr_addr);
    hunter_addr->s_addr = addr->sin_addr.s_addr;
}

void check_data(const data_st* data,int* index,pack_st* packets,const struct in_addr* hunter_addr)
{
    bool_t flag1 = FALSE;
    bool_t flag2 = FALSE;
    struct in_addr local_host;
    local_host.s_addr = inet_addr("127.0.0.1");
    if(data->dest_addr.s_addr != local_host.s_addr && data->dest_addr.s_addr != hunter_addr->s_addr)
    {
        flag1 = TRUE;
        for(size_t i=0;i<(*index);++i)
        {
            if(data->dest_addr.s_addr == packets[i].addr.s_addr)
            {
                flag1 = FALSE;
            }
        }
    }
    else if(data->source_addr.s_addr != local_host.s_addr && data->source_addr.s_addr != hunter_addr->s_addr)
    {
        flag2 = TRUE;
        for(size_t i=0;i<(*index);++i)
        {
            if(data->source_addr.s_addr == packets[i].addr.s_addr)
            {
                flag2 = FALSE;
            }
        }
    }
    struct in_addr address;
    struct hostent* host_st = NULL;
    if(flag1)
    {
        packets[*index].addr.s_addr = data->dest_addr.s_addr;
        address.s_addr = data->dest_addr.s_addr;
        host_st = gethostbyaddr(&address,sizeof(address),AF_INET);
        if(host_st==NULL)
        {
            strcpy(packets[*index].host_name,"Unknown");
        }
        else
        {
            strncpy(packets[*index].host_name,host_st->h_name,NAME_LEN);
        }
        (*index)++;
    }
    else if(flag2)
    {
        packets[*index].addr.s_addr = data->source_addr.s_addr;
        address.s_addr = data->source_addr.s_addr;
        host_st = gethostbyaddr(&address,sizeof(address),AF_INET);
        if(host_st==NULL)
        {
            strcpy(packets[*index].host_name,"Unknown");
        }
        else
        {
            strncpy(packets[*index].host_name,host_st->h_name,NAME_LEN);
        }
        (*index)++;
    }
}

void print_data(const pack_st* packets,int index)
{
    printf("\tCaptured addresses:\n");
    for(size_t i=0;i<index;++i)
    {
        printf("%ld. %s :\t<%s>\n",i+1,inet_ntoa(packets[i].addr),packets[i].host_name);
    }
    printf("\n\t**** **** End **** ****\n");
}

void write_to_file(const char* file_name,const pack_st* packets,int index)
{
    int fd = open(file_name,O_CREAT | O_WRONLY);
    if(fd == -1)
    {
        fprintf(stderr,"Error of open calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    size_t buf_len = index * sizeof(pack_st) * 3;
    char buffer[buf_len];
    memset(buffer,0,buf_len);
    size_t data_offset = 0;
    char buf[sizeof(pack_st)*3];
    for(size_t i=0;i<index;++i)
    {
        sprintf(buf,"%ld. %s :\t<%s>\n",i+1,inet_ntoa(packets[i].addr),packets[i].host_name);
        memcpy(buffer+data_offset,buf,strlen(buf));
        data_offset += strlen(buf);
    }
    int status = write(fd,buffer,strlen(buffer));
    if(status == -1)
    {
        fprintf(stderr,"Error of read calling: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(fd);
}

void parse_arguments(int* counter,int* num_of_sec,char* file_name,const int argc,char** argv)
{
    *counter = PACK_ARR_LEN;
    *num_of_sec = 72000;
    strcpy(file_name,"");
    for(int i=1;i<argc;++i)
    {
        if((strcmp(argv[i],"-h")==0) || (strcmp(argv[i],"--help")==0))
        {
            help_function();
            exit(EXIT_SUCCESS);
        }
        if((strcmp(argv[i],"-c")==0) || (strcmp(argv[i],"--count")==0))
        {
            *counter = atoi(argv[i+1]);
        }
        if((strcmp(argv[i],"-t")==0) || (strcmp(argv[i],"--time")==0))
        {
            *num_of_sec = atoi(argv[i+1]);
        }
        if((strcmp(argv[i],"-f")==0) || (strcmp(argv[i],"--file")==0))
        {
            strncpy(file_name,argv[i+1],NAME_LEN);
        }
    }
}
