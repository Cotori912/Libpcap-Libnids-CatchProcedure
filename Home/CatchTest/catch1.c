#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <string.h>
#define MAX_LINE_LENGTH 100


void print_ether_header(const u_char *packet);
void print_ip_header(const u_char *packet);
void print_tcp_header(const u_char *packet);
void print_udp_header(const u_char *packet);
void print_arp_header(const u_char *packet);
void print_icmp_header(const u_char *packet);

    FILE *fp;
    char errBuf[PCAP_ERRBUF_SIZE];
    char line[MAX_LINE_LENGTH];
    char config_path[] = "config.txt";
    char * devStr[MAX_LINE_LENGTH];
    char path[MAX_LINE_LENGTH];
    char condition[MAX_LINE_LENGTH];
    char rule[MAX_LINE_LENGTH];
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    struct ether_header *ethernet_header;
    int packetcount = 0;
//extern char * devStr[MAX_LINE_LENGTH];
//extern char path[MAX_LINE_LENGTH];
//extern char condition[MAX_LINE_LENGTH];
//extern char rule[MAX_LINE_LENGTH];
//extern FILE *fp;
//extern char line[MAX_LINE_LENGTH];
//extern char config_path[];

void autotest() {
    printf("Running config.txt...\n");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file: %s\n", config_path);
        exit(EXIT_FAILURE);
    }

    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        // get the first string variable
        if (strstr(line, "devStr=") != NULL) {
            sscanf(line, "devStr=%s", devStr);
        }
        if(strstr(line,"path=")!=NULL){
            sscanf(line,"path=%s",path);
        }
        if (strstr(line,"condition=")!=NULL){
            sscanf(line,"condition=%s",condition);
        }
        if(strstr(line,"rule=")!=NULL){
            sscanf(line,"rule=%s",rule);
        }
    }

    fclose(fp);
}

void handtest(char devStr[], char path[], char condition[], char rule[]) {
    
    printf("请依次输入您想要的参数\n");
    
    printf("请输入网卡名称(例如 eth0):");
    scanf(" %s", devStr);
    
    printf("请输入默认路径(例如 ./packet/pack.pcap):");
    scanf(" %s", path);
    
    printf("请输入程序状态(live or offline):");
    scanf(" %s", condition);
    
    printf("请设置捕获正则(例如 ip tcp ):");
    scanf(" %s", rule);
}

int main() {
    int choice;
    fp = fopen(config_path, "r");
    
    printf("请问是否采用配置文件?\n");
    printf("1.使用配置文件\n");
    printf("2.手动输入\n");
    printf("输入您的选择:");
    scanf("%d", &choice);
    
    switch (choice) {
        case 1:
            autotest();
            printf("已完成配置文件数据调用\n");
            break;
        case 2:
            handtest(devStr,path,condition,rule);
            printf("已完成配置文件数据输入\n");
            break;
        default:
            printf("未知选项\n");
            exit(1);
    }
    
    sleep(1);
    int maxcatch;
    printf("请设置最大捕获包数量:");
    scanf("%d",&maxcatch);
    char anwser;
    printf("请确认您的输入信息是否正确\n");
    printf("网卡:%s\n",devStr);
    printf("路径:%s\n",path);
    printf("状态:%s\n",condition);
    printf("正则:%s\n",rule);
    printf("数量:%d\n",maxcatch);
    
    printf("请问配置是否正确(y/n):");
    scanf(" %c", &anwser);
    if (anwser == 'y'|| anwser == 'Y'){
        printf("即将进行抓包捕获...");
    } else if(anwser == 'n'|| anwser == 'N'){
        printf("即将返回重新修改...");
        sleep(1);
        handtest(devStr,path,condition,rule);
    } else {
        printf("无效输入,即将正常进行捕获...");
    }
    sleep(1);
    
    
    struct bpf_program fb;
    bpf_u_int32 net, mask;
    pcap_t *device; 
    if(strcmp(condition,"live")==0){
    device = pcap_open_live(devStr, BUFSIZ, 1, 1000, errBuf);
    }
    else {
    printf("You are offline!\n");
    device=pcap_open_offline(path,errBuf);
    }
    pcap_dumper_t* out_pcap;
if (pcap_compile(device, &fb, rule, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", rule, pcap_geterr(device));
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(device, &fb) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", rule, pcap_geterr(device));
        return EXIT_FAILURE;
    }

    while (1) {
        packet = pcap_next(device, &packet_header);
        if (packet == NULL) {
            printf("Error capturing packet\n");
            continue;
        }
        ethernet_header = (struct ether_header*) packet;
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_ip_header(packet);
        } 
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_arp_header(packet);
        } else {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            printf("Unknown packet type\n");
        }
        out_pcap  = pcap_dump_open(device,path);
        packetcount++;
        if (packetcount >= maxcatch) {
            break;
        }
    }

    pcap_close(packet);
    return 0;
}

void print_ethernet_header(const u_char *packet) {
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header*) packet;

    printf("Ethernet header:\n");
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_shost[0], ethernet_header->ether_shost[1],
           ethernet_header->ether_shost[2], ethernet_header->ether_shost[3],
           ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1],
           ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3],
           ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
    printf("\tType: %d\n", ntohs(ethernet_header->ether_type));
}

// 打印IP数据包头部信息
void print_ip_header(const u_char *packet)
{
    struct iphdr *ip_header;
    ip_header = (struct iphdr *) packet;

    printf("\n---------- IP Header ----------\n");
    printf("Version: %d\n", ip_header->version);
    printf("Header length: %d bytes\n", ip_header->ihl * 4);
    printf("Type of service: %d\n", ip_header->tos);
    printf("Total length: %d bytes\n", ntohs(ip_header->tot_len));
    printf("Identification: %d\n", ntohs(ip_header->id));
    printf("Flags: %d\n", ntohs(ip_header->frag_off) & 0xE000);
    printf("Fragment offset: %d\n", ntohs(ip_header->frag_off) & 0x1FFF);
    printf("Time to live: %d\n", ip_header->ttl);
    printf("Protocol: ");
    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            printf("TCP\n");
            print_tcp_header(packet + sizeof(struct iphdr));
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            print_udp_header(packet + sizeof(struct iphdr));
            break;
        case IPPROTO_ICMP:
            printf("ICMP\n");
            print_icmp_header(packet + sizeof(struct iphdr));
            break;
        default:
            printf("Unknown\n");
            break;
    }
    printf("Header checksum: %d\n", ntohs(ip_header->check));
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
}

// 打印TCP数据包头部信息
void print_tcp_header(const u_char *packet)
{
    struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr *) packet;

    printf("\n---------- TCP Header ----------\n");
    printf("Source port: %d\n", ntohs(tcp_header->source));
    printf("Destination port: %d\n", ntohs(tcp_header->dest));
    printf("Sequence number: %u\n", ntohl(tcp_header->seq));
    printf("Acknowledgment number: %u\n", ntohl(tcp_header->ack_seq));
    printf("Header length: %d bytes\n", tcp_header->doff * 4);
    printf("Flags: ");
    if (tcp_header->urg)
        printf("U");
    if (tcp_header->ack)
        printf("A");
    if (tcp_header->psh)
        printf("P");
    if (tcp_header->rst)
        printf("R");
    if (tcp_header->syn)
        printf("S");
    if (tcp_header->fin)
        printf("F");
    printf("\n");
    printf("Window size: %d\n", ntohs(tcp_header->window));
    printf("Checksum: %d\n", ntohs(tcp_header->check));
    printf("Urgent pointer: %d\n", ntohs(tcp_header->urg_ptr));
}

// 打印UDP数据包头部信息
void print_udp_header(const u_char *packet)
{
    struct udphdr *udp_header;
    udp_header = (struct udphdr *) packet;

    printf("\n---------- UDP Header ----------\n");
    printf("Source port: %d\n", ntohs(udp_header->source));
    printf("Destination port: %d\n", ntohs(udp_header->dest));
    printf("Length: %d bytes\n", ntohs(udp_header->len));
    printf("Checksum: %d\n", ntohs(udp_header->check));
}

// 打印ARP数据包头部信息
void print_arp_header(const u_char *packet)
{
    struct arphdr *arp_header;
    arp_header = (struct arphdr *) packet;

    printf("\n---------- ARP Header ----------\n");
    printf("Hardware type: %s\n", (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER) ? "Ethernet" : "Unknown");
    printf("Protocol type: %s\n", (ntohs(arp_header->ar_pro) == ETHERTYPE_IP) ? "IP" : "Unknown");
    printf("Hardware address length: %d bytes\n", arp_header->ar_hln);
    printf("Protocol address length: %d bytes\n", arp_header->ar_pln);
    printf("Operation: %s\n", (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply");

    struct ether_arp *arp_payload;
    arp_payload = (struct ether_arp *) (packet + sizeof(struct arphdr));
    printf("Sender MAC: %s\n", ether_ntoa((struct ether_addr *) arp_payload->arp_sha));
    printf("Sender IP: %s\n", inet_ntoa(*(struct in_addr *) arp_payload->arp_spa));
    printf("Target MAC: %s\n", ether_ntoa((struct ether_addr *) arp_payload->arp_tha));
    printf("Target IP: %s\n", inet_ntoa(*(struct in_addr *) arp_payload->arp_tpa));
}

// 打印ICMP数据包头部信息
void print_icmp_header(const u_char *packet)
{
    struct icmphdr *icmp_header;
    icmp_header = (struct icmphdr *) packet;

    printf("\n---------- ICMP Header ----------\n");
    printf("Type: ");
    switch (icmp_header->type) {
        case ICMP_ECHOREPLY:
            printf("Echo Reply");
            break;
        case ICMP_DEST_UNREACH:
    printf("Destination Unreachable");
    break;
    case ICMP_SOURCE_QUENCH:
    printf("Source Quench");
    break;
    case ICMP_REDIRECT:
    printf("Redirect");
    break;
    case ICMP_ECHO:
    printf("Echo Request");
    break;
    case ICMP_TIME_EXCEEDED:
    printf("Time Exceeded");
    break;
    case ICMP_PARAMETERPROB:
    printf("Parameter Problem");
    break;
    case ICMP_TIMESTAMP:
    printf("Timestamp Request");
    break;
    case ICMP_TIMESTAMPREPLY:
    printf("Timestamp Reply");
    break;
    case ICMP_INFO_REQUEST:
    printf("Information Request");
    break;
    case ICMP_INFO_REPLY:
    printf("Information Reply");
    break;
    default:
    printf("Unknown");
    break;
    }
printf("\n");
printf("Code: %d\n", icmp_header->code);
printf("Checksum: %d\n", ntohs(icmp_header->checksum));
}