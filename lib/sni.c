#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

void print_ether_header(const u_char *packet);
void print_ip_header(const u_char *packet);
void print_tcp_header(const u_char *packet);
void print_udp_header(const u_char *packet);
void print_arp_header(const u_char *packet);
void print_icmp_header(const u_char *packet);

int main(int argc, char *argv[])
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "";
    bpf_u_int32 subnet_mask, ip;

    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // 获取网络接口
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], error_buffer);
        return 2;
    }

    // 获取网络接口的IP地址和子网掩码
    if (pcap_lookupnet(argv[1], &ip, &subnet_mask, error_buffer) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", argv[1], error_buffer);
        ip = 0;
        subnet_mask = 0;
    }

    // 编译过滤器表达式
    if (pcap_compile(handle, &fp, filter_exp, 0, ip) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 应用过滤器表达式
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    // 开始捕获网络数据包
    pcap_loop(handle, -1, print_ether_header, NULL);

    // 关闭网络接口
    pcap_close(handle);

    return 0;
}

// 打印以太网帧头部信息
void print_ether_header(const u_char *packet)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    printf("\n---------- Ethernet Header ----------\n");
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_dhost));
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *) eth_header->ether_shost));

    // 判断以太网帧中的协议类型
    switch (ntohs(eth_header->ether_type)) {
        case ETHERTYPE_IP:
            printf("Protocol: IP\n");
            print_ip_header(packet + sizeof(struct ether_header));
            break;
        case ETHERTYPE_ARP:
            printf("Protocol: ARP\n");
            print_arp_header(packet + sizeof(struct ether_header));
            break;
        default:
            printf("Protocol: Unknown\n");
            break;
    }
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