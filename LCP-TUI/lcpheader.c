#include "lcpheader.h"
#include <stdio.h>
#include <stdlib.h>
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
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>

const u_char *packet;


void print_ethernet_header(const u_char *packet) {
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header*) packet;

    printw("Ethernet header:\n");
    printw("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_shost[0], ethernet_header->ether_shost[1],
           ethernet_header->ether_shost[2], ethernet_header->ether_shost[3],
           ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
    printw("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1],
           ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3],
           ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
    printw("\tType: %d\n", ntohs(ethernet_header->ether_type));
}

// 打印IP数据包头部信息
void print_ip_header(const u_char *packet)
{
    struct iphdr *ip_header;
    ip_header = (struct iphdr *) (packet+14);

    printw("\n---------- IP Header ----------\n");
    printw("Version: %d\n", ip_header->version);
    printw("Header length: %d bytes\n", ip_header->ihl * 4);
    printw("Type of service: %d\n", ip_header->tos);
    printw("Total length: %d bytes\n", ntohs(ip_header->tot_len));
    printw("Identification: %d\n", ntohs(ip_header->id));
    printw("Flags: %d\n", ntohs(ip_header->frag_off) & 0xE000);
    printw("Fragment offset: %d\n", ntohs(ip_header->frag_off) & 0x1FFF);
    printw("Time to live: %d\n", ip_header->ttl);
    printw("Protocol: ");
    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            printw("TCP\n");
            print_tcp_header(packet + sizeof(struct iphdr));
            break;
        case IPPROTO_UDP:
            printw("UDP\n");
            print_udp_header(packet + sizeof(struct iphdr));
            break;
        case IPPROTO_ICMP:
            printw("ICMP\n");
            print_icmp_header(packet + sizeof(struct iphdr));
            break;
        default:
            printw("Unknown\n");
            break;
    }
    printw("Header checksum: %d\n", ntohs(ip_header->check));
    printw("Source IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->saddr));
    printw("Destination IP: %s\n", inet_ntoa(*(struct in_addr *) &ip_header->daddr));
}

// 打印TCP数据包头部信息
void print_tcp_header(const u_char *packet)
{
    struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr *) packet;

    printw("\n---------- TCP Header ----------\n");
    printw("Source port: %d\n", ntohs(tcp_header->source));
    printw("Destination port: %d\n", ntohs(tcp_header->dest));
    printw("Sequence number: %u\n", ntohl(tcp_header->seq));
    printw("Acknowledgment number: %u\n", ntohl(tcp_header->ack_seq));
    printw("Header length: %d bytes\n", tcp_header->doff * 4);
    printw("Flags: ");
    if (tcp_header->urg)
        printw("U");
    if (tcp_header->ack)
        printw("A");
    if (tcp_header->psh)
        printw("P");
    if (tcp_header->rst)
        printw("R");
    if (tcp_header->syn)
        printw("S");
    if (tcp_header->fin)
        printw("F");
    printw("\n");
    printw("Window size: %d\n", ntohs(tcp_header->window));
    printw("Checksum: %d\n", ntohs(tcp_header->check));
    printw("Urgent pointer: %d\n", ntohs(tcp_header->urg_ptr));
}

// 打印UDP数据包头部信息
void print_udp_header(const u_char *packet)
{
    struct udphdr *udp_header;
    udp_header = (struct udphdr *) packet;

    printw("\n---------- UDP Header ----------\n");
    printw("Source port: %d\n", ntohs(udp_header->source));
    printw("Destination port: %d\n", ntohs(udp_header->dest));
    printw("Length: %d bytes\n", ntohs(udp_header->len));
    printw("Checksum: %d\n", ntohs(udp_header->check));
}

// 打印ARP数据包头部信息
void print_arp_header(const u_char *packet)
{
    struct arphdr *arp_header;
    arp_header = (struct arphdr *) packet;

    printw("\n---------- ARP Header ----------\n");
    printw("Hardware type: %s\n", (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER) ? "Ethernet" : "Unknown");
    printw("Protocol type: %s\n", (ntohs(arp_header->ar_pro) == ETHERTYPE_IP) ? "IP" : "Unknown");
    printw("Hardware address length: %d bytes\n", arp_header->ar_hln);
    printw("Protocol address length: %d bytes\n", arp_header->ar_pln);
    printw("Operation: %s\n", (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply");

    struct ether_arp *arp_payload;
    arp_payload = (struct ether_arp *) (packet + sizeof(struct arphdr));
    printw("Sender MAC: %s\n", ether_ntoa((struct ether_addr *) arp_payload->arp_sha));
    printw("Sender IP: %s\n", inet_ntoa(*(struct in_addr *) arp_payload->arp_spa));
    printw("Target MAC: %s\n", ether_ntoa((struct ether_addr *) arp_payload->arp_tha));
    printw("Target IP: %s\n", inet_ntoa(*(struct in_addr *) arp_payload->arp_tpa));
}

// 打印ICMP数据包头部信息
void print_icmp_header(const u_char *packet)
{
    struct icmphdr *icmp_header;
    icmp_header = (struct icmphdr *) packet;

    printw("\n---------- ICMP Header ----------\n");
    printw("Type: ");
    switch (icmp_header->type) {
        case ICMP_ECHOREPLY:
            printw("Echo Reply");
            break;
        case ICMP_DEST_UNREACH:
    printw("Destination Unreachable");
    break;
    case ICMP_SOURCE_QUENCH:
    printw("Source Quench");
    break;
    case ICMP_REDIRECT:
    printw("Redirect");
    break;
    case ICMP_ECHO:
    printw("Echo Request");
    break;
    case ICMP_TIME_EXCEEDED:
    printw("Time Exceeded");
    break;
    case ICMP_PARAMETERPROB:
    printw("Parameter Problem");
    break;
    case ICMP_TIMESTAMP:
    printw("Timestamp Request");
    break;
    case ICMP_TIMESTAMPREPLY:
    printw("Timestamp Reply");
    break;
    case ICMP_INFO_REQUEST:
    printw("Information Request");
    break;
    case ICMP_INFO_REPLY:
    printw("Information Reply");
    break;
    default:
    printw("Unknown");
    break;
    }
printw("\n");
printw("Code: %d\n", icmp_header->code);
printw("Checksum: %d\n", ntohs(icmp_header->checksum));
}
