#include "lcpheader.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
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

void print_ipv4_header(const u_char *packet)
{
    struct iphdr *ip_header;
    ip_header = (struct iphdr *) (packet+14);

    printf("\n---------- IPv4 Header ----------\n");
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

