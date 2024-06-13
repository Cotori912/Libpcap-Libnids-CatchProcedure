#include <stdio.h> /
#include <stdlib.h> /
#include <string.h> /
#include <nids.h> /
#include <arpa/inet.h> /
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h> /
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const struct in_addr *ip) {
    printf("%s\n", inet_ntoa(*ip));
}

void print_tcp(const struct tcphdr *tcp) {
    printf("TCP:\n");
    printf("  src port: %d\n", ntohs(tcp->source));
    printf("  dst port: %d\n", ntohs(tcp->dest));
    printf("  seq: %u\n", ntohl(tcp->seq));
    printf("  ack: %u\n", ntohl(tcp->ack_seq));
    printf("  flags: %c%c%c%c%c%c\n",
           tcp->urg ? 'U' : '-',
           tcp->ack ? 'A' : '-',
           tcp->psh ? 'P' : '-',
           tcp->rst ? 'R' : '-',
           tcp->syn ? 'S' : '-',
           tcp->fin ? 'F' : '-');
}

void print_udp(const struct udphdr *udp) {
    printf("UDP:\n");
    printf("  src port: %d\n", ntohs(udp->source));
    printf("  dst port: %d\n", ntohs(udp->dest));
}

void print_icmp(const struct icmphdr *icmp) {
    printf("ICMP:\n");
    printf("  type: %d\n", icmp->type);
    printf("  code: %d\n", icmp->code);
}

void packet_callback(struct ip *ip_header, void *data, int len) {
    printf("Packet:\n");

    // 解析以太网
    const struct ethhdr *eth = (struct ethhdr *) data;
    printf("Ethernet:\n");
    printf("  src mac: ");
    print_mac(eth->h_source);
    printf("  dst mac: ");
    print_mac(eth->h_dest);

    // 解析IP
    printf("IP:\n");
    printf("  src IP: ");
    print_ip(&ip_header->ip_src);
    printf("  dst IP: ");
    print_ip(&ip_header->ip_dst);

    // 解析协议
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            print_tcp((struct tcphdr *) ((char *) ip_header + ip_header->ip_hl * 4));
            break;
        case IPPROTO_UDP:
            print_udp((struct udphdr *) ((char *) ip_header + ip_header->ip_hl * 4));
            break;
        case IPPROTO_ICMP:
            print_icmp((struct icmphdr *) ((char *) ip_header + ip_header->ip_hl * 4));
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n");
            break;
        default:
            printf("Protocol: unknown\n");
            break;
    }
    printf("\n");
}

int main() {
    if (!nids_init()) {
        fprintf(stderr, "%s\n", nids_errbuf);
        exit(1);
    }

    nids_register_ip((void *) packet_callback);

    printf("Listening...\n");
    nids_run();

    return 0;
}