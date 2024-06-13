#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nids.h>
#include <net/if_arp.h>
#include <netinet/udp.h>

static int print_data(const u_char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (i % 16 != 0) {
        printf("\n");
    }
    return i;
}

static void handle_ethernet(const u_char *data, int len) {
    printf("Ethernet Header:\n");
    printf("    Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[6], data[7], data[8], data[9], data[10], data[11]);
    printf("    Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", data[0], data[1], data[2], data[3], data[4], data[5]);
    printf("    Type: 0x%04x\n", (data[12] << 8) | data[13]);
}

static void handle_ip(const u_char *data, int len) {
    struct iphdr *ip = (struct iphdr *) data;
    printf("IP Header:\n");
    printf("    Version: %d\n", ip->version);
    printf("    Header Length: %d bytes\n", ip->ihl * 4);
    printf("    Total Length: %d bytes\n", ntohs(ip->tot_len));
    printf("    TTL: %d\n", ip->ttl);
    printf("    Protocol: %d\n", ip->protocol);
    printf("    Source IP: %s\n", inet_ntoa(*((struct in_addr *)&ip->saddr)));
    printf("    Destination IP: %s\n", inet_ntoa(*((struct in_addr *)&ip->daddr)));
}

static void handle_tcp(const u_char *data, int len) {
    struct tcphdr *tcp = (struct tcphdr *) data;
    printf("TCP Header:\n");
    printf("    Source Port: %d\n", ntohs(tcp->source));
    printf("    Destination Port: %d\n", ntohs(tcp->dest));
    printf("    SequenceNumber: %u\n", ntohl(tcp->seq));
    printf("    Acknowledgment Number: %u\n", ntohl(tcp->ack_seq));
    printf("    Header Length: %d bytes\n", tcp->doff * 4);
    printf("    Flags: ");
    if (tcp->urg) printf("U");
    if (tcp->ack) printf("A");
    if (tcp->psh) printf("P");
    if (tcp->rst) printf("R");
    if (tcp->syn) printf("S");
    if (tcp->fin) printf("F");
    printf("\n");
    printf("    Window Size: %d\n", ntohs(tcp->window));
    printf("    Checksum: 0x%04x\n", ntohs(tcp->check));
}

static void handle_udp(const u_char *data, int len) {
    struct udphdr *udp = (struct udphdr *) data;
    printf("UDP Header:\n");
    printf("    Source Port: %d\n", ntohs(udp->source));
    printf("    Destination Port: %d\n", ntohs(udp->dest));
    printf("    Length: %d bytes\n", ntohs(udp->len));
    printf("    Checksum: 0x%04x\n", ntohs(udp->check));
}


static int packet_callback(struct ip *ip, void *arg) {
    const u_char *data = (const u_char *) ip;
    int len = ntohs(ip->ip_len);

    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("Received a TCP packet:\n");
            handle_ethernet(data, 14);
            handle_ip(data + 14, 20);
            handle_tcp(data + 34, len - 34);
            break;
        case IPPROTO_UDP:
            printf("Received a UDP packet:\n");
            handle_ethernet(data, 14);
            handle_ip(data + 14, 20);
            handle_udp(data + 34, len - 34);
            break;
        default:
            printf("Received a packet with unknown protocol:\n");
            handle_ethernet(data, 14);
            handle_ip(data + 14, 20);
            break;
    }

    printf("Packet data:\n");
    print_data(data, len);


    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    if (!nids_init()) {
        printf("Error initializing libnids\n");
        return 1;
    }

    nids_params.device = argv[1];
    nids_params.tcp_workarounds = 1;
    nids_params.scan_num_hosts = 0;
    nids_params.syslog = 0;

    printf("Starting packet capture on interface %s\n", nids_params.device);

    nids_register_ip(packet_callback);

    nids_run();

    printf("Stopping packet capture\n");

    nids_exit();

    return 0;
}