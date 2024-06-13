#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_ethernet_header(const u_char *packet);
void print_ip_header(const u_char *packet);
void print_arp_header(const u_char *packet);

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    struct ether_header *ethernet_header;

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        exit(1);
    }

    printf("Sniffing on device: %s\n", device);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        printf("Error opening device: %s\n", error_buffer);
        exit(1);
    }

    while (1) {
        packet = pcap_next(handle, &packet_header);
        if (packet == NULL) {
            printf("Error capturing packet\n");
            continue;
        }
        ethernet_header = (struct ether_header*) packet;
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_ip_header(packet);
        } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_arp_header(packet);
        } else {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            printf("Unknown packet type\n");
        }
    }

    pcap_close(handle);

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

void print_ip_header(const u_char *packet) {
    struct iphdr *ip_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));

    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    printf("IP header:\n");
    printf("\tSource IP: %s\n", source_ip);
    printf("\tDestination IP: %s\n", dest_ip);
    printf("\tProtocol: %d\n", ip_header->protocol);
}

void print_arp_header(const u_char *packet) {
    struct ether_arp *arp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    arp_header = (struct ether_arp*)(packet + sizeof(struct ether_header));

    inet_ntop(AF_INET, arp_header->arp_spa, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, dest_ip, INET_ADDRSTRLEN);

    printf("ARP header:\n");
    printf("\tSource IP: %s\n", source_ip);
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
           arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    printf("\tDestination IP: %s\n", dest_ip);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
           arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);
} 